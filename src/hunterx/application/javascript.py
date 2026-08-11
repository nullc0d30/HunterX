# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript intelligence use-case services.

``JavaScriptService`` is the orchestrator - the bridge between a mission and
the JavaScript analysis tooling. Given a target, a posture and acquired script
content, it validates scope, builds a :class:`JSStrategy`, runs the registered
JavaScript analyzer through the :class:`ExecutionEngine` pipeline per asset,
correlates and confidence-filters the findings, diffs history, persists
everything to the TIDB and publishes ``javascript.*`` events.

``JavaScriptQueryService`` reads persisted JavaScript intelligence back from
the TIDB and answers the reporting queries (assets, endpoints, routes, auth,
domains, services, storage, secrets, technology, dependencies, configuration,
workers, wasm, security, dynamic imports, conflicts, changes and executions).
Both services depend on ports only.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceAsset as TidbJSAsset,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceAuth as TidbJSAuth,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceChange as TidbJSChange,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceConfiguration as TidbJSConfiguration,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceConflict as TidbJSConflict,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceDependency as TidbJSDependency,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceDomain as TidbJSDomain,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceEndpoint as TidbJSEndpoint,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceImport as TidbJSImport,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceRoute as TidbJSRoute,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceRun as TidbJSRun,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceSecret as TidbJSSecret,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceSecurity as TidbJSSecurity,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceService as TidbJSService,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceStorage as TidbJSStorage,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceTechnology as TidbJSTechnology,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceWasm as TidbJSWasm,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceWorker as TidbJSWorker,
)
from hunterx.domain.events.types import (
    JavaScriptAnalysisCompletedEvent,
    JavaScriptAnalysisFailedEvent,
    JavaScriptAnalysisStartedEvent,
    JavaScriptAssetAnalysedEvent,
    JavaScriptChangeDetectedEvent,
    JavaScriptCorrelationCompletedEvent,
    JavaScriptPhaseStartedEvent,
    JavaScriptSecretDiscoveredEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.javascript.history import JSHistory, JSHistorySnapshot
from hunterx.domain.javascript.models import (
    JavaScriptBatch,
    JSMode,
    JSTarget,
    findings_from_payload,
    make_mode,
    make_target,
)
from hunterx.domain.javascript.scope import JSScopeEnforcer, JSScopePolicy
from hunterx.domain.javascript.strategy import JSStrategyBuilder
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.javascript import JS_TOOL_IDS
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

#: Default execution profile label for JavaScript analysis runs.
_PROFILE = "javascript-intelligence"

#: Minimum confidence floor applied when the caller does not override it.
_DEFAULT_MIN_CONFIDENCE = 0.0


class JavaScriptService:
    """Run JavaScript intelligence missions through the Tool SDK.

    Usage::

        service = JavaScriptService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(
            mission_id="m1",
            target="https://example.com",
            parameters={"assets": [{"content": "...", "url": "https://example.com/app.js"}]},
        )
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        scope: JSScopePolicy | None = None,
        strategy_builder: JSStrategyBuilder | None = None,
        history: JSHistory | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._scope = scope or JSScopePolicy()
        self._strategy_builder = strategy_builder or JSStrategyBuilder()
        self._history = history or JSHistory()

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    def run(
        self,
        *,
        mission_id: str = "",
        target: JSTarget | str,
        mode: JSMode | str = JSMode.ACTIVE,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        with_history: bool = False,
        historical: JSHistorySnapshot | None = None,
        min_confidence: float | None = None,
        max_assets: int = 200,
    ) -> JavaScriptBatch:
        """Execute a JavaScript intelligence run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to analyse (URL, host, domain or IP).
            mode: the execution posture (passive, active, hybrid).
            tools: JavaScript tool ids to run; defaults to every registered
                JavaScript tool. Requesting an unregistered tool raises
                :class:`ValueError`.
            parameters: per-tool parameters merged into each execution
                context. Supply ``content``/``url`` for a single asset or
                ``assets`` (a list of ``{"content", "url", ...}`` mappings)
                for multiple assets.
            with_history: compare current findings against ``historical``.
            historical: historical snapshot to diff against.
            min_confidence: minimum confidence for a finding to be retained.
            max_assets: ceiling on the number of assets analysed per run.

        Returns:
            The :class:`JavaScriptBatch` with correlated findings, evidence,
            changes and execution summaries.

        Raises:
            ValueError: when the target is out of scope or a requested tool is
                not registered.

        """
        js_target = target if isinstance(target, JSTarget) else make_target(target)
        policy = self._scope_for(js_target)
        decision = JSScopeEnforcer(policy).allows_url(js_target.value) if "://" in js_target.value else JSScopeEnforcer(policy).allows_domain(js_target.value)
        if not decision.allowed:
            raise ValueError(f"JavaScript analysis target is out of scope: {decision.reason}")
        js_mode = make_mode(mode)
        selected = self._select_tools(tools)
        if js_mode is JSMode.PASSIVE:
            selected = []
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters.setdefault("mode", js_mode.value)
        strategy = self._strategy_builder.build(
            js_target.value,
            mode=js_mode,
            target_kind=js_target.target_type,
            with_secrets=True,
            with_technology=True,
            with_routes=True,
            with_history=with_history,
            max_assets=max_assets,
        )
        runnable = [tool_id for tool_id in strategy.analyzers if tool_id in selected] or selected
        if not runnable and selected:
            runnable = list(selected)

        batch = JavaScriptBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=js_target,
            mode=js_mode,
        )
        self._publish(
            JavaScriptAnalysisStartedEvent(
                mission_id,
                correlation_id,
                js_target.value,
                mode=js_mode.value,
                tools=list(runnable),
            )
        )
        started = time.time()
        try:
            self._publish(JavaScriptPhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            analyses = self._collect(js_target, mission_id, correlation_id, parameters, runnable, batch) if runnable else []

            self._publish(JavaScriptPhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlation = self._correlate(analyses, min_confidence=min_confidence)
            batch.assets = correlation.assets
            batch.endpoints = correlation.endpoints
            batch.routes = correlation.routes
            batch.auth = correlation.auth
            batch.domains = correlation.domains
            batch.services = correlation.services
            batch.storage = correlation.storage
            batch.secrets = correlation.secrets
            batch.technology = correlation.technology
            batch.dependencies = correlation.dependencies
            batch.configuration = correlation.configuration
            batch.workers = correlation.workers
            batch.wasm = correlation.wasm
            batch.security = correlation.security
            batch.dynamic_imports = correlation.dynamic_imports
            batch.evidence = correlation.evidence
            if not batch.secrets:
                batch.secrets = [
                    secret
                    for analysis in analyses
                    for secret in analysis.secrets
                ]
            self._publish(
                JavaScriptCorrelationCompletedEvent(
                    mission_id,
                    correlation_id,
                    raw_observations=batch.finding_count(),
                    correlated_observations=batch.finding_count(),
                    assets=batch.asset_count(),
                    secrets=batch.secret_count(),
                )
            )

            self._publish(JavaScriptPhaseStartedEvent(correlation_id, "history", mission_id=mission_id))
            if with_history and historical is not None:
                for change in self._diff_history(historical, batch, correlation_id, mission_id):
                    self._publish(
                        JavaScriptChangeDetectedEvent(
                            correlation_id,
                            change.subject,
                            change.change_type,
                            previous=change.previous,
                            current=change.current,
                            tool_id=change.source,
                            mission_id=mission_id,
                        )
                    )

            self._publish_discoveries(batch, correlation_id, mission_id)

            if self._stores is not None:
                self._publish(JavaScriptPhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, js_target, mission_id, correlation_id, strategy.max_assets)

            if runnable:
                batch.add_execution(
                    self._summary(batch, runnable, started, mission_id, correlation_id, status="completed")
                )
            self._publish(
                JavaScriptAnalysisCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=js_target.value,
                    assets=batch.asset_count(),
                    findings=batch.finding_count(),
                    secrets=batch.secret_count(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                JavaScriptAnalysisFailedEvent(
                    mission_id,
                    correlation_id,
                    js_target.value,
                    str(exc),
                )
            )
            raise
        return batch

    # -- pipeline helpers ---------------------------------------------------

    def _scope_for(self, target: JSTarget) -> JSScopePolicy:
        """Return the effective scope policy for a target.

        When no scope roots are configured the target itself authorizes its own
        host tree; configured roots remain strictly fail-closed.
        """
        policy = self._scope
        if not policy.roots and target.value:
            policy = JSScopePolicy(
                roots=frozenset({target.value}),
                excludes=policy.excludes,
                strict=policy.strict,
            )
        return policy

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered JavaScript tools to run for this mission."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in JS_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested JavaScript tools are not registered: {', '.join(missing)}")
        return requested

    def _collect(
        self,
        target: JSTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        runnable: Sequence[str],
        batch: JavaScriptBatch,
    ) -> list[Any]:
        """Run the analyzer over the supplied assets and return analyses."""
        assets = parameters.get("assets")
        if isinstance(assets, list) and assets:
            inputs = list(assets)
        elif parameters.get("content") is not None or parameters.get("url"):
            inputs = [dict(parameters)]
        else:
            raise ValueError("no JavaScript content supplied: provide 'content'/'url' or an 'assets' list")
        inputs = inputs[: strategy_max_assets(parameters, 200)]

        analyses: list[Any] = []
        for index, item in enumerate(inputs):
            if not isinstance(item, dict):
                continue
            item = dict(item)
            if "url" not in item or not item["url"]:
                item["url"] = f"{target.value}:inline:{index}"
            for tool_id in runnable:
                context = self._build_context(tool_id, target, mission_id, correlation_id, item)
                outcome = self._engine.execute(context)
                result = outcome.result
                found = findings_from_payload(result.output.json) if result.status.is_success else []
                analyses.extend(found)
                for analysis in found:
                    batch.add_analysis(analysis)
                self._publish(
                    JavaScriptAssetAnalysedEvent(
                        correlation_id,
                        str(item.get("url", "")),
                        findings=sum(len(getattr(analysis, field) or ()) for analysis in found for field in _ANALYSIS_FIELDS),
                        secrets=sum(len(analysis.secrets or ()) for analysis in found),
                        tool_id=tool_id,
                        mission_id=mission_id,
                    )
                )
        return analyses

    def _build_context(
        self,
        tool_id: str,
        target: JSTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
    ) -> ExecutionContext:
        """Build an execution context for one JavaScript tool."""
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile(_PROFILE)
            .with_correlation_id(correlation_id)
            .with_permissions(("local",))
            .with_parameters(dict(parameters))
            .build()
        )

    def _correlate(self, analyses: Sequence[Any], *, min_confidence: float | None) -> Any:
        """Correlate per-asset analyses and enforce the confidence floor."""
        from dataclasses import replace

        from hunterx.domain.javascript.correlator import JSCorrelator

        floor = min_confidence if min_confidence is not None else _DEFAULT_MIN_CONFIDENCE
        kept: list[Any] = []
        for analysis in analyses:
            if floor <= 0.0:
                kept.append(analysis)
                continue
            filtered = replace(
                analysis,
                endpoints=_filtered(analysis.endpoints, floor),
                routes=_filtered(analysis.routes, floor),
                auth=_filtered(analysis.auth, floor),
                domains=_filtered(analysis.domains, floor),
                services=_filtered(analysis.services, floor),
                storage=_filtered(analysis.storage, floor),
                secrets=_filtered(analysis.secrets, floor),
                technology=_filtered(analysis.technology, floor),
                dependencies=_filtered(analysis.dependencies, floor),
                configuration=_filtered(analysis.configuration, floor),
                workers=_filtered(analysis.workers, floor),
                wasm=_filtered(analysis.wasm, floor),
                security=_filtered(analysis.security, floor),
                dynamic_imports=_filtered(analysis.dynamic_imports, floor),
            )
            kept.append(filtered)
        return JSCorrelator().correlate(kept)

    def _diff_history(
        self,
        previous: JSHistorySnapshot,
        batch: JavaScriptBatch,
        correlation_id: str,
        mission_id: str,
    ) -> list[Any]:
        """Diff the current batch against the previous snapshot."""
        current = JSHistorySnapshot.from_batch(batch, target_key=batch.target.value)
        return self._history.compare(previous, current, source=correlation_id)

    def _summary(
        self,
        batch: JavaScriptBatch,
        runnable: Sequence[str],
        started: float,
        mission_id: str,
        correlation_id: str,
        *,
        status: str,
    ) -> Any:
        """Build an execution summary record for the run."""
        from hunterx.domain.javascript.models import JSExecutionSummary

        return JSExecutionSummary(
            tool_id=", ".join(runnable) or "javascript",
            status=status,
            assets=batch.asset_count(),
            endpoints=batch.endpoint_count(),
            secrets=batch.secret_count(),
            duration_ms=int((time.time() - started) * 1000),
            error="",
        )

    def _persist(
        self,
        batch: JavaScriptBatch,
        target: JSTarget,
        mission_id: str,
        correlation_id: str,
        max_assets: int,
    ) -> int:
        """Persist correlated JavaScript intelligence into the TIDB; returns rows."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist JavaScript intelligence without TIDB stores")
        count = 0
        for analysis in batch.analyses:
            asset = analysis.asset
            stores.repository_for(TidbJSAsset).save(
                _to_asset_entity(asset, target.value, mission_id, correlation_id)
            )
            count += 1
            asset_url = asset.url
            for endpoint in analysis.endpoints:
                stores.repository_for(TidbJSEndpoint).save(_to_endpoint_entity(endpoint, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for route in analysis.routes:
                stores.repository_for(TidbJSRoute).save(_to_route_entity(route, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for auth in analysis.auth:
                stores.repository_for(TidbJSAuth).save(_to_auth_entity(auth, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for domain in analysis.domains:
                stores.repository_for(TidbJSDomain).save(_to_domain_entity(domain, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for service in analysis.services:
                stores.repository_for(TidbJSService).save(_to_service_entity(service, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for storage in analysis.storage:
                stores.repository_for(TidbJSStorage).save(_to_storage_entity(storage, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for secret in analysis.secrets:
                stores.repository_for(TidbJSSecret).save(_to_secret_entity(secret, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for technology in analysis.technology:
                stores.repository_for(TidbJSTechnology).save(_to_technology_entity(technology, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for dependency in analysis.dependencies:
                stores.repository_for(TidbJSDependency).save(_to_dependency_entity(dependency, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for configuration in analysis.configuration:
                stores.repository_for(TidbJSConfiguration).save(_to_configuration_entity(configuration, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for worker in analysis.workers:
                stores.repository_for(TidbJSWorker).save(_to_worker_entity(worker, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for wasm in analysis.wasm:
                stores.repository_for(TidbJSWasm).save(_to_wasm_entity(wasm, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for security in analysis.security:
                stores.repository_for(TidbJSSecurity).save(_to_security_entity(security, asset_url, target.value, mission_id, correlation_id))
                count += 1
            for dynamic_import in analysis.dynamic_imports:
                stores.repository_for(TidbJSImport).save(_to_import_entity(dynamic_import, asset_url, target.value, mission_id, correlation_id))
                count += 1
        for conflict in batch.conflicts:
            stores.repository_for(TidbJSConflict).save(_to_conflict_entity(conflict, mission_id, correlation_id))
            count += 1
        for change in batch.changes:
            stores.repository_for(TidbJSChange).save(_to_change_entity(change, mission_id, correlation_id))
            count += 1
        run = TidbJSRun(
            mission_id=mission_id,
            target_key=target.value,
            status="completed",
            assets=batch.asset_count(),
            endpoints=batch.endpoint_count(),
            routes=len(batch.routes),
            secrets=batch.secret_count(),
            services=len(batch.services),
            dependencies=len(batch.dependencies),
            technologies=len(batch.technology),
            conflicts=len(batch.conflicts),
            changes=len(batch.changes),
            started_at=batch.created_at,
            completed_at=utcnow_iso(),
            duration_ms=_run_duration_ms(batch),
            summary={
                "tools": [summary.tool_id for summary in batch.executions],
                "max_assets": max_assets,
            },
            correlation_id=correlation_id,
        )
        stores.repository_for(TidbJSRun).save(run)
        count += 1
        return count

    # -- events -------------------------------------------------------------

    def _publish_discoveries(self, batch: JavaScriptBatch, correlation_id: str, mission_id: str) -> None:
        """Publish per-finding discovery events."""
        for secret in batch.secrets:
            self._publish(
                JavaScriptSecretDiscoveredEvent(
                    correlation_id,
                    getattr(secret, "location", ""),
                    getattr(secret, "classification", "generic-secret"),
                    tier=getattr(secret, "tier", "low"),
                    tool_id=getattr(secret, "tool_id", ""),
                    mission_id=mission_id,
                )
            )

    def _publish(self, event: Any) -> None:
        """Publish an event to the bus when one is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


class JavaScriptQueryService:
    """Query service for persisted JavaScript intelligence results."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache

    def assets(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted script assets for a target/mission."""
        return self._records(TidbJSAsset, "target_key", host, mission_id, _asset_dict)

    def endpoints(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted endpoints for a target/mission."""
        return self._records(TidbJSEndpoint, "target_key", host, mission_id, _endpoint_dict)

    def routes(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted routes for a target/mission."""
        return self._records(TidbJSRoute, "target_key", host, mission_id, _route_dict)

    def auth(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted auth references for a target/mission."""
        return self._records(TidbJSAuth, "target_key", host, mission_id, _auth_dict)

    def domains(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted external domains for a target/mission."""
        return self._records(TidbJSDomain, "target_key", host, mission_id, _domain_dict)

    def services(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted third-party services for a target/mission."""
        return self._records(TidbJSService, "target_key", host, mission_id, _service_dict)

    def storage(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted storage indicators for a target/mission."""
        return self._records(TidbJSStorage, "target_key", host, mission_id, _storage_dict)

    def secrets(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted secrets (masked only) for a target/mission."""
        return self._records(TidbJSSecret, "target_key", host, mission_id, _secret_dict)

    def technology(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted technology evidence for a target/mission."""
        return self._records(TidbJSTechnology, "target_key", host, mission_id, _technology_dict)

    def dependencies(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted dependencies for a target/mission."""
        return self._records(TidbJSDependency, "target_key", host, mission_id, _dependency_dict)

    def configuration(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted configuration indicators for a target/mission."""
        return self._records(TidbJSConfiguration, "target_key", host, mission_id, _configuration_dict)

    def workers(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted worker references for a target/mission."""
        return self._records(TidbJSWorker, "target_key", host, mission_id, _worker_dict)

    def wasm(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted WebAssembly references for a target/mission."""
        return self._records(TidbJSWasm, "target_key", host, mission_id, _wasm_dict)

    def security(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted security API indicators for a target/mission."""
        return self._records(TidbJSSecurity, "target_key", host, mission_id, _security_dict)

    def dynamic_imports(self, *, host: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted dynamic imports for a target/mission."""
        return self._records(TidbJSImport, "target_key", host, mission_id, _import_dict)

    def conflicts(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted analysis conflicts for a mission."""
        return self._records(TidbJSConflict, "mission_id", mission_id, mission_id, _conflict_dict)

    def changes(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted historical changes for a mission."""
        return self._records(TidbJSChange, "mission_id", mission_id, mission_id, _change_dict)

    def executions(self, *, target: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return execution summaries for a target/mission."""
        return self._records(TidbJSRun, "target_key", target, mission_id, _run_dict)

    # -- helpers ------------------------------------------------------------

    def _records(
        self,
        entity_type: type,
        field: str,
        value: str,
        mission_id: str,
        mapper: Any,
    ) -> list[dict[str, Any]]:
        """Return persisted entities for ``field == value`` (or by mission)."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(entity_type)
        if value:
            return [mapper(record) for record in repo.list_by(field, value)]
        if mission_id:
            return [mapper(record) for record in repo.list_by("mission_id", mission_id)]
        return [mapper(record) for record in repo.list()]


# -- persistence mappers -----------------------------------------------------

_ANALYSIS_FIELDS = (
    "endpoints",
    "routes",
    "auth",
    "domains",
    "services",
    "storage",
    "secrets",
    "technology",
    "dependencies",
    "configuration",
    "workers",
    "wasm",
    "security",
    "dynamic_imports",
)


def strategy_max_assets(parameters: Mapping[str, Any], default: int) -> int:
    """Return the per-run asset ceiling from ``parameters``."""
    value = parameters.get("max_assets", default)
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _filtered(items: Sequence[Any], floor: float) -> list[Any]:
    """Return items whose ``confidence`` is at least ``floor``."""
    return [item for item in items or () if getattr(item, "confidence", 1.0) >= floor]


def _run_duration_ms(batch: JavaScriptBatch) -> int:
    """Sum execution durations when recorded, else ``0``."""
    total = 0
    for summary in batch.executions:
        total += getattr(summary, "duration_ms", 0) or 0
    return total


def _evidence_dicts(items: Any) -> list[dict[str, Any]]:
    """Serialize evidence fragments to JSON-safe dicts."""
    return [item.to_dict() for item in (items or ())]


def _to_asset_entity(asset: Any, target_key: str, mission_id: str, correlation_id: str) -> TidbJSAsset:
    return TidbJSAsset(
        url=getattr(asset, "url", ""),
        origin=getattr(asset, "origin", ""),
        parent_url=getattr(asset, "parent_url", ""),
        asset_kind=str(getattr(asset, "asset_kind", "external")),
        content_hash=getattr(asset, "content_hash", ""),
        size=getattr(asset, "size", 0),
        status_code=getattr(asset, "status_code", None),
        content_type=getattr(asset, "content_type", ""),
        etag=getattr(asset, "etag", "") or "",
        last_modified=getattr(asset, "last_modified", "") or "",
        sha256=getattr(asset, "sha256", ""),
        source=getattr(asset, "source", "crawl"),
        tool_id=getattr(asset, "tool_id", ""),
        target_key=target_key,
        execution_id=getattr(asset, "execution_id", ""),
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_endpoint_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSEndpoint:
    return TidbJSEndpoint(
        url=getattr(finding, "url", ""),
        method=getattr(finding, "method", "GET"),
        kind=str(getattr(finding, "kind", "fetch")),
        api_type=str(getattr(finding, "api_type", "rest")),
        base_url=getattr(finding, "base_url", ""),
        parameters=list(getattr(finding, "parameters", []) or ()),
        headers=list(getattr(finding, "headers", []) or ()),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_route_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSRoute:
    return TidbJSRoute(
        route=getattr(finding, "route", ""),
        pattern=getattr(finding, "pattern", ""),
        parameters=list(getattr(finding, "parameters", []) or ()),
        framework=str(getattr(finding, "framework", "other")),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_auth_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSAuth:
    return TidbJSAuth(
        kind=str(getattr(finding, "kind", "other")),
        value=getattr(finding, "value", ""),
        mechanism=getattr(finding, "mechanism", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_domain_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSDomain:
    return TidbJSDomain(
        domain=getattr(finding, "domain", ""),
        relation=str(getattr(finding, "relation", "unknown")),
        hostname=getattr(finding, "hostname", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_service_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSService:
    return TidbJSService(
        provider=getattr(finding, "provider", ""),
        service=getattr(finding, "service", ""),
        category=str(getattr(finding, "category", "other")),
        domain=getattr(finding, "domain", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_storage_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSStorage:
    return TidbJSStorage(
        storage_type=str(getattr(finding, "storage_type", "local-storage")),
        key_pattern=getattr(finding, "key_pattern", ""),
        usage_context=getattr(finding, "usage_context", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_secret_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSSecret:
    return TidbJSSecret(
        classification=str(getattr(finding, "classification", "generic-secret")),
        masked_value=getattr(finding, "masked_value", ""),
        value_hash=getattr(finding, "value_hash", ""),
        location=getattr(finding, "location", ""),
        file=getattr(finding, "file", ""),
        line=getattr(finding, "line", None),
        offset=getattr(finding, "offset", -1),
        detection_rule=getattr(finding, "detection_rule", ""),
        confidence=getattr(finding, "confidence", 0.5),
        tier=str(getattr(finding, "tier", "low")),
        reasoning=getattr(finding, "reasoning", ""),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_technology_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSTechnology:
    return TidbJSTechnology(
        name=getattr(finding, "name", ""),
        kind=str(getattr(finding, "kind", "library")),
        version=getattr(finding, "version", ""),
        version_confidence=str(getattr(finding, "version_confidence", "unknown")),
        category=getattr(finding, "category", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_dependency_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSDependency:
    return TidbJSDependency(
        name=getattr(finding, "name", ""),
        version=getattr(finding, "version", ""),
        source=getattr(finding, "source", "import"),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_configuration_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSConfiguration:
    return TidbJSConfiguration(
        kind=str(getattr(finding, "kind", "other")),
        key=getattr(finding, "key", ""),
        value=getattr(finding, "value", ""),
        environment=getattr(finding, "environment", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_worker_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSWorker:
    return TidbJSWorker(
        kind=str(getattr(finding, "kind", "worker")),
        url=getattr(finding, "url", ""),
        registration_context=getattr(finding, "registration_context", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_wasm_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSWasm:
    return TidbJSWasm(
        kind=str(getattr(finding, "kind", "resource")),
        url=getattr(finding, "url", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_security_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSSecurity:
    return TidbJSSecurity(
        api=str(getattr(finding, "api", "")),
        context=getattr(finding, "context", ""),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_import_entity(finding: Any, asset_url: str, target_key: str, mission_id: str, correlation_id: str) -> TidbJSImport:
    return TidbJSImport(
        specifier=getattr(finding, "specifier", ""),
        url=getattr(finding, "url", ""),
        chunk=bool(getattr(finding, "chunk", False)),
        confidence=getattr(finding, "confidence", 1.0),
        evidence=_evidence_dicts(getattr(finding, "evidence", None)),
        asset_url=asset_url,
        target_key=target_key,
        execution_id="",
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _to_conflict_entity(finding: Any, mission_id: str, correlation_id: str) -> TidbJSConflict:
    return TidbJSConflict(
        subject=getattr(finding, "subject", ""),
        artifact_type=getattr(finding, "artifact_type", ""),
        observations=list(getattr(finding, "observations", []) or ()),
        selected=getattr(finding, "selected", ""),
        reason=getattr(finding, "reason", ""),
        confidence=getattr(finding, "confidence", 0.0),
        mission_id=mission_id,
        correlation_id=correlation_id,
    )


def _to_change_entity(finding: Any, mission_id: str, correlation_id: str) -> TidbJSChange:
    return TidbJSChange(
        artifact_type=getattr(finding, "artifact_type", ""),
        subject=getattr(finding, "subject", ""),
        change_type=str(getattr(finding, "change_type", "changed")),
        previous=getattr(finding, "previous", ""),
        current=getattr(finding, "current", ""),
        source=getattr(finding, "source", ""),
        mission_id=mission_id,
        correlation_id=correlation_id,
    )


# -- query mappers -----------------------------------------------------------

def _asset_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "url": getattr(record, "url", ""),
        "origin": getattr(record, "origin", ""),
        "asset_kind": getattr(record, "asset_kind", ""),
        "content_hash": getattr(record, "content_hash", ""),
        "source": getattr(record, "source", ""),
        "tool_id": getattr(record, "tool_id", ""),
        "mission_id": getattr(record, "mission_id", ""),
        "observed_at": getattr(record, "created_at", ""),
    }


def _endpoint_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "url": getattr(record, "url", ""),
        "method": getattr(record, "method", ""),
        "kind": getattr(record, "kind", ""),
        "api_type": getattr(record, "api_type", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "asset_url": getattr(record, "asset_url", ""),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _route_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "route": getattr(record, "route", ""),
        "pattern": getattr(record, "pattern", ""),
        "framework": getattr(record, "framework", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "asset_url": getattr(record, "asset_url", ""),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _auth_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "kind": getattr(record, "kind", ""),
        "mechanism": getattr(record, "mechanism", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "asset_url": getattr(record, "asset_url", ""),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _domain_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "domain": getattr(record, "domain", ""),
        "relation": getattr(record, "relation", ""),
        "hostname": getattr(record, "hostname", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _service_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "provider": getattr(record, "provider", ""),
        "service": getattr(record, "service", ""),
        "category": getattr(record, "category", ""),
        "domain": getattr(record, "domain", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _storage_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "storage_type": getattr(record, "storage_type", ""),
        "key_pattern": getattr(record, "key_pattern", ""),
        "usage_context": getattr(record, "usage_context", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "asset_url": getattr(record, "asset_url", ""),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _secret_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "classification": getattr(record, "classification", ""),
        "masked_value": getattr(record, "masked_value", ""),
        "location": getattr(record, "location", ""),
        "detection_rule": getattr(record, "detection_rule", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "tier": getattr(record, "tier", ""),
        "asset_url": getattr(record, "asset_url", ""),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _technology_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "name": getattr(record, "name", ""),
        "kind": getattr(record, "kind", ""),
        "version": getattr(record, "version", ""),
        "version_confidence": getattr(record, "version_confidence", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _dependency_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "name": getattr(record, "name", ""),
        "version": getattr(record, "version", ""),
        "source": getattr(record, "source", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _configuration_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "kind": getattr(record, "kind", ""),
        "key": getattr(record, "key", ""),
        "value": getattr(record, "value", ""),
        "environment": getattr(record, "environment", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _worker_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "kind": getattr(record, "kind", ""),
        "url": getattr(record, "url", ""),
        "registration_context": getattr(record, "registration_context", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _wasm_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "kind": getattr(record, "kind", ""),
        "url": getattr(record, "url", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _security_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "api": getattr(record, "api", ""),
        "context": getattr(record, "context", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _import_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "specifier": getattr(record, "specifier", ""),
        "url": getattr(record, "url", ""),
        "chunk": getattr(record, "chunk", False),
        "confidence": getattr(record, "confidence", 0.0),
        "target_key": getattr(record, "target_key", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _conflict_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "subject": getattr(record, "subject", ""),
        "artifact_type": getattr(record, "artifact_type", ""),
        "selected": getattr(record, "selected", ""),
        "reason": getattr(record, "reason", ""),
        "confidence": getattr(record, "confidence", 0.0),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _change_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "artifact_type": getattr(record, "artifact_type", ""),
        "subject": getattr(record, "subject", ""),
        "change_type": getattr(record, "change_type", ""),
        "previous": getattr(record, "previous", ""),
        "current": getattr(record, "current", ""),
        "source": getattr(record, "source", ""),
        "mission_id": getattr(record, "mission_id", ""),
    }


def _run_dict(record: Any) -> dict[str, Any]:
    return {
        "id": getattr(record, "id", ""),
        "target_key": getattr(record, "target_key", ""),
        "status": getattr(record, "status", ""),
        "assets": getattr(record, "assets", 0),
        "endpoints": getattr(record, "endpoints", 0),
        "routes": getattr(record, "routes", 0),
        "secrets": getattr(record, "secrets", 0),
        "conflicts": getattr(record, "conflicts", 0),
        "changes": getattr(record, "changes", 0),
        "started_at": getattr(record, "started_at", ""),
        "completed_at": getattr(record, "completed_at", ""),
        "duration_ms": getattr(record, "duration_ms", 0),
        "mission_id": getattr(record, "mission_id", ""),
        "correlation_id": getattr(record, "correlation_id", ""),
    }
