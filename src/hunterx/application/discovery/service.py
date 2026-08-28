# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery application service.

Drives the Phase 4 universal deep-discovery pipeline against any target:

    ASSET → DNS → SUBDOMAIN → HOST → PORT → SERVICE → TECHNOLOGY → HTTP →
    API → GRAPHQL → JAVASCRIPT → WORKFLOW → AUTH

For every stage the service selects the providers registered on the execution
engine, runs each through the SDK pipeline, parses the canonical payload,
converts it into discovered assets + attack-surface observations, feeds the
observations into :class:`AttackSurfaceService` (graph upsert + capability
mapping + assessment-queue scheduling), and records an honest per-provider
state (AVAILABLE / UNAVAILABLE / FAILED / PARTIAL / NOT_APPLICABLE /
COMPLETED).

A provider that is not registered or not healthy is reported ``UNAVAILABLE`` —
never silently skipped, never a mission-terminating error. One failed tool
never kills the mission: every other provider still runs and the run report
carries the exact gaps.
"""

from __future__ import annotations

import time
from typing import Any

from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.discovery.converters import CONVERTERS, ConversionResult, Observation
from hunterx.domain.discovery.canonical import DiscoveryDeduper
from hunterx.domain.discovery.enums import DiscoveryStage, DiscoveryState
from hunterx.domain.discovery.models import DiscoveryProviderResult, DiscoveryRun, DiscoveryStageResult
from hunterx.domain.discovery.pipeline import ProviderSpec, StageDefinition, StagePlan
from hunterx.domain.execution import ExecutionContext, ExecutionStatus
from hunterx.shared.time import utcnow_iso
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

#: Payload family per tool registry group. Tool ids come from the registries;
#: the mapping below only links a registry family to its converter + payload key.
_FAMILY_BY_TOOL: dict[str, str] = {
    # recon
    "subfinder": "recon",
    "amass": "recon",
    "assetfinder": "recon",
    "findomain": "recon",
    "bbot": "recon",
    "theharvester": "recon",
    # dns
    "dnsx": "dns",
    "dnspython": "dns",
    "massdns": "dns",
    "shuffledns": "dns",
    # livehost
    "nmap": "livehost",
    "naabu": "livehost",
    "masscan": "livehost",
    "rustscan": "livehost",
    "tcp-connect": "livehost",
    # technology
    "httpx": "tech",
    "whatweb": "tech",
    "signature": "tech",
    # web crawl
    "crawler": "web",
    "katana": "web",
    "gospider": "web",
    "hakrawler": "web",
    "gau": "web",
    "waybackurls": "web",
    "urlfinder": "web",
    # content discovery
    "ffuf": "content",
    "gobuster": "content",
    "feroxbuster": "content",
    "dirsearch": "content",
    # parameter discovery
    "arjun": "parameter",
    "paramspider": "parameter",
    "kiterunner": "parameter",
    # api
    "api-openapi": "api",
    "api-swagger": "api",
    "api-graphql": "api",
    "api-websocket": "api",
    "api-soap": "api",
    "api-hints": "api",
    "graphqlmap": "api",
    "inql": "api",
    # javascript
    "javascript": "javascript",
    "linkfinder": "javascript",
    "secretfinder": "javascript",
    "xnlinkfinder": "javascript",
    # auth
    "auth-analysis": "auth",
}

#: Tool groups per stage. Only these stages run against the target; a stage
#: with zero registered providers is reported ``UNAVAILABLE`` honestly.
_STAGE_TOOL_GROUPS: list[tuple[DiscoveryStage, tuple[str, ...]]] = [
    (DiscoveryStage.DNS, ("dnsx", "dnspython", "massdns", "shuffledns")),
    (DiscoveryStage.SUBDOMAIN, ("subfinder", "amass", "assetfinder", "findomain", "bbot", "theharvester")),
    (DiscoveryStage.HOST, ("dnspython", "dnsx")),
    (DiscoveryStage.PORT, ("nmap", "naabu", "masscan", "rustscan", "tcp-connect")),
    (DiscoveryStage.SERVICE, ("nmap", "rustscan", "tcp-connect")),
    (DiscoveryStage.TECHNOLOGY, ("httpx", "whatweb", "signature")),
    (DiscoveryStage.HTTP, ("crawler", "katana", "gospider", "hakrawler", "gau", "waybackurls", "urlfinder")),
    (DiscoveryStage.API, ("api-openapi", "api-swagger", "api-soap", "api-websocket", "api-hints", "graphqlmap", "inql")),
    (DiscoveryStage.GRAPHQL, ("api-graphql",)),
    (DiscoveryStage.JAVASCRIPT, ("javascript", "linkfinder", "secretfinder", "xnlinkfinder")),
    (DiscoveryStage.WORKFLOW, ("arjun", "paramspider", "kiterunner")),
    (DiscoveryStage.AUTH, ("auth-analysis",)),
]


def build_stage_plan() -> StagePlan:
    """Build the declarative stage plan from the tool registry mapping.

    The plan is target-agnostic: tool ids come from the platform registries
    (via the family map above), and every stage's providers are optional —
    the service honestly reports stages without a registered provider.
    """
    definitions: list[StageDefinition] = []
    for stage, tool_ids in _STAGE_TOOL_GROUPS:
        providers = tuple(
            ProviderSpec(
                tool_id=tool_id,
                kind=_FAMILY_BY_TOOL.get(tool_id, "recon"),
            )
            for tool_id in tool_ids
            if tool_id in _FAMILY_BY_TOOL
        )
        definitions.append(
            StageDefinition(
                stage=stage,
                providers=providers,
                optional=stage in (DiscoveryStage.GRAPHQL,),
                title=stage.value.title(),
            )
        )
    return StagePlan(stages=tuple(definitions))


class UniversalDiscoveryService:
    """Run the universal deep-discovery pipeline for one target.

    Args:
        engine: the execution engine with the desired adapters registered.
        surface: the attack-surface service observations are fed into
            (``None`` builds a fresh one).
        mission_id: owning mission id (``""`` for ad-hoc runs).
        target_key: root target key for the surface graph.
        plan: stage plan; ``None`` uses :func:`build_stage_plan`.
        catalog: capability catalog for the surface mapper (``None`` sources
            the live platform catalog).

    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        surface: AttackSurfaceService | None = None,
        mission_id: str = "",
        target_key: str = "",
        plan: StagePlan | None = None,
        catalog: list[str] | None = None,
    ) -> None:
        self.engine = engine
        self.mission_id = mission_id
        self.target_key = target_key
        self.plan = plan or build_stage_plan()
        self.surface = surface or AttackSurfaceService(
            mission_id=mission_id,
            target_key=target_key or mission_id,
            catalog=catalog,
        )
        self.deduper = DiscoveryDeduper()
        self._discovered: dict[str, set[str]] = {
            "host": set(),
            "subdomain": set(),
            "ip": set(),
            "url": set(),
            "endpoint": set(),
            "api_endpoint": set(),
            "graphql_operation": set(),
            "websocket": set(),
            "javascript_endpoint": set(),
            "auth_surface": set(),
            "port": set(),
            "service": set(),
        }

    # -- public API ----------------------------------------------------------

    def run(
        self,
        *,
        target: str,
        mode: str = "hybrid",
        session_state: str = "",
        timeout_seconds: float = 60.0,
    ) -> DiscoveryRun:
        """Run the full discovery pipeline against ``target``.

        Returns:
            A :class:`DiscoveryRun` with every stage result, the deduplicated
            assets and the summary — the machine-readable Phase 4 evidence.

        """
        run = DiscoveryRun(mission_id=self.mission_id, target=target, mode=mode)
        self.surface.establish_target()
        self.surface.on_observation(
            observation_type="asset",
            content={"target": target},
            asset_key=target,
            source="universal-discovery",
            session_state=session_state,
        )

        for definition in self.plan.stages:
            stage_result = self._run_stage(definition, target=target, mode=mode, session_state=session_state, timeout_seconds=timeout_seconds)
            run.add_stage(stage_result)

        self.deduper.add_many(asset for stage in run.stages for asset in stage.assets)
        run.assets = self.deduper.all()
        run.dedup = self.deduper.stats()
        run.summary = self._summarize(run)
        return run

    # -- stage execution -----------------------------------------------------

    def _run_stage(
        self,
        definition: StageDefinition,
        *,
        target: str,
        mode: str,
        session_state: str,
        timeout_seconds: float,
    ) -> DiscoveryStageResult:
        """Execute one stage: every provider, honest states, aggregated result."""
        started = utcnow_iso()
        providers: list[DiscoveryProviderResult] = []
        assets: list[Any] = []
        for provider in definition.providers:
            outcome = self._run_provider(
                provider,
                stage=definition.stage,
                target=target,
                mode=mode,
                session_state=session_state,
                timeout_seconds=timeout_seconds,
            )
            providers.append(outcome)
            assets.extend(outcome.assets)
        state = _aggregate_stage_state(providers, definition)
        return DiscoveryStageResult(
            stage=definition.stage,
            state=state,
            providers=providers,
            assets=assets,
            started_at=started,
            completed_at=utcnow_iso(),
        )

    def _run_provider(
        self,
        provider: ProviderSpec,
        *,
        stage: DiscoveryStage,
        target: str,
        mode: str,
        session_state: str,
        timeout_seconds: float,
    ) -> DiscoveryProviderResult:
        """Run one provider through the engine and record its honest outcome."""
        adapter = self.engine.adapter_for(provider.tool_id)
        if adapter is None:
            return DiscoveryProviderResult(
                provider_id=provider.tool_id,
                tool_id=provider.tool_id,
                state=DiscoveryState.UNAVAILABLE,
                error="adapter not registered on the execution engine",
            )
        if not self.engine.health_check(provider.tool_id):
            return DiscoveryProviderResult(
                provider_id=provider.tool_id,
                tool_id=provider.tool_id,
                state=DiscoveryState.UNAVAILABLE,
                error="tool is not installed or unhealthy",
            )
        if provider.kind == "parameter" and mode == "passive":
            return DiscoveryProviderResult(
                provider_id=provider.tool_id,
                tool_id=provider.tool_id,
                state=DiscoveryState.NOT_APPLICABLE,
                error="parameter discovery requires an active posture",
            )

        context = self._build_context(provider, adapter=adapter, target=target, mode=mode, timeout_seconds=timeout_seconds)
        started = time.monotonic()
        pipeline = self.engine.execute(context)
        duration_ms = int((time.monotonic() - started) * 1000)
        result = pipeline.result

        if result.status is not ExecutionStatus.COMPLETED:
            error = result.error or result.failure_kind.value if result.failure_kind else "execution failed"
            return DiscoveryProviderResult(
                provider_id=provider.tool_id,
                tool_id=provider.tool_id,
                state=DiscoveryState.FAILED,
                error=str(error)[:500],
                duration_ms=duration_ms,
            )

        converted = self._convert(provider, context, result.output.json if result.output else None)
        self._track_discovered(converted)
        self._feed_surface(converted, session_state=session_state)

        state = DiscoveryState.COMPLETED
        details: dict[str, Any] = {"records": len(converted.records), "assets": len(converted.assets)}
        if not converted.records and provider.kind == "api" and "graphql" in provider.tool_id:
            state = DiscoveryState.NOT_APPLICABLE
            details["reason"] = "no GraphQL surface discovered"
        elif not converted.records:
            state = DiscoveryState.COMPLETED
            details["reason"] = "completed with no records (honest negative)"
        return DiscoveryProviderResult(
            provider_id=provider.tool_id,
            tool_id=provider.tool_id,
            state=state,
            records=tuple(converted.records),
            assets=tuple(converted.assets),
            duration_ms=duration_ms,
            details=details,
        )

    # -- context / conversion ------------------------------------------------

    def _build_context(
        self,
        provider: ProviderSpec,
        *,
        adapter: Any,
        target: str,
        mode: str,
        timeout_seconds: float,
    ) -> ExecutionContext:
        """Build an execution context for one provider run."""
        descriptor = getattr(adapter, "descriptor", None)
        permissions = tuple(getattr(descriptor, "permissions", ()) or ())
        builder = (
            ExecutionContextBuilder(tool_id=provider.tool_id, target=target)
            .with_mission(self.mission_id)
            .with_profile("universal-discovery")
            .with_timeout(timeout_seconds)
            .with_permissions(permissions)
            .with_parameters(self._parameters_for(provider, target=target, mode=mode))
        )
        return builder.build()

    def _parameters_for(self, provider: ProviderSpec, *, target: str, mode: str) -> dict[str, Any]:
        """Build tool parameters from the provider kind and discovery state."""
        parameters: dict[str, Any] = {"mode": mode}
        kind = provider.kind
        if kind == "dns":
            parameters["record_types"] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
        elif kind == "livehost" and provider.tool_id == "tcp-connect":
            parameters["ports"] = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]
        elif kind == "web":
            parameters["seed_urls"] = [target] if "://" in target else []
            parameters["depth"] = 2
            parameters["max_pages"] = 100
            parameters["respect_robots"] = False
        elif kind == "tech" and provider.tool_id == "signature":
            parameters["scheme"] = "https" if target.startswith("https") else "http"
            parameters["fallback"] = True
        elif kind == "api" and provider.tool_id == "api-graphql":
            endpoints = sorted(self._discovered["graphql_operation"])
            if endpoints:
                parameters["graphql_endpoints"] = [{"url": url} for url in endpoints]
        elif kind == "api" and provider.tool_id == "api-websocket":
            endpoints = sorted(self._discovered["websocket"])
            if endpoints:
                parameters["websocket_endpoints"] = [{"url": url} for url in endpoints]
        elif kind == "api" and provider.tool_id == "api-hints":
            parameters["web_origins"] = [{"origin_key": target}]
            parameters["url_observations"] = [{"url": url} for url in sorted(self._discovered["url"])]
            parameters["web_api_endpoints"] = [{"url": url} for url in sorted(self._discovered["api_endpoint"])]
            parameters["js_endpoints"] = [{"url": url} for url in sorted(self._discovered["javascript_endpoint"])]
            parameters["websocket_endpoints"] = [{"url": url} for url in sorted(self._discovered["websocket"])]
            parameters["graphql_endpoints"] = [{"url": url} for url in sorted(self._discovered["graphql_operation"])]
        elif kind == "javascript" and provider.tool_id == "javascript":
            scripts = sorted(self._discovered["javascript_endpoint"])
            if not scripts:
                scripts = [
                    url for url in sorted(self._discovered["url"])
                    if url.rsplit("?", 1)[0].endswith((".js", ".mjs"))
                ]
            if scripts:
                parameters["url"] = scripts[0]
        elif kind == "auth":
            parameters["auth_input"] = {
                "target": target,
                "url": target,
                "observed_urls": sorted(self._discovered["url"])[:50],
            }
        return parameters

    def _convert(self, provider: ProviderSpec, context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
        """Convert a provider payload into assets + observations."""
        converter = CONVERTERS.get(provider.kind)
        if converter is None:
            return ConversionResult()
        return converter(context, payload)

    def _track_discovered(self, converted: ConversionResult) -> None:
        """Feed converted assets into the discovery state (continuous loop)."""
        for asset in converted.assets:
            name = asset.name.strip()
            if asset.kind == "url":
                if "://" not in name:
                    continue
                if name.rsplit("?", 1)[0].endswith((".js", ".mjs")):
                    self._discovered["javascript_endpoint"].add(name)
                continue
            pool = self._discovered.get(asset.kind)
            if pool is not None:
                pool.add(name)

    def _feed_surface(self, converted: ConversionResult, *, session_state: str) -> None:
        """Feed every observation into the attack-surface service."""
        for observation in converted.observations:
            self._ingest_observation(observation, session_state=session_state)

    def _ingest_observation(self, observation: Observation, *, session_state: str) -> None:
        """Ingest one observation payload into the surface model."""
        self.surface.on_observation(
            observation_type=observation.observation_type,
            content=observation.content,
            asset_key=observation.asset_key,
            source=observation.source or "universal-discovery",
            session_state=session_state or observation.session_state,
        )

    # -- reporting -----------------------------------------------------------

    def _summarize(self, run: DiscoveryRun) -> dict[str, Any]:
        """Build the run-level summary."""
        stage_states = {stage.stage.value: stage.state.value for stage in run.stages}
        counts: dict[str, int] = {}
        for asset in run.assets:
            counts[asset.kind] = counts.get(asset.kind, 0) + 1
        provider_states: dict[str, int] = {}
        for stage in run.stages:
            for provider in stage.providers:
                provider_states[provider.state.value] = provider_states.get(provider.state.value, 0) + 1
        return {
            "target": run.target,
            "mode": run.mode,
            "stages": stage_states,
            "assets_by_kind": counts,
            "provider_states": provider_states,
            "assets_total": run.asset_count(),
            "surfaces": self.surface.snapshot(),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the service state (plan + surface) for reports."""
        return {
            "plan": [definition.stage.value for definition in self.plan.stages],
            "surface": self.surface.to_dict(),
        }


def _aggregate_stage_state(providers: list[DiscoveryProviderResult], definition: StageDefinition) -> DiscoveryState:
    """Aggregate the honest stage state from its provider outcomes.

    UNAVAILABLE providers are recorded per-provider (the report carries the
    exact gaps) but do not downgrade the stage: the stage is PARTIAL only when
    an available provider actually failed, FAILED when every available provider
    failed, UNAVAILABLE when none could run, and NOT_APPLICABLE when the stage
    does not apply.
    """
    if not providers:
        return DiscoveryState.UNAVAILABLE
    states = [provider.state for provider in providers]
    available = [state for state in states if state is not DiscoveryState.UNAVAILABLE]
    if not available:
        return DiscoveryState.UNAVAILABLE
    if all(state is DiscoveryState.NOT_APPLICABLE for state in available):
        return DiscoveryState.NOT_APPLICABLE
    if all(state is DiscoveryState.FAILED for state in available):
        return DiscoveryState.FAILED
    if any(state is DiscoveryState.FAILED for state in available):
        return DiscoveryState.PARTIAL
    if any(state is DiscoveryState.COMPLETED for state in available):
        return DiscoveryState.COMPLETED
    return DiscoveryState.PARTIAL


__all__ = ["UniversalDiscoveryService", "build_stage_plan"]
