# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology fingerprinting use-case services.

``FingerprintService`` is the orchestrator — the bridge between a mission and
the fingerprinting tooling. Given a target and a posture, it validates scope,
builds a :class:`TechStrategy`, selects the registered fingerprinting tools,
runs each through the :class:`ExecutionEngine` pipeline, folds in existing
intelligence (live service fingerprints, TLS metadata and previously persisted
technology observations), normalizes, validates, resolves, correlates and
confidence-scores the detections, detects conflicts, diffs history, persists
everything to the TIDB, updates the attack-surface topology and publishes
``technology.*`` events.

``TechnologyQueryService`` reads persisted technology intelligence back from
the TIDB and answers the reporting queries (inventory, stacks, versions, CMS,
CDN/WAF, cloud/hosting indicators and changes). Both services depend on ports
only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from hunterx.domain.entities.tidb.technology import (
    TechnologyChange as TidbTechnologyChange,
)
from hunterx.domain.entities.tidb.technology import (
    TechnologyConflict as TidbTechnologyConflict,
)
from hunterx.domain.entities.tidb.technology import (
    TechnologyEvidence as TidbTechnologyEvidence,
)
from hunterx.domain.entities.tidb.technology import (
    TechnologyObservation as TidbTechnologyObservation,
)
from hunterx.domain.entities.tidb.technology import TechnologyRun as TidbTechnologyRun
from hunterx.domain.entities.tidb.technology import TechnologyVersion as TidbTechnologyVersion
from hunterx.domain.entities.tidb.topology import TopologyRelationship as TidbTopologyRelationship
from hunterx.domain.events.types import (
    TechnologyConflictEvent,
    TechnologyDetectedEvent,
    TechnologyFingerprintingCompletedEvent,
    TechnologyFingerprintingFailedEvent,
    TechnologyFingerprintingStartedEvent,
    TechnologyPhaseStartedEvent,
    TechnologyRemovedEvent,
    TechnologyUpdatedEvent,
    TechnologyVersionChangedEvent,
    TechnologyVersionDetectedEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.recon.models import ReconMode
from hunterx.domain.technology.confidence import TechnologyConfidenceEngine
from hunterx.domain.technology.conflicts import TechnologyConflictResolver
from hunterx.domain.technology.correlator import TechnologyCorrelator
from hunterx.domain.technology.history import TechnologyHistory
from hunterx.domain.technology.models import (
    ASSET_HOSTNAME,
    ASSET_IP,
    EvidenceStrength,
    EvidenceType,
    TechChange,
    TechConflict,
    TechExecutionSummary,
    TechnologyBatch,
    TechnologyCategory,
    TechnologyEvidence,
    TechnologyObservation,
    TechTarget,
    VersionConfidence,
    VersionSpec,
    infer_asset_type,
    make_observation,
    observations_from_payload,
)
from hunterx.domain.technology.normalizer import TechnologyNormalizer
from hunterx.domain.technology.resolver import TechnologyResolver
from hunterx.domain.technology.scope import TechnologyScopeEnforcer, TechnologyScopePolicy
from hunterx.domain.technology.strategy import TechStrategy, TechStrategyBuilder
from hunterx.domain.technology.validator import TechnologyValidator
from hunterx.domain.technology.version import VersionResolver
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.models import GraphRelationship, TopologyEntity
from hunterx.domain.topology.normalizer import TopologyNormalizer
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.tech.registry import TECH_TOOL_IDS

#: Category hints that produce a strong version signal when reported by a tool.
_STRONG_VERSION_CATEGORIES = frozenset({"web-server", "cms", "application-server"})

#: TLS issuer keywords that imply a hosting/CDN provider observation.
_TLS_PROVIDER_HINTS: Mapping[str, tuple[str, str]] = {
    "cloudflare": ("Cloudflare", "cdn"),
    "fastly": ("Fastly", "cdn"),
    "akamai": ("Akamai", "cdn"),
    "amazon": ("Amazon Web Services", "cloud"),
    "google": ("Google Cloud", "cloud"),
    "azure": ("Microsoft Azure", "cloud"),
}


class FingerprintService:
    """Run technology fingerprinting missions through the Tool SDK.

    Usage::

        service = FingerprintService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="example.com", mode="hybrid")
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        scope: TechnologyScopePolicy | None = None,
        strategy_builder: TechStrategyBuilder | None = None,
        normalizer: TechnologyNormalizer | None = None,
        resolver: TechnologyResolver | None = None,
        confidence: TechnologyConfidenceEngine | None = None,
        correlator: TechnologyCorrelator | None = None,
        conflicts: TechnologyConflictResolver | None = None,
        validator: TechnologyValidator | None = None,
        history: TechnologyHistory | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._scope = scope or TechnologyScopePolicy()
        self._normalizer = normalizer or TechnologyNormalizer()
        self._resolver = resolver or TechnologyResolver(normalizer=self._normalizer)
        self._versions = VersionResolver()
        self._confidence = confidence or TechnologyConfidenceEngine()
        self._strategy_builder = strategy_builder or TechStrategyBuilder()
        self._correlator = correlator or TechnologyCorrelator(
            scope=self._scope,
            confidence=self._confidence.policy,
            resolver=self._resolver,
        )
        self._conflicts = conflicts or TechnologyConflictResolver(confidence=self._confidence.policy)
        self._validator = validator or TechnologyValidator()
        self._history = history or TechnologyHistory()
        self._scope_enforcer = TechnologyScopeEnforcer(self._scope)

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    @property
    def correlator(self) -> TechnologyCorrelator:
        """Return the correlator used to merge technology observations."""
        return self._correlator

    def run(
        self,
        *,
        mission_id: str = "",
        target: TechTarget | str,
        mode: ReconMode | str = ReconMode.HYBRID,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        categories: Sequence[TechnologyCategory | str] | None = None,
        with_history: bool = False,
        historical: Sequence[TechnologyObservation] | None = None,
        existing: Sequence[TechnologyObservation] | None = None,
        services: Sequence[object] | None = None,
        tls: Sequence[object] | None = None,
        min_confidence: float | None = None,
        max_concurrency: int = 4,
    ) -> TechnologyBatch:
        """Execute a fingerprinting run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to fingerprint (hostname, domain, IP or URL).
            mode: the execution posture (passive, active or hybrid).
            tools: fingerprinting tool ids to run; defaults to every registered
                fingerprinting tool. Requesting an unregistered tool raises
                :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context.
            categories: canonical categories to retain (empty = all).
            with_history: compare current observations against ``historical``.
            historical: historical observations to diff against.
            existing: existing technology observations to fold in.
            services: live service fingerprints (product/version) to consume.
            tls: TLS certificate observations to consume for hosting hints.
            min_confidence: minimum confidence for a technology to be retained.
            max_concurrency: execution concurrency ceiling.

        Returns:
            The :class:`TechnologyBatch` with correlated technologies, evidence,
            conflicts, changes and execution summaries.

        Raises:
            ValueError: when the target is out of scope or a requested tool is
                not registered.

        """
        tech_target = target if isinstance(target, TechTarget) else _make_target(target)
        decision = self._scope_enforcer.allows_target(tech_target)
        if not decision.allowed:
            raise ValueError(f"fingerprinting target is out of scope: {decision.reason}")
        recon_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        if recon_mode is ReconMode.PASSIVE:
            selected = []
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = recon_mode.value
        if tech_target.target_id:
            parameters["target_id"] = tech_target.target_id

        strategy = self._strategy_builder.build(
            tech_target.value,
            mode=recon_mode,
            target_kind=tech_target.target_type,
            tools=tuple(selected) if selected else (),
            categories=tuple(categories) if categories else (),
            min_confidence=min_confidence,
            with_history=with_history,
            max_concurrency=max_concurrency,
        )
        runnable = [tool_id for tool_id in strategy.tools if tool_id in selected]

        batch = TechnologyBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=tech_target,
            mode=recon_mode,
        )
        self._publish(
            TechnologyFingerprintingStartedEvent(
                mission_id,
                correlation_id,
                tech_target.value,
                mode=recon_mode.value,
                tools=list(runnable),
            )
        )

        raw: list[TechnologyObservation] = []
        try:
            self._publish(TechnologyPhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            for tool_id in runnable:
                context = self._build_context(
                    tool_id,
                    tech_target,
                    mission_id,
                    correlation_id,
                    parameters,
                    strategy,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                found = observations_from_payload(result.output.json) if result.status.is_success else []
                raw.extend(found)
                summary = TechExecutionSummary(
                    tool_id=tool_id,
                    status=result.status.value,
                    observations=len(found),
                    technologies=len({obs.canonical_name for obs in found}),
                    duration_ms=result.duration_ms,
                    error=result.error,
                )
                batch.add_execution(summary)

            self._publish(TechnologyPhaseStartedEvent(correlation_id, "existing-intelligence", mission_id=mission_id))
            existing_observations = self._collect_existing(
                tech_target,
                existing=existing,
                services=services,
                tls=tls,
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
            raw.extend(existing_observations)

            self._publish(TechnologyPhaseStartedEvent(correlation_id, "normalization", mission_id=mission_id))
            normalized = self._normalizer_step(raw)

            self._publish(TechnologyPhaseStartedEvent(correlation_id, "validation", mission_id=mission_id))
            normalized = self._validator.filter_valid(normalized)

            self._publish(TechnologyPhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlation = self._correlator.correlate(normalized, min_confidence=strategy.min_confidence)
            batch.technologies = list(correlation.technologies)
            for conflict in correlation.conflicts:
                batch.add_conflict(conflict)
                self._publish(
                    TechnologyConflictEvent(
                        correlation_id,
                        conflict.asset,
                        conflict.technology,
                        [item.get("version", "") for item in conflict.observations],
                        selected=conflict.selected,
                        conflict_type=conflict.conflict_type,
                        mission_id=mission_id,
                    )
                )

            self._publish(TechnologyPhaseStartedEvent(correlation_id, "history", mission_id=mission_id))
            if strategy.with_history and historical is not None:
                comparison = self._history.compare(historical, batch.technologies)
                for change in comparison.changes:
                    batch.add_change(change)
                    self._publish_change(change, correlation_id, mission_id)

            self._publish_detections(batch, correlation_id, mission_id)

            if self._stores is not None:
                self._publish(TechnologyPhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, tech_target, mission_id, correlation_id, strategy)

            self._publish(TechnologyPhaseStartedEvent(correlation_id, "topology", mission_id=mission_id))
            if self._stores is not None:
                self._update_topology(batch, mission_id, correlation_id)

            self._publish(
                TechnologyFingerprintingCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=tech_target.value,
                    technologies=batch.technology_count(),
                    distinct=batch.distinct_technologies(),
                    versions=batch.version_count(),
                    conflicts=batch.conflict_count(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                TechnologyFingerprintingFailedEvent(
                    mission_id,
                    correlation_id,
                    tech_target.value,
                    str(exc),
                )
            )
            raise
        return batch

    # -- pipeline helpers ---------------------------------------------------

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered fingerprinting tools to run for this mission."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in TECH_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested fingerprinting tools are not registered: {', '.join(missing)}")
        return requested

    def _build_context(
        self,
        tool_id: str,
        target: TechTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        strategy: TechStrategy,
    ) -> ExecutionContext:
        """Build an execution context for one fingerprinting tool."""
        merged = dict(parameters)
        merged.setdefault("asset_type", target.target_type)
        merged.setdefault("include_versions", strategy.include_versions)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("technology")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )

    def _collect_existing(
        self,
        target: TechTarget,
        *,
        existing: Sequence[TechnologyObservation] | None,
        services: Sequence[object] | None,
        tls: Sequence[object] | None,
        mission_id: str,
        correlation_id: str,
    ) -> list[TechnologyObservation]:
        """Fold existing intelligence into the raw observation set."""
        observations: list[TechnologyObservation] = []
        for observation in existing or ():
            if not self._scope_enforcer.allows_observation(observation).allowed:
                continue
            observations.append(observation)
        for service in services or ():
            converted = _from_service(service, self._resolver, self._versions, mission_id, correlation_id)
            if converted is not None and self._scope_enforcer.allows_observation(converted).allowed:
                observations.append(converted)
        for finding in tls or ():
            converted = _from_tls(finding, self._resolver, self._versions, mission_id, correlation_id)
            if converted is not None and self._scope_enforcer.allows_observation(converted).allowed:
                observations.append(converted)
        if self._stores is not None and self._scope_enforcer.policy.roots or self._scope_enforcer.policy.root_cidrs:
            persisted = self._load_persisted(target.value)
            observations.extend(persisted)
        return observations

    def _load_persisted(self, asset: str) -> list[TechnologyObservation]:
        """Read previously persisted technology observations for ``asset``."""
        stores = self._stores
        if stores is None:
            return []
        repo = stores.repository_for(TidbTechnologyObservation)
        records = list(repo.list_by("asset", asset, limit=500))
        observations: list[TechnologyObservation] = []
        for record in records:
            if record.deleted_at is not None:
                continue
            version_spec = None
            if record.software_version:
                version_spec = VersionSpec(
                    value=record.software_version,
                    confidence=_parse_version_confidence(record.version_confidence),
                )
            observations.append(
                make_observation(
                    asset=record.asset,
                    asset_type=record.asset_type,
                    raw_name=record.raw_name or record.canonical_name,
                    canonical_name=record.canonical_name,
                    vendor=record.vendor,
                    product=record.product,
                    version=record.software_version,
                    version_spec=version_spec,
                    category=record.category,
                    family=record.family,
                    confidence=record.confidence,
                    source=record.source or "tidb",
                    tool_id=record.tool_id or "tidb",
                    validation_status=record.validation_status,
                    observed_at=record.last_seen or record.created_at,
                )
            )
        return observations

    def _normalizer_step(self, observations: Sequence[TechnologyObservation]) -> list[TechnologyObservation]:
        """Normalize names and canonicalize unknown technologies deterministically."""
        normalized: list[TechnologyObservation] = []
        for observation in observations:
            if observation.canonical_name:
                normalized.append(observation)
                continue
            resolution = self._resolver.resolve(observation.raw_name)
            if not resolution.is_known and not observation.version_spec and observation.version:
                continue
            normalized.append(
                replace(
                    observation,
                    canonical_name=resolution.canonical_name,
                    vendor=resolution.vendor or observation.vendor,
                    product=resolution.product or observation.product,
                    category=resolution.category,
                    family=resolution.family,
                )
            )
        return normalized

    def _persist(
        self,
        batch: TechnologyBatch,
        target: TechTarget,
        mission_id: str,
        correlation_id: str,
        strategy: TechStrategy,
    ) -> int:
        """Persist correlated technology intelligence into the TIDB; returns rows."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist technology intelligence without TIDB stores")
        count = 0
        for observation in batch.technologies:
            entity = _to_observation_entity(observation, target, mission_id, correlation_id)
            stores.repository_for(TidbTechnologyObservation).save(entity)
            count += 1
            if observation.version_spec is not None and observation.version_spec.value:
                stores.repository_for(TidbTechnologyVersion).save(
                    _to_version_entity(observation, entity.id, mission_id)
                )
                count += 1
            for evidence in observation.evidence:
                stores.repository_for(TidbTechnologyEvidence).save(
                    _to_evidence_entity(observation, evidence, entity.id)
                )
                count += 1
        for conflict in batch.conflicts:
            stores.repository_for(TidbTechnologyConflict).save(
                _to_conflict_entity(conflict, mission_id, correlation_id)
            )
            count += 1
        for change in batch.changes:
            stores.repository_for(TidbTechnologyChange).save(
                _to_change_entity(change, mission_id, correlation_id)
            )
            count += 1
        run = TidbTechnologyRun(
            mission_id=mission_id,
            target_key=target.value,
            status="completed",
            observations=len(batch.raw),
            technologies=batch.technology_count(),
            versions=batch.version_count(),
            conflicts=batch.conflict_count(),
            changes=len(batch.changes),
            started_at=batch.created_at,
            completed_at=utcnow_iso(),
            summary={
                "distinct": batch.distinct_technologies(),
                "tools": [summary.tool_id for summary in batch.executions],
                "category_filter": [category.value for category in strategy.categories],
            },
            correlation_id=correlation_id,
        )
        stores.repository_for(TidbTechnologyRun).save(run)
        count += 1
        return count

    def _update_topology(self, batch: TechnologyBatch, mission_id: str, correlation_id: str) -> None:
        """Derive asset-to-technology edges and persist them into the topology."""
        stores = self._stores
        if stores is None:
            return
        repo = stores.repository_for(TidbTopologyRelationship)
        for observation in batch.technologies:
            edge = _to_relationship(observation, mission_id, correlation_id)
            if edge is None:
                continue
            repo.save(edge.to_tidb())

    # -- events -------------------------------------------------------------

    def _publish_detections(self, batch: TechnologyBatch, correlation_id: str, mission_id: str) -> None:
        """Publish detected/updated/version events for the correlated set."""
        seen: set[str] = set()
        for observation in batch.technologies:
            key = observation.key()
            is_new = key not in seen
            seen.add(key)
            if is_new:
                self._publish(
                    TechnologyDetectedEvent(
                        correlation_id,
                        observation.asset,
                        observation.canonical_name,
                        category=observation.category.value,
                        version=observation.version,
                        tool_id=observation.tool_id,
                        mission_id=mission_id,
                    )
                )
            else:
                self._publish(
                    TechnologyUpdatedEvent(
                        correlation_id,
                        observation.asset,
                        observation.canonical_name,
                        category=observation.category.value,
                        version=observation.version,
                        tool_id=observation.tool_id,
                        mission_id=mission_id,
                    )
                )
            if observation.version_spec is not None and observation.version_spec.value:
                self._publish(
                    TechnologyVersionDetectedEvent(
                        correlation_id,
                        observation.asset,
                        observation.canonical_name,
                        observation.version,
                        confidence=observation.version_spec.confidence.value,
                        mission_id=mission_id,
                    )
                )

    def _publish_change(self, change: TechChange, correlation_id: str, mission_id: str) -> None:
        """Publish the event for one historical change."""
        if change.change_type == "removed":
            self._publish(
                TechnologyRemovedEvent(
                    correlation_id,
                    change.asset,
                    change.technology,
                    previous=change.previous,
                    mission_id=mission_id,
                )
            )
            return
        if change.change_type == "changed":
            self._publish(
                TechnologyVersionChangedEvent(
                    correlation_id,
                    change.asset,
                    change.technology,
                    old_version=change.previous,
                    new_version=change.current,
                    mission_id=mission_id,
                )
            )
            return

    def _publish(self, event: Any) -> None:
        """Publish an event when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


# -- TIDB mapping helpers -----------------------------------------------------


def _to_observation_entity(
    observation: TechnologyObservation,
    target: TechTarget,
    mission_id: str,
    correlation_id: str,
) -> TidbTechnologyObservation:
    """Map a correlated observation onto the TIDB technology observation entity."""
    return TidbTechnologyObservation(
        asset=observation.asset,
        asset_type=observation.asset_type,
        raw_name=observation.raw_name,
        canonical_name=observation.canonical_name,
        vendor=observation.vendor,
        product=observation.product,
        software_version=observation.version,
        version_confidence=(
            observation.version_spec.confidence.value if observation.version_spec is not None else "unknown"
        ),
        category=observation.category.value,
        family=observation.family.value,
        confidence=observation.confidence,
        evidence_count=len(observation.evidence),
        source=observation.source,
        tool_id=observation.tool_id,
        validation_status=observation.validation_status,
        target_id=observation.target_id or target.target_id or None,
        execution_id=observation.execution_id,
        correlation_id=correlation_id,
        mission_id=mission_id,
        first_seen=observation.observed_at,
        last_seen=observation.observed_at,
    )


def _to_version_entity(
    observation: TechnologyObservation,
    observation_id: str,
    mission_id: str,
) -> TidbTechnologyVersion:
    """Map a version spec onto the TIDB technology version entity."""
    spec = observation.version_spec
    return TidbTechnologyVersion(
        observation_id=observation_id,
        asset=observation.asset,
        canonical_name=observation.canonical_name,
        value=spec.value if spec is not None else "",
        confidence=spec.confidence.value if spec is not None else "unknown",
        lower=spec.lower if spec is not None else "",
        upper=spec.upper if spec is not None else "",
        evidence=list(spec.evidence) if spec is not None else [],
        tool_id=observation.tool_id,
        meta={"mission_id": mission_id},
    )


def _to_evidence_entity(
    observation: TechnologyObservation,
    evidence: TechnologyEvidence,
    observation_id: str,
) -> TidbTechnologyEvidence:
    """Map an evidence fragment onto the TIDB evidence entity."""
    return TidbTechnologyEvidence(
        observation_id=observation_id,
        asset=observation.asset,
        canonical_name=observation.canonical_name,
        evidence_type=evidence.evidence_type.value,
        value=evidence.value,
        source=evidence.source,
        strength=evidence.strength.value,
        tool_id=evidence.tool_id,
        detail=evidence.detail,
    )


def _to_conflict_entity(conflict: TechConflict, mission_id: str, correlation_id: str) -> TidbTechnologyConflict:
    """Map a conflict onto the TIDB conflict entity."""
    return TidbTechnologyConflict(
        asset=conflict.asset,
        technology=conflict.technology,
        observations=[dict(item) for item in conflict.observations],
        conflict_type=conflict.conflict_type,
        selected_value=conflict.selected,
        selected_source=conflict.selected_source,
        reason=conflict.reason,
        confidence=conflict.confidence,
        mission_id=mission_id,
        correlation_id=correlation_id,
    )


def _to_change_entity(change: TechChange, mission_id: str, correlation_id: str) -> TidbTechnologyChange:
    """Map a historical change onto the TIDB change entity."""
    return TidbTechnologyChange(
        asset=change.asset,
        technology=change.technology,
        change_type=change.change_type,
        old_value=change.previous,
        new_value=change.current,
        tool_id=change.source,
        confidence=getattr(change, "confidence", 1.0),
        mission_id=mission_id,
        correlation_id=correlation_id,
    )


def _to_relationship(
    observation: TechnologyObservation,
    mission_id: str,
    correlation_id: str,
) -> GraphRelationship | None:
    """Build an asset-to-technology graph edge for a correlated observation."""
    source_kind = {
        "hostname": EntityKind.HOSTNAME,
        "domain": EntityKind.DOMAIN,
        "ip": EntityKind.IP,
        "url": EntityKind.HOSTNAME,
        "service": EntityKind.SERVICE,
    }.get(observation.asset_type)
    if source_kind is None:
        source_kind = EntityKind.HOSTNAME
    target_kind = _technology_entity_kind(observation.category.value)
    if not observation.canonical_name:
        return None
    return GraphRelationship(
        rel_type=RelationshipType.USES,
        source=TopologyEntity(kind=source_kind, name=observation.asset),
        target=TopologyEntity(kind=target_kind, name=observation.canonical_name),
        sources=[observation.tool_id] if observation.tool_id else ["technology"],
        evidence={
            "category": observation.category.value,
            "version": observation.version,
            "confidence": observation.confidence,
            "source": observation.source,
        },
        confidence=observation.confidence,
        mission_id=mission_id,
        correlation_id=correlation_id,
        in_scope=True,
    )


def _technology_entity_kind(category: str) -> EntityKind:
    """Map a technology category onto a canonical topology entity kind."""
    mapping = {
        "web-server": EntityKind.WEB_SERVER,
        "application-server": EntityKind.APPLICATION_SERVER,
        "cms": EntityKind.CMS,
        "framework": EntityKind.FRAMEWORK,
        "frontend": EntityKind.FRONTEND_FRAMEWORK,
        "backend": EntityKind.BACKEND_FRAMEWORK,
        "javascript": EntityKind.JAVASCRIPT,
        "programming-language": EntityKind.PROGRAMMING_LANGUAGE,
        "runtime": EntityKind.RUNTIME,
        "database": EntityKind.DATABASE,
        "operating-system": EntityKind.OPERATING_SYSTEM,
        "cdn": EntityKind.CDN,
        "waf": EntityKind.WAF,
        "proxy": EntityKind.REVERSE_PROXY,
        "load-balancer": EntityKind.LOAD_BALANCER,
        "cloud": EntityKind.CLOUD_PLATFORM,
        "hosting": EntityKind.HOSTING_PROVIDER,
    }
    return mapping.get(category, EntityKind.TECHNOLOGY)


# -- existing intelligence converters ------------------------------------------


def _from_service(
    service: object,
    resolver: TechnologyResolver,
    versions: VersionResolver,
    mission_id: str,
    correlation_id: str,
) -> TechnologyObservation | None:
    """Convert a live service fingerprint (product/version) into an observation."""
    address = str(getattr(service, "address", "") or "").strip()
    product = str(getattr(service, "product", "") or "").strip()
    name = str(getattr(service, "service", "") or "").strip()
    raw_name = product or name
    if not address or not raw_name:
        return None
    version = str(getattr(service, "version", "") or "").strip()
    evidence: tuple[TechnologyEvidence, ...] = ()
    banner = str(getattr(service, "banner", "") or "").strip()
    if banner:
        evidence = (
            TechnologyEvidence(
                evidence_type=EvidenceType.SERVICE_BANNER,
                value=banner,
                source=getattr(service, "source", "") or "tidb",
                strength=EvidenceStrength.MODERATE,
                tool_id=getattr(service, "tool_id", "") or "tidb",
                detail=banner[:256],
            ),
        )
    resolution = resolver.resolve(raw_name)
    version_spec = versions.extract(version).to_spec() if version else None
    return make_observation(
        asset=address,
        asset_type=ASSET_IP,
        raw_name=raw_name,
        canonical_name=resolution.canonical_name,
        vendor=resolution.vendor,
        product=resolution.product,
        version=version_spec.value if version_spec is not None else version,
        version_spec=version_spec,
        category=resolution.category,
        family=resolution.family,
        confidence=0.7,
        evidence=evidence,
        source=getattr(service, "source", "") or "livehost",
        tool_id=getattr(service, "tool_id", "") or "nmap",
        validation_status="valid",
    )


def _from_tls(
    finding: object,
    resolver: TechnologyResolver,
    versions: VersionResolver,
    mission_id: str,
    correlation_id: str,
) -> TechnologyObservation | None:
    """Convert a TLS certificate observation into a hosting/CDN observation."""
    issuer = str(getattr(finding, "issuer", "") or "").strip()
    if not issuer:
        return None
    lowered = issuer.lower()
    provider = next((hint for hint in _TLS_PROVIDER_HINTS if hint in lowered), None)
    if provider is None:
        return None
    canonical, category = _TLS_PROVIDER_HINTS[provider]
    address = str(getattr(finding, "address", "") or "").strip()
    asset = address or str(getattr(finding, "hostname", "") or "").strip() or issuer
    asset_type = ASSET_IP if address else ASSET_HOSTNAME
    evidence = (
        TechnologyEvidence(
            evidence_type=EvidenceType.TLS_CERTIFICATE,
            value=issuer,
            source=getattr(finding, "source", "") or "livehost",
            strength=EvidenceStrength.MODERATE,
            tool_id=getattr(finding, "tool_id", "") or "nmap",
            detail=issuer[:256],
        ),
    )
    return make_observation(
        asset=asset,
        asset_type=asset_type,
        raw_name=canonical,
        canonical_name=canonical,
        category=category,
        family="cloud-platform" if category == "cloud" else "cdn",
        confidence=0.6,
        evidence=evidence,
        source=getattr(finding, "source", "") or "livehost",
        tool_id=getattr(finding, "tool_id", "") or "nmap",
        validation_status="unknown",
    )


# -- small helpers -------------------------------------------------------------


def _make_target(target: str) -> TechTarget:
    """Build a :class:`TechTarget` from a plain string."""
    stripped = target.strip()
    return TechTarget(value=stripped, target_type=infer_asset_type(stripped))


def _make_mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    return ReconMode(str(mode).lower())


def _parse_version_confidence(value: object) -> VersionConfidence:
    """Coerce a stored version-confidence string into a :class:`VersionConfidence`."""
    try:
        return VersionConfidence(str(value).lower())
    except ValueError:
        return VersionConfidence.UNKNOWN


class TechnologyQueryService:
    """Answer technology intelligence queries from persisted TIDB records."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
        resolver: TechnologyResolver | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache
        self._resolver = resolver or TechnologyResolver()
        self._normalizer = TopologyNormalizer()

    def inventory(self, *, asset: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return the persisted technology inventory (optionally filtered)."""
        observations = self._observations(asset=asset, mission_id=mission_id)
        return [self._observation_dict(observation) for observation in observations]

    def stack(self, asset: str, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the technology stack for one asset."""
        return [
            self._observation_dict(observation)
            for observation in self._observations(asset=asset, mission_id=mission_id)
        ]

    def by_category(self, category: str, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return technologies in a canonical category."""
        return [
            self._observation_dict(observation)
            for observation in self._observations(mission_id=mission_id)
            if observation.category == category
        ]

    def versions(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return every persisted technology with an evidence-backed version."""
        result: list[dict[str, Any]] = []
        for observation in self._observations(mission_id=mission_id):
            if observation.software_version:
                result.append(self._observation_dict(observation))
        return result

    def cms(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the CMS technologies."""
        return self.by_category("cms", mission_id=mission_id)

    def frameworks(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the framework-family technologies."""
        return [
            self._observation_dict(observation)
            for observation in self._observations(mission_id=mission_id)
            if observation.family in ("web-framework", "frontend-framework", "backend-framework")
        ]

    def servers(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the web/application server technologies."""
        return [
            self._observation_dict(observation)
            for observation in self._observations(mission_id=mission_id)
            if observation.category in ("web-server", "application-server")
        ]

    def cdn_waf(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the CDN/WAF/proxy technologies."""
        return [
            self._observation_dict(observation)
            for observation in self._observations(mission_id=mission_id)
            if observation.category in ("cdn", "waf", "proxy", "load-balancer")
        ]

    def cloud_hosting(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return the cloud/hosting indicator technologies."""
        return [
            self._observation_dict(observation)
            for observation in self._observations(mission_id=mission_id)
            if observation.category in ("cloud", "hosting")
        ]

    def conflicts(self, *, asset: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted technology conflicts."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbTechnologyConflict)
        records = list(repo.list_by("asset", asset, limit=500)) if asset else list(repo.stream())
        return [
            {
                "asset": record.asset,
                "technology": record.technology,
                "conflict_type": record.conflict_type,
                "selected": record.selected_value,
                "selected_source": record.selected_source,
                "reason": record.reason,
                "confidence": record.confidence,
                "mission_id": record.mission_id,
                "created_at": record.created_at,
            }
            for record in records
            if record.deleted_at is None and (not mission_id or record.mission_id == mission_id)
        ]

    def changes(self, *, asset: str = "", mission_id: str = "") -> list[dict[str, Any]]:
        """Return persisted technology changes."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbTechnologyChange)
        records = list(repo.list_by("asset", asset, limit=500)) if asset else list(repo.stream())
        return [
            {
                "asset": record.asset,
                "technology": record.technology,
                "change_type": record.change_type,
                "old_value": record.old_value,
                "new_value": record.new_value,
                "tool_id": record.tool_id,
                "mission_id": record.mission_id,
                "created_at": record.created_at,
            }
            for record in records
            if record.deleted_at is None and (not mission_id or record.mission_id == mission_id)
        ]

    # -- helpers ------------------------------------------------------------

    def _observations(self, *, asset: str = "", mission_id: str = "") -> list[Any]:
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbTechnologyObservation)
        records = list(repo.list_by("asset", asset, limit=1000)) if asset else list(repo.stream())
        if mission_id:
            records = [record for record in records if record.mission_id == mission_id]
        return [record for record in records if record.deleted_at is None]

    def _observation_dict(self, record: Any) -> dict[str, Any]:
        return {
            "asset": record.asset,
            "asset_type": record.asset_type,
            "technology": record.canonical_name,
            "raw_name": record.raw_name,
            "vendor": record.vendor,
            "product": record.product,
            "version": record.software_version,
            "version_confidence": record.version_confidence,
            "category": record.category,
            "family": record.family,
            "confidence": record.confidence,
            "evidence_count": record.evidence_count,
            "tool_id": record.tool_id,
            "source": record.source,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
            "mission_id": record.mission_id,
        }
