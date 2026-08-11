# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Target Intelligence use-case services.

``TargetIntelligenceService`` is the orchestrator: it bridges the pure target
intelligence domain and the :class:`TargetIntelligenceEngine` to the TIDB
system-of-record, wires the Sprint 025 mission-aware tool selector into the
next-action engine, persists normalized intelligence entities (targets,
assets, observations, evidence, history, changes, coverage, gaps, hypotheses,
actions, decisions, negative results, conflicts, scores) and publishes
``target-intelligence.*`` events.

``TargetIntelligenceQueryService`` reads persisted intelligence records back
from the TIDB and answers the canonical queries (target state, graph, coverage
matrix, gaps, hypotheses, actions, history, scores, replay).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunterx.domain.entities.tidb.target_intelligence import (
    CoverageRecord,
    HypothesisRecord,
    InformationGapRecord,
    IntelligenceActionRecord,
    IntelligenceAssetRecord,
    IntelligenceChangeRecord,
    IntelligenceConflictRecord,
    IntelligenceDecisionRecord,
    IntelligenceEvidenceRecord,
    IntelligenceScoreRecord,
    IntelligenceTargetRecord,
    NegativeResultRecord,
    ObservationRecord,
    TargetHistoryRecord,
)
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.target_intelligence.actions import NextActionEngine, ToolSelectorAdapter
from hunterx.domain.target_intelligence.coverage import CoverageEngine
from hunterx.domain.target_intelligence.enums import (
    ActionStatus,
    ActionType,
    ChangeKind,
    ConflictState,
    CoverageCapability,
    HypothesisStatus,
    HypothesisType,
    InformationGapCategory,
    IntelligencePhase,
    IntelligenceTargetKind,
    IntelligenceTargetStatus,
    ObservationType,
    StopCondition,
)
from hunterx.domain.target_intelligence.models import (
    CoverageMatrix,
    Hypothesis,
    InformationGap,
    IntelligenceAction,
    IntelligenceAsset,
    IntelligenceChange,
    IntelligenceConflict,
    IntelligenceDecision,
    IntelligenceEvidence,
    IntelligenceScore,
    IntelligenceTarget,
    NegativeResult,
    Observation,
    TargetHistoryEntry,
    TargetIntelligenceState,
)
from hunterx.engines.target_intelligence.engine import TargetIntelligenceEngine

#: CoverageCapability → Sprint 023/025 tool capability id mapping. When no tool
#: maps, the adapter falls back to ``http-enumeration``.
_CAPABILITY_TO_TIP: dict[str, str] = {
    "asset_discovery": "host-discovery",
    "subdomain_enumeration": "subdomain-discovery",
    "port_discovery": "port-scanning",
    "service_detection": "service-fingerprint",
    "technology_fingerprint": "technology-detection",
    "content_discovery": "directory-discovery",
    "parameter_discovery": "parameter-discovery",
    "endpoint_enumeration": "http-enumeration",
    "api_mapping": "api-discovery",
    "graphql_enumeration": "graphql-testing",
    "javascript_analysis": "javascript-analysis",
    "dns_enumeration": "dns-records",
    "certificate_enumeration": "certificate-lookup",
    "authentication_analysis": "http-enumeration",
    "authorization_analysis": "http-enumeration",
    "cloud_ownership_mapping": "cloud-assessment",
    "vulnerability_scanning": "vulnerability-scan",
    "sql_injection": "sqli-detection",
    "xss": "xss-detection",
    "ssrf": "web-fuzzing",
    "ssti": "ssti-detection",
    "xxe": "web-fuzzing",
    "lfi": "web-fuzzing",
    "rce": "vulnerability-scan",
    "idor": "http-enumeration",
    "api_security": "api-fuzzing",
    "graphql_security": "graphql-testing",
    "secret_detection": "secrets-detection",
    "dependency_check": "cve-detection",
    "proof_validation": "evidence-capture",
    "replay": "evidence-capture",
}


class _MasteryToolSelectorAdapter:
    """Sprint 025 wiring: adapts the mission-aware selector to the engine.

    The adapter never widens scope or authorization: it only forwards a
    capability requirement and reports the selected tool plus its rationale.
    When selection fails (no tool within the mission ceiling), the engine
    degrades gracefully to an undecided tool.
    """

    def __init__(self, selector: Any, *, mission_type: str = "bug-bounty") -> None:
        self._selector = selector
        self._mission_type = mission_type

    def select(
        self,
        *,
        target: IntelligenceTarget,
        capability: CoverageCapability,
        asset_key: str = "",
        mission_id: str = "",
    ) -> tuple[str, tuple[str, ...], str]:
        tip_capability = _CAPABILITY_TO_TIP.get(capability.value, "http-enumeration")
        try:
            decisions = self._selector.select(
                tip_capability,
                mission_type=self._mission_type,
                target_type=target.kind.value,
                limit=4,
            )
        except Exception:  # noqa: BLE001 - selection failures degrade gracefully
            return "", (), f"no tool selected for {capability.value}"
        if not decisions:
            return "", (), f"no tool available for {capability.value}"
        best = decisions[0]
        alternatives = tuple(decision.tool_id for decision in decisions[1:4])
        return best.tool_id, alternatives, best.reason or f"required capability: {capability.value}"


class TargetIntelligenceService:
    """Orchestrate the target intelligence layer against the TIDB + Sprint 025."""

    def __init__(
        self,
        *,
        engine: TargetIntelligenceEngine | None = None,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        mastery: Any | None = None,
        mission_type: str = "bug-bounty",
    ) -> None:
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._engine = engine or TargetIntelligenceEngine()
        if mastery is not None:
            self._wire_mastery(mastery, mission_type=mission_type)

    @property
    def engine(self) -> TargetIntelligenceEngine:
        """Return the underlying target intelligence engine."""
        return self._engine

    def _wire_mastery(self, mastery: Any, *, mission_type: str) -> None:
        """Wire the Sprint 025 mission-aware selector into the next-action engine."""
        selector = getattr(mastery, "selector", None)
        if selector is None:
            return
        adapter: ToolSelectorAdapter = _MasteryToolSelectorAdapter(selector, mission_type=mission_type)
        engine = self._engine
        engine.next_action = NextActionEngine(
            weights=engine.next_action.weights,
            tool_selector=adapter,
            action_budget=engine.next_action.action_budget,
        )

    # -- ingestion ----------------------------------------------------------

    def register_target(
        self,
        target: IntelligenceTarget,
        *,
        persist: bool = True,
    ) -> IntelligenceTarget:
        """Register a target in the engine and the TIDB."""
        registered = self._engine.register_target(target)
        if persist and self._stores is not None:
            repo = self._stores.repository_for(IntelligenceTargetRecord)
            repo.save(_target_to_record(registered))
        self._publish("target-intelligence.target.registered", {"target_id": target.target_id})
        return registered

    def ingest_observations(
        self,
        target: IntelligenceTarget,
        observations: Sequence[Observation],
        *,
        persist: bool = True,
    ) -> list[Observation]:
        """Ingest observations into the engine and persist them to the TIDB."""
        accepted = self._engine.ingest_observations(target, observations)
        if persist and self._stores is not None and accepted:
            repo = self._stores.repository_for(ObservationRecord)
            repo.save_many([_observation_to_record(obs) for obs in accepted])
            self._persist_assets(target)
            self._persist_coverage(target)
        self._publish(
            "target-intelligence.observations.ingested",
            {"target_id": target.target_id, "count": len(accepted)},
        )
        return accepted

    def ingest_assets(self, target: IntelligenceTarget, assets: Sequence[IntelligenceAsset], *, persist: bool = True) -> list[IntelligenceAsset]:
        """Ingest assets into the engine and persist them to the TIDB."""
        accepted = self._engine.ingest_assets(target, assets)
        if persist and self._stores is not None and accepted:
            self._persist_assets(target)
        return accepted

    def ingest_evidence(self, target: IntelligenceTarget, evidence: Sequence[IntelligenceEvidence], *, persist: bool = True) -> list[IntelligenceEvidence]:
        """Store evidence records in the engine and the TIDB."""
        stored = self._engine.ingest_evidence(target, evidence)
        if persist and self._stores is not None and stored:
            repo = self._stores.repository_for(IntelligenceEvidenceRecord)
            repo.save_many([_evidence_to_record(item) for item in stored])
        return stored

    def record_negative(self, target: IntelligenceTarget, negative: NegativeResult, *, persist: bool = True) -> NegativeResult:
        """Record a carefully-scoped negative result."""
        stored = self._engine.record_negative(target, negative)
        if persist and self._stores is not None:
            repo = self._stores.repository_for(NegativeResultRecord)
            repo.save(_negative_to_record(stored))
            self._persist_coverage(target)
            self._persist_history(target)
        self._publish(
            "target-intelligence.negative.recorded",
            {"target_id": target.target_id, "capability": negative.tested_capability.value},
        )
        return stored

    # -- analysis -----------------------------------------------------------

    def run_cycle(
        self,
        target: IntelligenceTarget,
        *,
        mission_objective: str = "",
        available_tools: Sequence[str] | None = None,
        safety_ceiling: str = "high_impact",
        authorization_granted: bool = False,
        persist: bool = True,
    ) -> tuple[TargetIntelligenceState, list[IntelligenceAction], IntelligenceDecision]:
        """Run one adaptive intelligence cycle and persist the derived state."""
        state, actions, decision = self._engine.run_cycle(
            target,
            mission_objective=mission_objective,
            available_tools=available_tools,
            safety_ceiling=safety_ceiling,
            authorization_granted=authorization_granted,
        )
        if persist and self._stores is not None:
            self._persist_cycle(target, state, actions, decision)
        self._publish(
            "target-intelligence.cycle.completed",
            {
                "target_id": target.target_id,
                "phase": state.target.phase.value,
                "actions": len(actions),
                "hypotheses": len(state.hypotheses),
                "gaps": len(state.gaps),
            },
        )
        return state, actions, decision

    def snapshot(self, target: IntelligenceTarget) -> TargetIntelligenceState:
        """Return the assembled intelligence state for a target."""
        return self._engine.snapshot(target)

    def score(self, target: IntelligenceTarget) -> IntelligenceScore:
        """Compute (and persist) the explainable intelligence score."""
        score = self._engine.score(target)
        if self._stores is not None:
            repo = self._stores.repository_for(IntelligenceScoreRecord)
            repo.save(_score_to_record(target, score))
        return score

    def detect_changes(self, target: IntelligenceTarget, *, persist: bool = True) -> list[IntelligenceChange]:
        """Detect target changes and persist them."""
        changes = self._engine.detect_changes(target)
        if persist and self._stores is not None and changes:
            repo = self._stores.repository_for(IntelligenceChangeRecord)
            repo.save_many([_change_to_record(change) for change in changes])
            self._persist_history(target)
        return changes

    def replay(self, target: IntelligenceTarget, observations: Sequence[Observation], *, mission_objective: str = "") -> Any:
        """Replay the intelligence pipeline from stored observations."""
        from hunterx.domain.target_intelligence.replay import IntelligenceReplayRunner

        runner = IntelligenceReplayRunner(
            correlator=self._engine.correlator,
            hypotheses=self._engine.hypotheses,
            next_action=self._engine.next_action,
            coverage=self._engine.coverage,
        )
        return runner.replay(target, observations, mission_objective=mission_objective)

    # -- persistence --------------------------------------------------------

    def _persist_assets(self, target: IntelligenceTarget) -> None:
        if self._stores is None:
            return
        assets = self._engine.assets.list(target_id=target.target_id)
        if assets:
            repo = self._stores.repository_for(IntelligenceAssetRecord)
            repo.save_many([_asset_to_record(asset) for asset in assets])

    def _persist_coverage(self, target: IntelligenceTarget) -> None:
        if self._stores is None:
            return
        entries = self._engine.coverage.matrix(target.target_id).entries
        if entries:
            repo = self._stores.repository_for(CoverageRecord)
            repo.save_many([_coverage_to_record(target, entry) for entry in entries])

    def _persist_history(self, target: IntelligenceTarget) -> None:
        if self._stores is None:
            return
        entries = self._engine.history.for_target(target.target_id, limit=500)
        if entries:
            repo = self._stores.repository_for(TargetHistoryRecord)
            repo.save_many([_history_to_record(entry) for entry in entries])

    def _persist_cycle(
        self,
        target: IntelligenceTarget,
        state: TargetIntelligenceState,
        actions: Sequence[IntelligenceAction],
        decision: IntelligenceDecision,
    ) -> None:
        if self._stores is None:
            return
        stores = self._stores

        target_repo = stores.repository_for(IntelligenceTargetRecord)
        target_repo.save(_target_to_record(state.target))

        self._persist_assets(target)
        self._persist_coverage(target)
        self._persist_history(target)

        if state.gaps:
            gaps_repo = stores.repository_for(InformationGapRecord)
            gaps_repo.save_many([_gap_to_record(gap) for gap in state.gaps])
        if state.hypotheses:
            hyp_repo = stores.repository_for(HypothesisRecord)
            hyp_repo.save_many([_hypothesis_to_record(h) for h in state.hypotheses])
        if actions:
            action_repo = stores.repository_for(IntelligenceActionRecord)
            action_repo.save_many([_action_to_record(action) for action in actions])
        if state.conflicts:
            conflict_repo = stores.repository_for(IntelligenceConflictRecord)
            conflict_repo.save_many([_conflict_to_record(c) for c in state.conflicts])
        if state.negative_results:
            neg_repo = stores.repository_for(NegativeResultRecord)
            neg_repo.save_many([_negative_to_record(n) for n in state.negative_results])
        if decision.decision_id:
            decision_repo = stores.repository_for(IntelligenceDecisionRecord)
            decision_repo.save(_decision_to_record(decision))
        if state.score is not None:
            score_repo = stores.repository_for(IntelligenceScoreRecord)
            score_repo.save(_score_to_record(target, state.score))

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        if self._event_bus is None:
            return
        from hunterx.domain.events import DomainEvent

        self._event_bus.publish(DomainEvent(event_type=event_type, payload=payload, source="application.target_intelligence"))


class TargetIntelligenceQueryService:
    """Answer canonical target-intelligence queries from persisted TIDB records."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
        engine: TargetIntelligenceEngine | None = None,
        coverage: CoverageEngine | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache
        self._engine = engine or TargetIntelligenceEngine(coverage=coverage or CoverageEngine())

    def get_target(self, target_id: str) -> IntelligenceTarget | None:
        """Return a persisted intelligence target or ``None``."""
        if self._stores is None:
            return self._engine.get_target(target_id)
        records = self._stores.repository_for(IntelligenceTargetRecord).list_by("target_id", target_id, limit=1)
        if not records:
            return self._engine.get_target(target_id)
        return _target_from_record(records[0])

    def assets(self, *, target_id: str = "", kind: str = "") -> list[IntelligenceAsset]:
        """Return persisted assets, optionally filtered."""
        if self._stores is None:
            return self._engine.assets.list(target_id=target_id, kind=kind)
        records = list(self._stores.repository_for(IntelligenceAssetRecord).stream())
        if target_id:
            records = [r for r in records if r.target_id == target_id]
        if kind:
            records = [r for r in records if r.kind == kind]
        return [_asset_from_record(r) for r in records]

    def observations(self, *, target_id: str = "", mission_id: str = "") -> list[Observation]:
        """Return persisted observations within an optional scope."""
        if self._stores is None:
            return list(self._engine.observations.stream(target_id=target_id, mission_id=mission_id))
        records = list(self._stores.repository_for(ObservationRecord).stream())
        if target_id:
            records = [r for r in records if r.target_id == target_id]
        if mission_id:
            records = [r for r in records if r.mission_id == mission_id]
        return [_observation_from_record(r) for r in records]

    def coverage_matrix(self, target_id: str) -> CoverageMatrix:
        """Return the persisted coverage matrix for a target."""
        if self._stores is None:
            return self._engine.coverage.matrix(target_id)
        records = [r for r in self._stores.repository_for(CoverageRecord).stream() if r.target_id == target_id]
        from hunterx.domain.target_intelligence.models import CoverageEntry

        entries = tuple(
            sorted(
                (
                    CoverageEntry(
                        record_id=r.id,
                        target_id=r.target_id,
                        asset_key=r.asset_key,
                        capability=_enum(CoverageCapability, r.capability, CoverageCapability.ASSET_DISCOVERY),
                        state=r.state,
                        tool=r.tool,
                        confidence=r.confidence,
                        tested_at=r.tested_at,
                        evidence_refs=tuple(r.evidence_refs),
                        notes=r.notes,
                    )
                    for r in records
                ),
                key=lambda e: e.cell_key,
            )
        )
        return CoverageMatrix(target_id=target_id, entries=entries)

    def gaps(self, target_id: str) -> list[InformationGap]:
        """Return persisted information gaps for a target."""
        if self._stores is None:
            return self._engine._gaps.get(target_id, [])
        records = [r for r in self._stores.repository_for(InformationGapRecord).stream() if r.target_id == target_id]
        return [_gap_from_record(r) for r in records]

    def hypotheses(self, target_id: str) -> list[Hypothesis]:
        """Return persisted hypotheses for a target."""
        if self._stores is None:
            return self._engine._hypotheses.get(target_id, [])
        records = [r for r in self._stores.repository_for(HypothesisRecord).stream() if r.target_id == target_id]
        return [_hypothesis_from_record(r) for r in records]

    def actions(self, target_id: str) -> list[IntelligenceAction]:
        """Return persisted actions for a target (highest priority first)."""
        if self._stores is None:
            return []
        records = [r for r in self._stores.repository_for(IntelligenceActionRecord).stream() if r.target_id == target_id]
        actions = [_action_from_record(r) for r in records]
        return sorted(actions, key=lambda a: (-a.priority, a.created_at))

    def history(self, target_id: str, *, limit: int = 200) -> list[TargetHistoryEntry]:
        """Return persisted history entries for a target."""
        if self._stores is None:
            return self._engine.history.for_target(target_id, limit=limit)
        records = [r for r in self._stores.repository_for(TargetHistoryRecord).stream() if r.target_id == target_id]
        records.sort(key=lambda r: r.changed_at, reverse=True)
        return [_history_from_record(r) for r in records[:limit]]

    def changes(self, target_id: str) -> list[IntelligenceChange]:
        """Return persisted changes for a target."""
        if self._stores is None:
            return self._engine._changes.get(target_id, [])
        records = [r for r in self._stores.repository_for(IntelligenceChangeRecord).stream() if r.target_id == target_id]
        return [_change_from_record(r) for r in records]

    def conflicts(self, target_id: str) -> list[IntelligenceConflict]:
        """Return persisted conflicts for a target."""
        if self._stores is None:
            return self._engine.conflict_manager.all(target_id=target_id)
        records = [r for r in self._stores.repository_for(IntelligenceConflictRecord).stream() if r.target_id == target_id]
        return [_conflict_from_record(r) for r in records]

    def negative_results(self, target_id: str) -> list[NegativeResult]:
        """Return persisted negative results for a target."""
        if self._stores is None:
            return self._engine._negatives.get(target_id, [])
        records = [r for r in self._stores.repository_for(NegativeResultRecord).stream() if r.target_id == target_id]
        return [_negative_from_record(r) for r in records]

    def score(self, target_id: str) -> IntelligenceScore | None:
        """Return the latest persisted score for a target or ``None``."""
        if self._stores is None:
            return self._engine._scores.get(target_id)
        records = [r for r in self._stores.repository_for(IntelligenceScoreRecord).stream() if r.target_id == target_id]
        if not records:
            return None
        latest = max(records, key=lambda r: r.created_at)
        return _score_from_record(latest)


# ==========================================================================
# Domain ↔ TIDB record mapping helpers
# ==========================================================================


def _enum(enum_cls: type, value: object, default: Any) -> Any:
    """Coerce a persisted string (or enum) to ``enum_cls``."""
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value))
    except (ValueError, TypeError):
        return default


def _target_to_record(target: IntelligenceTarget) -> IntelligenceTargetRecord:
    return IntelligenceTargetRecord(
        target_id=target.target_id,
        mission_id=target.mission_id,
        scope=target.scope,
        identity=target.identity,
        classification=target.classification,
        criticality=target.criticality,
        kind=target.kind.value,
        value=target.value,
        status=target.status.value,
        confidence=target.confidence,
        phase=target.phase.value,
        intelligence_state=target.intelligence_state,
        coverage_state=target.coverage_state,
        tenant=target.tenant,
    )


def _target_from_record(record: IntelligenceTargetRecord) -> IntelligenceTarget:
    return IntelligenceTarget(
        target_id=record.target_id,
        mission_id=record.mission_id,
        scope=record.scope,
        identity=record.identity,
        classification=record.classification,
        criticality=record.criticality,
        kind=_enum(IntelligenceTargetKind, record.kind, IntelligenceTargetKind.DOMAIN),
        value=record.value,
        status=_enum(IntelligenceTargetStatus, record.status, IntelligenceTargetStatus.ACTIVE),
        confidence=record.confidence,
        phase=_enum(IntelligencePhase, record.phase, IntelligencePhase.DISCOVERY),
        intelligence_state=dict(record.intelligence_state),
        coverage_state={k: float(v) for k, v in (record.coverage_state or {}).items()},
        tenant=record.tenant,
    )


def _asset_to_record(asset: IntelligenceAsset) -> IntelligenceAssetRecord:
    return IntelligenceAssetRecord(
        asset_id=asset.asset_id,
        target_id=asset.target_id,
        mission_id=asset.mission_id,
        kind=asset.kind.value if hasattr(asset.kind, "value") else str(asset.kind),
        name=asset.name,
        asset_key=asset.key,
        label=asset.label,
        properties=asset.properties,
        confidence=asset.confidence,
        in_scope=asset.in_scope,
        source=asset.source,
        parent_key=asset.parent_key,
        observed_by=list(asset.observed_by),
    )


def _asset_from_record(record: IntelligenceAssetRecord) -> IntelligenceAsset:
    return IntelligenceAsset(
        asset_id=record.asset_id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        kind=record.kind,
        name=record.name,
        key=record.asset_key,
        label=record.label,
        properties=dict(record.properties),
        confidence=record.confidence,
        in_scope=record.in_scope,
        source=record.source,
        parent_key=record.parent_key,
        observed_by=tuple(record.observed_by),
    )


def _observation_to_record(obs: Observation) -> ObservationRecord:
    return ObservationRecord(
        observation_id=obs.observation_id,
        target_id=obs.target_id,
        mission_id=obs.mission_id,
        tool=obs.tool,
        tool_version=obs.tool_version,
        capability=obs.capability,
        timestamp=obs.timestamp,
        observation_type=obs.observation_type.value,
        value=obs.value,
        normalized_value=obs.normalized_value,
        confidence=obs.confidence,
        source=obs.source,
        provenance=obs.provenance,
        scope=obs.scope,
        raw_artifact_ref=obs.raw_artifact_ref,
        evidence_ref=obs.evidence_ref,
        expires_at=obs.expires_at,
        asset_key=obs.asset_key,
        dedup_key=obs.dedup_key,
        supersedes=obs.supersedes,
    )


def _observation_from_record(record: ObservationRecord) -> Observation:
    return Observation(
        observation_id=record.observation_id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        tool=record.tool,
        tool_version=record.tool_version,
        capability=record.capability,
        timestamp=record.timestamp,
        observation_type=_enum(ObservationType, record.observation_type, ObservationType.OTHER),
        value=record.value,
        normalized_value=record.normalized_value,
        confidence=record.confidence,
        source=record.source,
        provenance=dict(record.provenance),
        scope=record.scope,
        raw_artifact_ref=record.raw_artifact_ref,
        evidence_ref=record.evidence_ref,
        expires_at=record.expires_at,
        asset_key=record.asset_key,
        dedup_key=record.dedup_key,
        supersedes=record.supersedes,
    )


def _evidence_to_record(item: IntelligenceEvidence) -> IntelligenceEvidenceRecord:
    return IntelligenceEvidenceRecord(
        evidence_id=item.evidence_id,
        target_id=item.target_id,
        mission_id=item.mission_id,
        asset_key=item.asset_key,
        what=item.what,
        where=item.where,
        when=item.when,
        how=item.how,
        source=item.source,
        why_trust=item.why_trust,
        reproducibility=item.reproducibility,
        tool=item.tool,
        tool_version=item.tool_version,
        command_configuration=item.command_configuration,
        raw_artifact_ref=item.raw_artifact_ref,
        parser_version=item.parser_version,
        normalizer_version=item.normalizer_version,
        confidence=item.confidence,
    )


def _evidence_from_record(record: IntelligenceEvidenceRecord) -> IntelligenceEvidence:
    return IntelligenceEvidence(
        evidence_id=record.evidence_id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        what=record.what,
        where=record.where,
        when=record.when,
        how=record.how,
        source=record.source,
        why_trust=record.why_trust,
        reproducibility=record.reproducibility,
        tool=record.tool,
        tool_version=record.tool_version,
        command_configuration=dict(record.command_configuration),
        raw_artifact_ref=record.raw_artifact_ref,
        parser_version=record.parser_version,
        normalizer_version=record.normalizer_version,
        confidence=record.confidence,
    )


def _history_to_record(entry: TargetHistoryEntry) -> TargetHistoryRecord:
    return TargetHistoryRecord(
        target_id=entry.target_id,
        mission_id=entry.mission_id,
        asset_key=entry.asset_key,
        field=entry.attribute,
        kind=entry.kind.value,
        previous_value=entry.previous_value,
        new_value=entry.new_value,
        source=entry.source,
        confidence=entry.confidence,
        changed_at=entry.changed_at,
        correlation_id=entry.correlation_id,
    )


def _history_from_record(record: TargetHistoryRecord) -> TargetHistoryEntry:
    return TargetHistoryEntry(
        history_id=record.id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        attribute=record.field,
        kind=_enum(ChangeKind, record.kind, ChangeKind.NEW),
        previous_value=record.previous_value,
        new_value=record.new_value,
        source=record.source,
        confidence=record.confidence,
        changed_at=record.changed_at,
        correlation_id=record.correlation_id,
    )


def _change_to_record(change: IntelligenceChange) -> IntelligenceChangeRecord:
    return IntelligenceChangeRecord(
        target_id=change.target_id,
        mission_id=change.mission_id,
        asset_key=change.asset_key,
        kind=change.kind.value,
        previous=change.previous,
        current=change.current,
        source=change.source,
        confidence=change.confidence,
        detected_at=change.detected_at,
    )


def _change_from_record(record: IntelligenceChangeRecord) -> IntelligenceChange:
    return IntelligenceChange(
        change_id=record.id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        kind=_enum(ChangeKind, record.kind, ChangeKind.NEW),
        previous=dict(record.previous),
        current=dict(record.current),
        source=record.source,
        confidence=record.confidence,
        detected_at=record.detected_at,
    )


def _coverage_to_record(target: IntelligenceTarget, entry: Any) -> CoverageRecord:
    return CoverageRecord(
        target_id=entry.target_id,
        asset_key=entry.asset_key,
        capability=entry.capability.value,
        state=entry.state.value,
        tool=entry.tool,
        confidence=entry.confidence,
        tested_at=entry.tested_at,
        evidence_refs=list(entry.evidence_refs),
        notes=entry.notes,
    )


def _gap_to_record(gap: InformationGap) -> InformationGapRecord:
    return InformationGapRecord(
        target_id=gap.target_id,
        mission_id=gap.mission_id,
        asset_key=gap.asset_key,
        category=gap.category.value,
        question=gap.question,
        importance=gap.importance,
        confidence=gap.confidence,
        required_capability=gap.required_capability.value,
        candidate_tools=list(gap.candidate_tools),
        estimated_cost=gap.estimated_cost,
        risk=gap.risk,
        blocking=gap.blocking,
    )


def _gap_from_record(record: InformationGapRecord) -> InformationGap:
    return InformationGap(
        gap_id=record.id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        category=_enum(InformationGapCategory, record.category, InformationGapCategory.ASSET_DISCOVERY),
        question=record.question,
        importance=record.importance,
        confidence=record.confidence,
        required_capability=_enum(CoverageCapability, record.required_capability, CoverageCapability.ASSET_DISCOVERY),
        candidate_tools=tuple(record.candidate_tools),
        estimated_cost=record.estimated_cost,
        risk=record.risk,
        blocking=record.blocking,
    )


def _hypothesis_to_record(hypothesis: Hypothesis) -> HypothesisRecord:
    return HypothesisRecord(
        target_id=hypothesis.target_id,
        mission_id=hypothesis.mission_id,
        asset_key=hypothesis.asset_key,
        category=hypothesis.category.value,
        statement=hypothesis.statement,
        supporting_observations=list(hypothesis.supporting_observations),
        contradicting_observations=list(hypothesis.contradicting_observations),
        required_evidence=list(hypothesis.required_evidence),
        validation_strategy=hypothesis.validation_strategy,
        proof_strategy=hypothesis.proof_strategy,
        confidence=hypothesis.confidence,
        priority=hypothesis.priority,
        status=hypothesis.status.value,
    )


def _hypothesis_from_record(record: HypothesisRecord) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=record.id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        category=_enum(HypothesisType, record.category, HypothesisType.UNKNOWN_BEHAVIOR),
        statement=record.statement,
        supporting_observations=tuple(record.supporting_observations),
        contradicting_observations=tuple(record.contradicting_observations),
        required_evidence=tuple(record.required_evidence),
        validation_strategy=record.validation_strategy,
        proof_strategy=record.proof_strategy,
        confidence=record.confidence,
        priority=record.priority,
        status=_enum(HypothesisStatus, record.status, HypothesisStatus.PROPOSED),
    )


def _action_to_record(action: IntelligenceAction) -> IntelligenceActionRecord:
    return IntelligenceActionRecord(
        target_id=action.target_id,
        mission_id=action.mission_id,
        asset_key=action.asset_key,
        objective=action.objective,
        action_type=action.action_type.value,
        required_capability=action.required_capability.value,
        tool=action.tool,
        reason=action.reason,
        expected_information_gain=action.expected_information_gain,
        expected_evidence=list(action.expected_evidence),
        estimated_cost=action.estimated_cost,
        risk=action.risk,
        scope_status=action.scope_status,
        preconditions=list(action.preconditions),
        stop_conditions=[s.value for s in action.stop_conditions],
        fallback=action.fallback,
        priority=action.priority,
        status=action.status.value,
        decision_id=action.decision_id,
        candidates=list(action.candidates),
    )


def _action_from_record(record: IntelligenceActionRecord) -> IntelligenceAction:
    return IntelligenceAction(
        action_id=record.id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        objective=record.objective,
        action_type=_enum(ActionType, record.action_type, ActionType.DISCOVER),
        required_capability=_enum(CoverageCapability, record.required_capability, CoverageCapability.ASSET_DISCOVERY),
        tool=record.tool,
        reason=record.reason,
        expected_information_gain=record.expected_information_gain,
        expected_evidence=tuple(record.expected_evidence),
        estimated_cost=record.estimated_cost,
        risk=record.risk,
        scope_status=record.scope_status,
        preconditions=tuple(record.preconditions),
        stop_conditions=tuple(
            _enum(StopCondition, item, item) if isinstance(item, str) else item for item in record.stop_conditions
        ),
        fallback=record.fallback,
        priority=record.priority,
        status=_enum(ActionStatus, record.status, ActionStatus.PROPOSED),
        decision_id=record.decision_id,
        candidates=tuple(record.candidates),
    )


def _decision_to_record(decision: IntelligenceDecision) -> IntelligenceDecisionRecord:
    return IntelligenceDecisionRecord(
        target_id=decision.target_id,
        mission_id=decision.mission_id,
        kind=decision.kind,
        payload=decision.payload,
        rationale=list(decision.rationale),
        evidence=list(decision.evidence),
        alternatives=list(decision.alternatives),
        why_alternatives_rejected=list(decision.why_alternatives_rejected),
        policy_applied=list(decision.policy_applied),
        ai_assisted=decision.ai_assisted,
        ai_overridden=decision.ai_overridden,
    )


def _negative_to_record(negative: NegativeResult) -> NegativeResultRecord:
    return NegativeResultRecord(
        target_id=negative.target_id,
        mission_id=negative.mission_id,
        asset_key=negative.asset_key,
        tested_capability=negative.tested_capability.value,
        tool=negative.tool,
        scope=negative.scope,
        conditions=negative.conditions,
        coverage=negative.coverage,
        result=negative.result,
        confidence=negative.confidence,
        tested_at=negative.tested_at,
    )


def _negative_from_record(record: NegativeResultRecord) -> NegativeResult:
    return NegativeResult(
        result_id=record.id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        tested_capability=_enum(CoverageCapability, record.tested_capability, CoverageCapability.VULNERABILITY_SCANNING),
        tool=record.tool,
        scope=record.scope,
        conditions=dict(record.conditions),
        coverage=record.coverage,
        result=record.result,
        confidence=record.confidence,
        tested_at=record.tested_at,
    )


def _conflict_to_record(conflict: IntelligenceConflict) -> IntelligenceConflictRecord:
    return IntelligenceConflictRecord(
        target_id=conflict.target_id,
        mission_id=conflict.mission_id,
        asset_key=conflict.asset_key,
        capability=conflict.capability.value,
        observations=[dict(o) for o in conflict.observations],
        tools=list(conflict.tools),
        state=conflict.state.value,
        resolution=conflict.resolution,
        detected_at=conflict.detected_at,
        resolved_at=conflict.resolved_at,
    )


def _conflict_from_record(record: IntelligenceConflictRecord) -> IntelligenceConflict:
    return IntelligenceConflict(
        conflict_id=record.id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        capability=_enum(CoverageCapability, record.capability, CoverageCapability.VULNERABILITY_SCANNING),
        observations=tuple(dict(o) for o in record.observations),
        tools=tuple(record.tools),
        state=_enum(ConflictState, record.state, ConflictState.OPEN),
        resolution=record.resolution,
        detected_at=record.detected_at,
        resolved_at=record.resolved_at,
    )


def _score_to_record(target: IntelligenceTarget, score: IntelligenceScore) -> IntelligenceScoreRecord:
    return IntelligenceScoreRecord(
        target_id=target.target_id,
        dimensions=score.dimensions,
        aggregate=score.aggregate,
        weights=score.weights,
        policy_id=score.policy_id,
    )


def _score_from_record(record: IntelligenceScoreRecord) -> IntelligenceScore:
    return IntelligenceScore(
        target_id=record.target_id,
        dimensions={k: float(v) for k, v in (record.dimensions or {}).items()},
        aggregate=record.aggregate,
        weights={k: float(v) for k, v in (record.weights or {}).items()},
        policy_id=record.policy_id,
    )


__all__ = [
    "CoverageCapability",
    "CoverageMatrix",
    "IntelligencePhase",
    "TargetIntelligenceQueryService",
    "TargetIntelligenceService",
]
