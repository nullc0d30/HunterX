# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Intelligence Engine facade.

Sprint 026. The `TargetIntelligenceEngine` is the runtime aggregate of the
Adaptive Target Intelligence layer: it ingests scope-checked observations and
assets, updates the attack-surface graph and coverage matrix, records negative
results and evidence, detects conflicts and changes, maintains target history,
regenerates hypotheses, ranks next best actions and assembles the target
intelligence state snapshot. It is injected with pure domain engines and the
Sprint 025 tool selector so it can be assembled from the platform composition
root or from test doubles.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunterx.domain.target_intelligence.actions import NextActionEngine, RankingWeights, ToolSelectorAdapter
from hunterx.domain.target_intelligence.conflicts import (
    IntelligenceConflictDetector,
    IntelligenceConflictManager,
)
from hunterx.domain.target_intelligence.correlation import IntelligenceCorrelationEngine
from hunterx.domain.target_intelligence.coverage import CoverageEngine
from hunterx.domain.target_intelligence.enums import (
    ChangeKind,
    CoverageCapability,
    IntelligencePhase,
    IntelligenceTargetKind,
    IntelligenceTargetStatus,
    ObservationType,
)
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
from hunterx.domain.target_intelligence.history import TargetChangeDetector, TargetHistory
from hunterx.domain.target_intelligence.hypotheses import HypothesisEngine
from hunterx.domain.target_intelligence.models import (
    CoverageMatrix,
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
from hunterx.domain.target_intelligence.scope import (
    TargetIntelligenceScopeEnforcer,
    TargetIsolationContext,
)
from hunterx.domain.target_intelligence.state import (
    IntelligenceScoreEngine,
    TargetIntelligenceStateAssembler,
)
from hunterx.domain.target_intelligence.stores import (
    AssetIntelligenceStore,
    EvidenceStore,
    InMemoryAssetIntelligenceStore,
    InMemoryEvidenceStore,
    InMemoryObservationStore,
    ObservationStore,
)
from hunterx.domain.target_intelligence.unknowns import UnknownsEngine
from hunterx.domain.topology.enums import EntityKind
from hunterx.domain.topology.keys import entity_key
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Mapping from observation type to the asset entity kind the observation
#: creates or refreshes.
_OBSERVATION_TO_KIND: dict[ObservationType, EntityKind] = {
    ObservationType.ASSET: EntityKind.ASSET,
    ObservationType.HOST: EntityKind.HOSTNAME,
    ObservationType.PORT: EntityKind.PORT,
    ObservationType.SERVICE: EntityKind.SERVICE,
    ObservationType.TECHNOLOGY: EntityKind.TECHNOLOGY,
    ObservationType.URL: EntityKind.URL,
    ObservationType.ENDPOINT: EntityKind.API_ENDPOINT,
    ObservationType.API: EntityKind.API_ENDPOINT,
    ObservationType.GRAPHQL: EntityKind.GRAPHQL_ENDPOINT,
    ObservationType.JAVASCRIPT: EntityKind.JAVASCRIPT,
    ObservationType.CLOUD_RESOURCE: EntityKind.CLOUD_RESOURCE,
    ObservationType.SAAS: EntityKind.SAAS_INTEGRATION,
    ObservationType.CERTIFICATE: EntityKind.CERTIFICATE,
    ObservationType.DNS_RECORD: EntityKind.DNS_RECORD,
    ObservationType.REPOSITORY: EntityKind.REPOSITORY,
    ObservationType.AUTHENTICATION_SURFACE: EntityKind.AUTH_SURFACE,
    ObservationType.AUTHORIZATION_SURFACE: EntityKind.AUTHORIZATION_ENDPOINT,
}


class TargetIntelligenceEngine:
    """Runtime aggregate of the Adaptive Target Intelligence layer.

    Attributes:
        coverage: coverage matrix engine.
        unknowns: unknowns/gap engine.
        hypotheses: hypothesis engine.
        next_action: next-action ranking engine.
        correlator: observation correlation engine.
        conflict_detector: conflict detection engine.
        conflict_manager: conflict lifecycle manager.
        history: target history store.
        change_detector: change detection engine.
        assembler: target state assembler.
        score_engine: intelligence score engine.
        scope: scope/isolation enforcer.
        assets: asset intelligence store.
        observations: observation store.
        evidence: evidence store.
        graph: attack-surface graph (in-memory index).
        targets: registered intelligence targets (in-memory index).

    """

    def __init__(
        self,
        *,
        coverage: CoverageEngine | None = None,
        unknowns: UnknownsEngine | None = None,
        hypotheses: HypothesisEngine | None = None,
        next_action: NextActionEngine | None = None,
        correlator: IntelligenceCorrelationEngine | None = None,
        conflict_detector: IntelligenceConflictDetector | None = None,
        conflict_manager: IntelligenceConflictManager | None = None,
        history: TargetHistory | None = None,
        change_detector: TargetChangeDetector | None = None,
        assembler: TargetIntelligenceStateAssembler | None = None,
        score_engine: IntelligenceScoreEngine | None = None,
        scope: TargetIntelligenceScopeEnforcer | None = None,
        assets: AssetIntelligenceStore | None = None,
        observations: ObservationStore | None = None,
        evidence: EvidenceStore | None = None,
        tool_selector: ToolSelectorAdapter | None = None,
        weights: RankingWeights | dict[str, float] | None = None,
        action_budget: int = 0,
    ) -> None:
        self.coverage = coverage or CoverageEngine()
        self.unknowns = unknowns or UnknownsEngine()
        self.hypotheses = hypotheses or HypothesisEngine()
        self.next_action = next_action or NextActionEngine(weights=weights, tool_selector=tool_selector, action_budget=action_budget)
        self.correlator = correlator or IntelligenceCorrelationEngine()
        self.conflict_detector = conflict_detector or IntelligenceConflictDetector()
        self.conflict_manager = conflict_manager or IntelligenceConflictManager()
        self.history = history or TargetHistory()
        self.change_detector = change_detector or TargetChangeDetector()
        self.assembler = assembler or TargetIntelligenceStateAssembler(coverage=self.coverage)
        self.score_engine = score_engine or IntelligenceScoreEngine(coverage=self.coverage)
        self.scope = scope or TargetIntelligenceScopeEnforcer(TargetIsolationContext())
        self.assets = assets or InMemoryAssetIntelligenceStore()
        self.observations = observations or InMemoryObservationStore()
        self.evidence = evidence or InMemoryEvidenceStore()
        self.graph = AttackSurfaceGraph()
        self._targets: dict[str, IntelligenceTarget] = {}
        self._gaps: dict[str, list[Any]] = {}
        self._hypotheses: dict[str, list[Any]] = {}
        self._negatives: dict[str, list[NegativeResult]] = {}
        self._changes: dict[str, list[IntelligenceChange]] = {}
        self._scores: dict[str, IntelligenceScore] = {}

    # -- target lifecycle ---------------------------------------------------

    def register_target(self, target: IntelligenceTarget) -> IntelligenceTarget:
        """Register (or refresh) an intelligence target after scope validation."""
        self.scope.check_target(target)
        self._targets[target.target_id] = target
        return target

    def get_target(self, target_id: str) -> IntelligenceTarget | None:
        """Return a registered target or ``None``."""
        return self._targets.get(target_id)

    def targets(self) -> list[IntelligenceTarget]:
        """Return all registered targets."""
        return list(self._targets.values())

    # -- ingestion ----------------------------------------------------------

    def ingest_observations(self, target: IntelligenceTarget, observations: Sequence[Observation]) -> list[Observation]:
        """Ingest scope-checked, deduplicated observations.

        Each observation is validated against the isolation context, deduplicated
        by its canonical dedup key, persisted to the observation store, and
        materialized into the attack-surface graph (assets + coverage). Coverage
        is recorded against the observation's asset context so a technology
        observed on a host covers that host's fingerprint cell.
        """
        self.scope.check_target(target)
        accepted: list[Observation] = []
        for observation in observations:
            observation = self.scope.check_observation(observation)
            if self.observations.dedup_key_exists(observation.dedup_key, target_id=target.target_id):
                continue
            stored = self.observations.add(observation)
            accepted.append(stored)
            asset = self._materialize_asset(target, observation)
            updated: IntelligenceAsset | None = None
            if asset is not None:
                updated = self.assets.upsert(asset)
                self.graph.upsert_asset(updated)
            else:
                updated = self._attach_observation_to_asset(target, observation)
            if updated is not None:
                self.coverage.record(
                    target_id=target.target_id,
                    asset_key=updated.key,
                    capability=observation.capability or _capability_for_observation(observation),
                    state="tested",
                    tool=observation.tool,
                    confidence=observation.confidence,
                    evidence_refs=(observation.evidence_ref,) if observation.evidence_ref else (),
                )
        self._refresh_target_stamp(target)
        return accepted

    def ingest_assets(self, target: IntelligenceTarget, assets: Sequence[IntelligenceAsset]) -> list[IntelligenceAsset]:
        """Ingest assets into the graph (scope-checked)."""
        self.scope.check_target(target)
        accepted: list[IntelligenceAsset] = []
        for asset in assets:
            self.scope.check_asset(asset)
            stored = self.assets.upsert(asset)
            self.graph.upsert_asset(stored)
            accepted.append(stored)
        self._refresh_target_stamp(target)
        return accepted

    def ingest_evidence(self, target: IntelligenceTarget, evidence: Sequence[IntelligenceEvidence]) -> list[IntelligenceEvidence]:
        """Store evidence records (scope-checked)."""
        self.scope.check_target(target)
        stored: list[IntelligenceEvidence] = []
        for record in evidence:
            if record.mission_id and target.mission_id and record.mission_id != target.mission_id:
                continue
            stored.append(self.evidence.add(record))
        return stored

    def record_negative(self, target: IntelligenceTarget, negative: NegativeResult) -> NegativeResult:
        """Record a carefully-scoped negative result (scope-checked)."""
        self.scope.check_target(target)
        self._negatives.setdefault(target.target_id, []).append(negative)
        self.coverage.ingest_negative(negative)
        self.history.record(
            target_id=target.target_id,
            mission_id=target.mission_id,
            asset_key=negative.asset_key,
            attribute=negative.tested_capability.value,
            kind=ChangeKind.CORROBORATED,
            new_value=f"negative ({negative.result}) by {negative.tool}",
            source=negative.tool,
            confidence=negative.confidence,
        )
        return negative

    # -- analysis -----------------------------------------------------------

    def detect_conflicts(self, target: IntelligenceTarget) -> list[IntelligenceConflict]:
        """Detect and register conflicts from stored observations."""
        observations = list(self.observations.stream(target_id=target.target_id))
        conflicts = self.conflict_detector.detect(
            observations,
            target_id=target.target_id,
            mission_id=target.mission_id,
        )
        for conflict in conflicts:
            self.conflict_manager.record(conflict)
        return conflicts

    def detect_changes(
        self,
        target: IntelligenceTarget,
        *,
        previous: dict[str, IntelligenceAsset] | None = None,
        source: str = "target-intelligence",
    ) -> list[IntelligenceChange]:
        """Detect changes by diffing the persisted asset snapshot."""
        current = {asset.key: asset for asset in self.assets.list(target_id=target.target_id)}
        previous_map = previous if previous is not None else self._previous_asset_map(target.target_id)
        changes = self.change_detector.detect(
            target_id=target.target_id,
            mission_id=target.mission_id,
            previous=previous_map,
            current=current,
            source=source,
        )
        self._changes.setdefault(target.target_id, []).extend(changes)
        for change in changes:
            self.history.record(
                target_id=target.target_id,
                mission_id=target.mission_id,
                asset_key=change.asset_key,
                attribute=change.kind.value,
                kind=change.kind,
                new_value=_json(change.current),
                previous_value=_json(change.previous),
                source=change.source,
                confidence=change.confidence,
            )
        return changes

    def correlate(self, target: IntelligenceTarget) -> Any:
        """Correlate stored observations for a target."""
        observations = list(self.observations.stream(target_id=target.target_id))
        return self.correlator.correlate(observations)

    def snapshot(self, target: IntelligenceTarget, *, open_hypotheses: Sequence[Any] | None = None) -> TargetIntelligenceState:
        """Assemble the current intelligence state for a target.

        Coverage cells are primed (NOT_ASSESSED) for every testable asset that
        has no explicit cell yet, so the matrix is explicit about what has not
        been tried — missing information is never treated as negative.
        """
        self.coverage.assign_to_assets(
            self.graph.coverage_targets(),
            target_id=target.target_id,
        )
        assets = self.assets.list(target_id=target.target_id)
        matrix = self.coverage.matrix(target.target_id)
        gaps = self._gaps.get(target.target_id, [])
        hypotheses = list(open_hypotheses if open_hypotheses is not None else self._hypotheses.get(target.target_id, []))
        negatives = self._negatives.get(target.target_id, [])
        conflicts = self.conflict_manager.open(target_id=target.target_id)
        history = self.history.for_target(target.target_id, limit=200)
        return self.assembler.assemble(
            target=target,
            assets=assets,
            coverage=matrix,
            gaps=gaps,
            hypotheses=hypotheses,
            negative_results=negatives,
            conflicts=conflicts,
            history=history,
            observation_count=self.observations.count(target_id=target.target_id),
            evidence_count=self.evidence.count(target_id=target.target_id),
            score=self._scores.get(target.target_id),
            mission_id=target.mission_id,
        )

    def score(self, target: IntelligenceTarget, matrix: CoverageMatrix | None = None) -> IntelligenceScore:
        """Compute the explainable intelligence score for a target."""
        matrix = matrix or self.coverage.matrix(target.target_id)
        score = self.score_engine.score(target=target, matrix=matrix)
        self._scores[target.target_id] = score
        return score

    # -- adaptive loop ------------------------------------------------------

    def run_cycle(
        self,
        target: IntelligenceTarget,
        *,
        mission_objective: str = "",
        available_tools: Sequence[str] | None = None,
        safety_ceiling: str = "high_impact",
        authorization_granted: bool = False,
    ) -> tuple[TargetIntelligenceState, list[IntelligenceAction], IntelligenceDecision]:
        """Run one adaptive intelligence cycle.

        The cycle: refresh state → detect conflicts/changes → generate gaps →
        generate/refine hypotheses → score → rank next best actions. The
        returned actions carry stop conditions and explainable rationales.
        """
        self.scope.check_target(target)
        self.detect_conflicts(target)
        self.detect_changes(target)

        state = self.snapshot(target)
        gaps = self.unknowns.analyze(state)
        self._gaps[target.target_id] = gaps

        hypotheses = self.hypotheses.generate(state)
        self._hypotheses[target.target_id] = hypotheses
        state = self.snapshot(target)

        score = self.score(target, state.coverage)
        self._scores[target.target_id] = score
        state = self.snapshot(target)

        actions, decision = self.next_action.rank(
            state,
            mission_objective=mission_objective,
            available_tools=available_tools,
            safety_ceiling=safety_ceiling,
            authorization_granted=authorization_granted,
        )
        return state, actions, decision

    # -- internals ----------------------------------------------------------

    def _materialize_asset(self, target: IntelligenceTarget, observation: Observation) -> IntelligenceAsset | None:
        """Derive an asset node from an observation (or ``None``).

        When the observation carries an explicit ``asset_key`` (the context the
        observation was collected under), that key is authoritative for the
        asset so coverage and graph lookups stay consistent.
        """
        kind = _OBSERVATION_TO_KIND.get(observation.observation_type)
        if kind is None or not observation.value:
            return None
        name = observation.normalized_value or observation.value
        if observation.asset_key and ":" in observation.asset_key:
            key = observation.asset_key
            name = observation.asset_key.split(":", 1)[1] or name
        else:
            key = entity_key(kind.value, name)
        return IntelligenceAsset(
            asset_id=generate_id(),
            target_id=target.target_id,
            mission_id=target.mission_id,
            kind=kind,
            name=name,
            key=key,
            label=name,
            properties={"source": observation.source, "capability": observation.capability},
            confidence=observation.confidence,
            in_scope=True,
            source=observation.tool or observation.source,
            last_seen=observation.timestamp,
            observed_by=(observation.tool,) if observation.tool else (),
        )

    def _attach_observation_to_asset(self, target: IntelligenceTarget, observation: Observation) -> IntelligenceAsset | None:
        """Attach an observation to its referenced asset (e.g. a parameter).

        Parameter observations do not create their own asset node; they enrich
        the endpoint asset they belong to so the hypothesis engine sees the
        parameter surface.
        """
        if observation.observation_type is not ObservationType.PARAMETER:
            return None
        asset = self.assets.get(observation.asset_key)
        if asset is None or not observation.value:
            return None
        import dataclasses

        parameters = list(asset.properties.get("parameters") or ())
        value = observation.normalized_value or observation.value
        if value not in parameters:
            parameters.append(value)
        enriched = dataclasses.replace(
            asset,
            properties={**asset.properties, "parameters": parameters, "capability": observation.capability},
            last_seen=observation.timestamp,
        )
        stored = self.assets.upsert(enriched)
        self.graph.upsert_asset(stored)
        return stored

    def _previous_asset_map(self, target_id: str) -> dict[str, IntelligenceAsset]:
        """Return the previously recorded asset snapshot (empty by default)."""
        return {}

    def _refresh_target_stamp(self, target: IntelligenceTarget) -> None:
        import dataclasses

        refreshed = dataclasses.replace(target, last_seen=utcnow_iso())
        self._targets[target.target_id] = refreshed


def _capability_for_observation(observation: Observation) -> str:
    """Map an observation type to a default coverage capability."""
    return {
        ObservationType.PORT: CoverageCapability.PORT_DISCOVERY.value,
        ObservationType.SERVICE: CoverageCapability.SERVICE_DETECTION.value,
        ObservationType.TECHNOLOGY: CoverageCapability.TECHNOLOGY_FINGERPRINT.value,
        ObservationType.PARAMETER: CoverageCapability.PARAMETER_DISCOVERY.value,
        ObservationType.URL: CoverageCapability.ENDPOINT_ENUMERATION.value,
        ObservationType.VULNERABILITY: CoverageCapability.VULNERABILITY_SCANNING.value,
    }.get(observation.observation_type, CoverageCapability.ASSET_DISCOVERY.value)


def _json(value: object) -> str:
    import json

    if not value:
        return ""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


__all__ = [
    "CoverageMatrix",
    "IntelligenceAction",
    "IntelligenceAsset",
    "IntelligenceChange",
    "IntelligenceConflict",
    "IntelligenceDecision",
    "IntelligenceEvidence",
    "IntelligenceScore",
    "IntelligenceTarget",
    "IntelligenceTargetKind",
    "IntelligenceTargetStatus",
    "IntelligencePhase",
    "NegativeResult",
    "Observation",
    "TargetHistoryEntry",
    "TargetIntelligenceEngine",
    "TargetIntelligenceState",
]
