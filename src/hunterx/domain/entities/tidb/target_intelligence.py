# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Target Intelligence TIDB entities.

Sprint 026. System-of-record entities for the Target Intelligence layer. The
layer persists normalized entities (never a JSON dump of the whole graph) so
references, relationships, provenance, history and indexes stay queryable.

Each entity mirrors the pure domain model in
``hunterx.domain.target_intelligence``; the application service maps between
them. Envelope (id, timestamps, versioning, soft-delete) comes from
:class:`TidbEntity`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class IntelligenceTargetRecord(TidbEntity):
    """A canonical intelligence target.

    Attributes:
        target_id: stable target identifier (scoping key for all records).
        mission_id: owning mission.
        scope: scope identifier.
        identity: human label.
        classification: target classification.
        criticality: business criticality.
        kind: target kind (``domain``, ``ip``, ``cloud_account``, ...).
        value: canonical target value.
        status: :class:`IntelligenceTargetStatus` value.
        confidence: aggregate confidence in ``[0, 1]``.
        phase: current :class:`IntelligencePhase` value.
        intelligence_state: per-category state map (JSON).
        coverage_state: per-dimension coverage summary (JSON).
        tenant: isolation key.

    """

    target_id: str = ""
    mission_id: str = ""
    scope: str = ""
    identity: str = ""
    classification: str = ""
    criticality: str = "medium"
    kind: str = "domain"
    value: str = ""
    status: str = "active"
    confidence: float = 1.0
    phase: str = "discovery"
    intelligence_state: dict[str, object] = field(default_factory=dict)
    coverage_state: dict[str, float] = field(default_factory=dict)
    tenant: str = ""


@dataclass(slots=True)
class IntelligenceAssetRecord(TidbEntity):
    """A discovered asset (graph node).

    Attributes:
        asset_id: stable asset identifier.
        target_id: owning target.
        mission_id: owning mission.
        kind: :class:`EntityKind` value.
        name: canonical asset value.
        asset_key: canonical node key (``kind:name``).
        label: human label.
        properties: free-form attributes (JSON).
        confidence: asset confidence.
        in_scope: whether the asset is authorized.
        source: provenance label.
        parent_key: canonical key of the parent asset.
        observed_by: tools that observed the asset (JSON list).

    """

    asset_id: str = ""
    target_id: str = ""
    mission_id: str = ""
    kind: str = "asset"
    name: str = ""
    asset_key: str = ""
    label: str = ""
    properties: dict[str, object] = field(default_factory=dict)
    confidence: float = 1.0
    in_scope: bool = True
    source: str = ""
    parent_key: str = ""
    observed_by: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ObservationRecord(TidbEntity):
    """An immutable intelligence observation.

    Attributes:
        observation_id: stable observation identifier.
        target_id: owning target.
        mission_id: owning mission.
        tool: producing tool.
        tool_version: producing tool version.
        capability: canonical capability id.
        timestamp: UTC ISO-8601 observation stamp.
        observation_type: :class:`ObservationType` value.
        value: observed value.
        normalized_value: canonical normalized value.
        confidence: observation confidence.
        source: source label.
        provenance: provenance map (JSON).
        scope: scope the observation was collected under.
        raw_artifact_ref: raw output reference.
        evidence_ref: evidence reference.
        expires_at: UTC ISO-8601 expiry.
        asset_key: related asset key.
        dedup_key: stable deduplication key.
        supersedes: corrected observation id.

    """

    observation_id: str = ""
    target_id: str = ""
    mission_id: str = ""
    tool: str = ""
    tool_version: str = ""
    capability: str = ""
    timestamp: str = ""
    observation_type: str = "other"
    value: str = ""
    normalized_value: str = ""
    confidence: float = 1.0
    source: str = ""
    provenance: dict[str, str] = field(default_factory=dict)
    scope: str = ""
    raw_artifact_ref: str = ""
    evidence_ref: str = ""
    expires_at: str | None = None
    asset_key: str = ""
    dedup_key: str = ""
    supersedes: str = ""


@dataclass(slots=True)
class IntelligenceEvidenceRecord(TidbEntity):
    """Evidence record (WHAT/WHERE/WHEN/HOW/SOURCE/WHY_TRUST/REPRODUCIBILITY).

    Attributes:
        evidence_id: stable evidence identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        what: what was observed.
        where: where it was observed.
        when: when it was observed.
        how: how it was observed.
        source: producing tool/component.
        why_trust: trust explanation.
        reproducibility: reproducibility label.
        tool / tool_version: producing tool and version.
        command_configuration: structured command/configuration (JSON).
        raw_artifact_ref: raw artifact reference.
        parser_version / normalizer_version: parsing pipeline versions.
        confidence: evidence confidence.

    """

    evidence_id: str = ""
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    what: str = ""
    where: str = ""
    when: str = ""
    how: str = ""
    source: str = ""
    why_trust: str = ""
    reproducibility: str = "not_assessed"
    tool: str = ""
    tool_version: str = ""
    command_configuration: dict[str, object] = field(default_factory=dict)
    raw_artifact_ref: str = ""
    parser_version: str = ""
    normalizer_version: str = ""
    confidence: float = 1.0


@dataclass(slots=True)
class TargetHistoryRecord(TidbEntity):
    """A point-in-time target history fact.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        field: the field that changed.
        kind: :class:`ChangeKind` value.
        previous_value: prior canonical value.
        new_value: new canonical value.
        source: provenance label.
        confidence: confidence of the new value.
        changed_at: UTC ISO-8601 change stamp.
        correlation_id: producing run correlation id.

    """

    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    field: str = ""
    kind: str = "new"
    previous_value: str = ""
    new_value: str = ""
    source: str = ""
    confidence: float = 1.0
    changed_at: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class IntelligenceChangeRecord(TidbEntity):
    """A detected change in the target's intelligence state.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        kind: :class:`ChangeKind` value.
        previous: prior state map (JSON).
        current: new state map (JSON).
        source: provenance label.
        confidence: confidence of the change.
        detected_at: UTC ISO-8601 detection stamp.

    """

    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    kind: str = "new"
    previous: dict[str, object] = field(default_factory=dict)
    current: dict[str, object] = field(default_factory=dict)
    source: str = ""
    confidence: float = 1.0
    detected_at: str = ""


@dataclass(slots=True)
class CoverageRecord(TidbEntity):
    """A single (asset, capability) coverage cell.

    Attributes:
        target_id: owning target.
        asset_key: canonical asset key.
        capability: :class:`CoverageCapability` value.
        state: :class:`CoverageState` value.
        tool: tool that last exercised the capability.
        confidence: confidence of the recorded state.
        tested_at: UTC ISO-8601 test stamp.
        evidence_refs: evidence references (JSON list).
        notes: free-form notes.

    """

    target_id: str = ""
    asset_key: str = ""
    capability: str = ""
    state: str = "not_assessed"
    tool: str = ""
    confidence: float = 0.0
    tested_at: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass(slots=True)
class InformationGapRecord(TidbEntity):
    """A concrete information gap.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        category: :class:`InformationGapCategory` value.
        question: the concrete question.
        importance: importance in ``[0, 1]``.
        confidence: confidence the gap is real.
        required_capability: :class:`CoverageCapability` value.
        candidate_tools: candidate tool ids (JSON list).
        estimated_cost: estimated execution cost.
        risk: risk label.
        blocking: whether the gap blocks dependent analysis.

    """

    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    category: str = "asset_discovery"
    question: str = ""
    importance: float = 0.5
    confidence: float = 0.5
    required_capability: str = "asset_discovery"
    candidate_tools: list[str] = field(default_factory=list)
    estimated_cost: float = 0.0
    risk: str = "passive"
    blocking: bool = False


@dataclass(slots=True)
class HypothesisRecord(TidbEntity):
    """A hypothesis to validate.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        category: :class:`HypothesisType` value.
        statement: the conjecture.
        supporting_observations: supporting observation ids (JSON list).
        contradicting_observations: contradicting observation ids (JSON list).
        required_evidence: evidence kinds required (JSON list).
        validation_strategy: validation approach.
        proof_strategy: proof strategy id.
        confidence: confidence in ``[0, 1]``.
        priority: priority in ``[0, 1]``.
        status: :class:`HypothesisStatus` value.

    """

    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    category: str = "unknown_behavior"
    statement: str = ""
    supporting_observations: list[str] = field(default_factory=list)
    contradicting_observations: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    validation_strategy: str = ""
    proof_strategy: str = ""
    confidence: float = 0.0
    priority: float = 0.0
    status: str = "proposed"


@dataclass(slots=True)
class IntelligenceActionRecord(TidbEntity):
    """A proposed next action.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        objective: what the action accomplishes.
        action_type: :class:`ActionType` value.
        required_capability: :class:`CoverageCapability` value.
        tool: selected tool id.
        reason: human-readable justification.
        expected_information_gain: expected gain in ``[0, 1]``.
        expected_evidence: evidence kinds (JSON list).
        estimated_cost: estimated cost.
        risk: risk label.
        scope_status: scope status.
        preconditions: preconditions (JSON list).
        stop_conditions: :class:`StopCondition` values (JSON list).
        fallback: fallback action.
        priority: ranking priority in ``[0, 1]``.
        status: :class:`ActionStatus` value.
        decision_id: producing decision id.
        candidates: alternative tool ids (JSON list).

    """

    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    objective: str = ""
    action_type: str = "discover"
    required_capability: str = "asset_discovery"
    tool: str = ""
    reason: str = ""
    expected_information_gain: float = 0.0
    expected_evidence: list[str] = field(default_factory=list)
    estimated_cost: float = 0.0
    risk: str = "passive"
    scope_status: str = "in_scope"
    preconditions: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    fallback: str = ""
    priority: float = 0.0
    status: str = "proposed"
    decision_id: str = ""
    candidates: list[str] = field(default_factory=list)


@dataclass(slots=True)
class IntelligenceDecisionRecord(TidbEntity):
    """An explainable adaptive decision.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        kind: decision kind.
        payload: decision payload (JSON).
        rationale: ordered reasons (JSON list).
        evidence: evidence references (JSON list).
        alternatives: alternatives considered (JSON list).
        why_alternatives_rejected: rejection reasons (JSON list).
        policy_applied: policy ids applied (JSON list).
        ai_assisted: whether AI contributed (advisory only).
        ai_overridden: whether AI was overridden by policy.

    """

    target_id: str = ""
    mission_id: str = ""
    kind: str = "next-action"
    payload: dict[str, object] = field(default_factory=dict)
    rationale: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)
    why_alternatives_rejected: list[str] = field(default_factory=list)
    policy_applied: list[str] = field(default_factory=list)
    ai_assisted: bool = False
    ai_overridden: bool = False


@dataclass(slots=True)
class NegativeResultRecord(TidbEntity):
    """A carefully-scoped negative result.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        tested_capability: :class:`CoverageCapability` value.
        tool: tool that produced the negative result.
        scope: scope under which the test ran.
        conditions: recorded test conditions (JSON).
        coverage: what the test covered.
        result: ``no_evidence`` or ``not_vulnerable`` (scoped).
        confidence: confidence in ``[0, 1]``.
        tested_at: UTC ISO-8601 test stamp.

    """

    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    tested_capability: str = "vulnerability_scanning"
    tool: str = ""
    scope: str = ""
    conditions: dict[str, object] = field(default_factory=dict)
    coverage: str = ""
    result: str = "no_evidence"
    confidence: float = 0.5
    tested_at: str = ""


@dataclass(slots=True)
class IntelligenceConflictRecord(TidbEntity):
    """A preserved contradiction between observations/tools.

    Attributes:
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        capability: capability the conflict concerns.
        observations: disagreeing observations (JSON list).
        tools: tools that disagree (JSON list).
        state: :class:`ConflictState` value.
        resolution: resolution note.
        detected_at: UTC ISO-8601 detection stamp.
        resolved_at: UTC ISO-8601 resolution stamp.

    """

    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    capability: str = "vulnerability_scanning"
    observations: list[dict[str, object]] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    state: str = "open"
    resolution: str = ""
    detected_at: str = ""
    resolved_at: str | None = None


@dataclass(slots=True)
class IntelligenceScoreRecord(TidbEntity):
    """An explainable multi-dimension intelligence score.

    Attributes:
        target_id: owning target.
        dimensions: dimension → score (JSON).
        aggregate: overall score in ``[0, 1]``.
        weights: dimension → weight (JSON).
        policy_id: weight/ranking policy id applied.

    """

    target_id: str = ""
    dimensions: dict[str, float] = field(default_factory=dict)
    aggregate: float = 0.0
    weights: dict[str, float] = field(default_factory=dict)
    policy_id: str = "target-intelligence/ranking/1.0.0"
