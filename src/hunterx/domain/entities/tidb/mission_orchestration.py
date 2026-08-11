# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration — Target Intelligence Database entities.

Sprint 032. System-of-record entities for the autonomous mission orchestration
layer: mission runs, phases, actions, decisions, hypotheses, branches,
checkpoints, policies, objectives, coverage, timelines, observations, negative
evidence, baselines, reasoning-trace entries, telemetry and impact analyses.
Each entity mirrors the pure domain model in
``hunterx.domain.mission_orchestration``; the application service maps between
them. Envelope (id, timestamps, versioning, soft-delete) comes from
:class:`TidbEntity`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class MissionOrchestrationRecord(TidbEntity):
    """A persisted orchestrated mission aggregate.

    Attributes:
        mission_id: stable mission identifier (also the Sprint 027 mission id).
        objective: objective name (sprint vocabulary, e.g. ``full_security_assessment``).
        mode: :class:`MissionMode` value.
        state: :class:`MissionState` value.
        strategy: orchestration :class:`StrategyKind` value.
        current_phase: canonical :class:`MissionPhase` value.
        target: primary target identifier.
        tenant: isolation key.
        authorization_context: authorization tier.
        policy: JSON-safe mission policy.
        budget: JSON-safe mission budget snapshot.
        coverage_ratio: current coverage ratio.
        outcome: JSON-safe final outcome (when finalized).

    """

    mission_id: str = ""
    objective: str = "full_security_assessment"
    mode: str = "balanced"
    state: str = "created"
    strategy: str = "adaptive"
    current_phase: str = "target_modeling"
    target: str = ""
    tenant: str = ""
    authorization_context: str = "default"
    policy: dict[str, object] = field(default_factory=dict)
    budget: dict[str, object] = field(default_factory=dict)
    coverage_ratio: float = 0.0
    outcome: dict[str, object] | None = None


@dataclass(slots=True)
class MissionRunRecord(TidbEntity):
    """A persisted mission execution run."""

    run_id: str = ""
    mission_id: str = ""
    status: str = "pending"
    started_at: str = ""
    finished_at: str = ""
    resumed_from_run_id: str = ""
    checkpoint_id: str = ""
    last_action_id: str = ""
    error: str = ""


@dataclass(slots=True)
class MissionPhaseLogRecord(TidbEntity):
    """A persisted mission phase transition (log entry)."""

    phase_id: str = ""
    mission_id: str = ""
    phase: str = ""
    started_at: str = ""
    completed_at: str = ""
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class MissionActionRecord(TidbEntity):
    """A persisted orchestrated mission action (tool execution)."""

    action_id: str = ""
    mission_id: str = ""
    capability: str = ""
    tool_id: str = ""
    tool_version: str = ""
    asset_key: str = ""
    status: str = "proposed"
    started_at: str = ""
    completed_at: str = ""
    result: dict[str, object] = field(default_factory=dict)
    provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class MissionDecisionRecord(TidbEntity):
    """A persisted explainable orchestration decision."""

    decision_id: str = ""
    mission_id: str = ""
    next_action: str = ""
    capability: str = ""
    tool_id: str = ""
    reason: str = ""
    expected_result: str = ""
    priority: float = 0.0
    dependencies: list[str] = field(default_factory=list)
    alternatives: list[list[str]] = field(default_factory=list)
    information_gain: float = 0.0
    factors: dict[str, float] = field(default_factory=dict)
    ai_assisted: bool = False
    latency_ms: int = 0


@dataclass(slots=True)
class MissionHypothesisRecord(TidbEntity):
    """A persisted orchestration hypothesis with evidence-driven state."""

    hypothesis_id: str = ""
    mission_id: str = ""
    statement: str = ""
    category: str = "unknown_behavior"
    state: str = "proposed"
    behavior_class: str = "novel_candidate"
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    tested_actions: list[str] = field(default_factory=list)
    confidence: float = 0.0
    priority: float = 0.5
    validation_strategy: str = ""
    proof_strategy: str = ""
    proposed_by: str = "orchestrator"
    provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class MissionBranchRecord(TidbEntity):
    """A persisted mission branch."""

    branch_id: str = ""
    mission_id: str = ""
    parent_branch_id: str = ""
    hypothesis_id: str = ""
    rationale: str = ""
    state: str = "open"
    actions: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    cost: float = 0.0
    priority: float = 0.5
    outcome: str = ""


@dataclass(slots=True)
class MissionCheckpointRecord(TidbEntity):
    """A persisted resumable mission checkpoint."""

    checkpoint_id: str = ""
    mission_id: str = ""
    label: str = ""
    snapshot: dict[str, object] = field(default_factory=dict)
    created_at_iso: str = ""


@dataclass(slots=True)
class MissionPolicyRecord(TidbEntity):
    """A persisted mission policy."""

    policy_id: str = ""
    mission_id: str = ""
    objective_name: str = "full_security_assessment"
    strategy: str = "adaptive"
    allowed_techniques: list[str] = field(default_factory=list)
    resource_budget: int = 1000
    time_budget_seconds: int = 0
    validation_depth: str = "proof"
    proof_depth: str = "minimal"
    coverage_target: float = 0.7
    stop_conditions: list[str] = field(default_factory=list)
    max_concurrency: int = 4
    rate_limit_per_minute: int = 0


@dataclass(slots=True)
class MissionObjectiveRecord(TidbEntity):
    """A persisted mission objective (current/remaining)."""

    record_id: str = ""
    mission_id: str = ""
    objective: str = ""
    status: str = "remaining"
    completed_at: str = ""


@dataclass(slots=True)
class MissionCoverageRecord(TidbEntity):
    """A persisted mission coverage cell."""

    cell_key: str = ""
    mission_id: str = ""
    asset_key: str = ""
    capability: str = ""
    state: str = "not_assessed"
    tool_id: str = ""
    confidence: float = 0.0
    evidence_refs: list[str] = field(default_factory=list)
    tested_at: str = ""
    notes: str = ""


@dataclass(slots=True)
class MissionTimelineRecord(TidbEntity):
    """A persisted mission timeline/history entry."""

    entry_id: str = ""
    mission_id: str = ""
    event_type: str = ""
    payload: dict[str, object] = field(default_factory=dict)
    occurred_at: str = ""


@dataclass(slots=True)
class MissionObservationRecord(TidbEntity):
    """A persisted normalized mission observation."""

    observation_id: str = ""
    mission_id: str = ""
    action_id: str = ""
    tool_id: str = ""
    tool_version: str = ""
    asset_key: str = ""
    observation_type: str = ""
    content: dict[str, object] = field(default_factory=dict)
    evidence_ref: str = ""
    confidence: float = 0.0
    provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class MissionNegativeRecord(TidbEntity):
    """A persisted bounded negative-evidence record."""

    record_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    capability: str = ""
    kind: str = "tested"
    tool_id: str = ""
    tool_version: str = ""
    input_hash: str = ""
    outcome: str = ""
    conditions: dict[str, object] = field(default_factory=dict)
    notes: str = ""


@dataclass(slots=True)
class MissionBaselineRecord(TidbEntity):
    """A persisted baseline behavior observation."""

    baseline_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    request_fingerprint: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    content_length: int = 0
    body_hash: str = ""
    timing_ms: int = 0
    parameters: dict[str, object] = field(default_factory=dict)
    provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class MissionReasoningRecord(TidbEntity):
    """A persisted structured reasoning-trace entry."""

    entry_id: str = ""
    mission_id: str = ""
    kind: str = "observation"
    node_id: str = ""
    content: dict[str, object] = field(default_factory=dict)
    parent_entry_id: str = ""
    occurred_at: str = ""


@dataclass(slots=True)
class MissionTelemetryRecord(TidbEntity):
    """A persisted mission telemetry snapshot."""

    snapshot_id: str = ""
    mission_id: str = ""
    snapshot: dict[str, object] = field(default_factory=dict)
    recorded_at: str = ""


@dataclass(slots=True)
class MissionImpactRecord(TidbEntity):
    """A persisted impact analysis for a validated finding."""

    impact_id: str = ""
    mission_id: str = ""
    finding_id: str = ""
    impact: dict[str, object] = field(default_factory=dict)
    analyzed_at: str = ""
