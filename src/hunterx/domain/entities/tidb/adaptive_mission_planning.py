# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Mission & Attack-Path Planning — Target Intelligence Database entities.

Sprint 027. System-of-record entities for the adaptive mission planning
engine: missions, action nodes, dynamic dependencies, conditional branches,
plan versions, plan deltas, decisions, attack paths, gaps, checkpoints,
failures, tool fallbacks and tool selections. Each entity mirrors the pure
domain model in ``hunterx.domain.adaptive_mission_planning``; the application
service maps between them. Envelope (id, timestamps, versioning, soft-delete)
comes from :class:`TidbEntity`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class AdaptiveMissionRecord(TidbEntity):
    """A persisted adaptive mission aggregate.

    Attributes:
        mission_id: stable mission identifier.
        objective: :class:`MissionObjective` value.
        mode: :class:`MissionMode` value.
        state: :class:`MissionState` value.
        plan_version: current plan version.
        progress: completion progress in ``[0, 100]``.
        authorization_context: authorization tier.
        safety_ceiling: safety ceiling.
        tenant: isolation key.
        target: primary target identifier.

    """

    mission_id: str = ""
    objective: str = "attack_surface_discovery"
    mode: str = "balanced"
    state: str = "created"
    plan_version: int = 1
    progress: float = 0.0
    authorization_context: str = "default"
    safety_ceiling: str = "low_impact_active"
    tenant: str = ""
    target: str = ""


@dataclass(slots=True)
class AdaptiveActionNodeRecord(TidbEntity):
    """A persisted action node in a mission execution graph.

    Attributes:
        action_id: stable action identifier.
        mission_id: owning mission.
        action_type: :class:`ActionType` value.
        asset: asset key the action applies to.
        capability: capability name required.
        selected_tool: currently selected tool id.
        tool_candidates: ordered candidate tool ids.
        hypothesis_id: hypothesis the action tests.
        expected_information_gain / expected_proof_value: estimates.
        risk / cost: estimates.
        timeout_seconds: execution timeout.
        validation_level: :class:`ValidationLevel` value.
        status: :class:`ActionStatus` value.
        priority: scheduling priority.
        depends_on: ids of actions that must finish first.
        provenance: JSON-safe provenance map.

    """

    action_id: str = ""
    mission_id: str = ""
    action_type: str = "discover_endpoints"
    asset: str = ""
    capability: str = ""
    selected_tool: str = ""
    tool_candidates: list[str] = field(default_factory=list)
    hypothesis_id: str = ""
    expected_information_gain: float = 0.0
    expected_proof_value: float = 0.0
    risk: float = 0.0
    cost: float = 0.0
    timeout_seconds: int = 60
    validation_level: str = "discovery"
    status: str = "proposed"
    priority: float = 100.0
    depends_on: list[str] = field(default_factory=list)
    provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AdaptiveDependencyRecord(TidbEntity):
    """A persisted dynamic dependency between action nodes."""

    dependency_id: str = ""
    mission_id: str = ""
    source_action_id: str = ""
    target_action_id: str = ""
    kind: str = "depends_on"
    rationale: str = ""


@dataclass(slots=True)
class AdaptiveBranchRecord(TidbEntity):
    """A persisted conditional branch construct."""

    branch_id: str = ""
    mission_id: str = ""
    kind: str = "if"
    condition: str = ""
    then_action_ids: list[str] = field(default_factory=list)
    else_action_ids: list[str] = field(default_factory=list)
    goto_action_id: str = ""
    wait_for_evidence: str = ""
    rationale: str = ""


@dataclass(slots=True)
class AdaptivePlanVersionRecord(TidbEntity):
    """A persisted plan version (replayable planning history)."""

    version_id: str = ""
    mission_id: str = ""
    plan_version: int = 1
    parent_version: int = 0
    reason: str = ""
    trigger: str = ""
    changed_nodes: list[str] = field(default_factory=list)
    changed_dependencies: list[str] = field(default_factory=list)
    created_by: str = "planner"
    decision_provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AdaptivePlanDeltaRecord(TidbEntity):
    """A persisted plan delta produced by replanning."""

    delta_id: str = ""
    mission_id: str = ""
    plan_version: int = 1
    parent_version: int = 0
    trigger: str = ""
    reason: str = ""
    changes: list[dict[str, object]] = field(default_factory=list)
    decision_provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AdaptiveDecisionRecord(TidbEntity):
    """A persisted explainable planning decision."""

    decision_id: str = ""
    mission_id: str = ""
    action_id: str = ""
    tool_id: str = ""
    why_this_action: str = ""
    why_now: str = ""
    why_this_tool: str = ""
    information_provided: str = ""
    hypothesis_tested: str = ""
    evidence_expected: str = ""
    proof_enabled: str = ""
    alternatives: list[list[str]] = field(default_factory=list)
    decision_provenance: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AdaptiveAttackPathRecord(TidbEntity):
    """A persisted attack path (intelligence, never directly executed)."""

    path_id: str = ""
    mission_id: str = ""
    objective: str = "attack_surface_discovery"
    state: str = "hypothetical"
    score: float = 0.0
    scores: dict[str, float] = field(default_factory=dict)
    steps: list[dict[str, object]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AdaptiveGapRecord(TidbEntity):
    """A persisted evidence or proof gap."""

    gap_id: str = ""
    mission_id: str = ""
    finding_id: str = ""
    kind: str = "evidence_gap"
    asset_key: str = ""
    required_evidence: list[str] = field(default_factory=list)
    minimum_action: str = ""
    priority: float = 0.0


@dataclass(slots=True)
class AdaptivePlanCheckpointRecord(TidbEntity):
    """A persisted resumable mission checkpoint."""

    checkpoint_id: str = ""
    mission_id: str = ""
    plan_version: int = 1
    mission_state: str = "created"
    completed_actions: list[str] = field(default_factory=list)
    pending_actions: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    proof_states: dict[str, object] = field(default_factory=dict)
    tool_state: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AdaptiveFailureRecord(TidbEntity):
    """A persisted classified action failure."""

    failure_id: str = ""
    mission_id: str = ""
    action_id: str = ""
    tool_id: str = ""
    failure_class: str = "tool_error"
    management: str = "retry"
    error: str = ""
    retries: int = 0


@dataclass(slots=True)
class AdaptiveToolFallbackRecord(TidbEntity):
    """A persisted capability-equivalent tool fallback."""

    fallback_id: str = ""
    mission_id: str = ""
    action_id: str = ""
    primary_tool: str = ""
    fallback_tool: str = ""
    capability: str = ""
    reason: str = ""


@dataclass(slots=True)
class AdaptiveToolSelectionRecord(TidbEntity):
    """A persisted tool selection for an action."""

    selection_id: str = ""
    mission_id: str = ""
    action_id: str = ""
    capability: str = ""
    tool_id: str = ""
    alternatives: list[str] = field(default_factory=list)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    expected_evidence: list[str] = field(default_factory=list)
    expected_proof_value: float = 0.0
    risk: float = 0.0
    cost: float = 0.0
