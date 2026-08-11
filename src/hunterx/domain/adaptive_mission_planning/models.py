# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Mission & Attack-Path Planning — pure data contracts.

Sprint 027. Canonical immutable (mostly frozen) dataclasses describing the
mission objective, constraints, action nodes, dynamic dependencies,
conditional branches, plan versions, plan deltas, decision records, attack
paths, evidence/proof gaps, checkpoints and tool selections. The engines in
``hunterx.engines.adaptive_mission_planning`` drive these models; no tool is
executed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    ActionType,
    AttackPathState,
    AttackPathStepKind,
    BranchKind,
    DependencyKind,
    EvidenceGapKind,
    FailureClass,
    FailureManagement,
    MissionObjective,
    MissionState,
    PlanDeltaKind,
    ReplanTrigger,
    ValidationLevel,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class MissionObjectiveSpec:
    """Definition of a mission objective.

    Attributes:
        objective: the canonical objective.
        coverage_priorities: ordered coverage capability names to prioritize.
        allowed_capabilities: capability whitelist (empty = objective default).
        validation_depth: deepest :class:`ValidationLevel` permitted.
        proof_required: whether proof is a completion requirement.
        risk_tolerance: relative risk tolerance in ``[0, 1]``.
        completion_criteria: human/machine-readable completion rules.
        description: human description of the objective.

    """

    objective: MissionObjective
    coverage_priorities: tuple[str, ...] = ()
    allowed_capabilities: tuple[str, ...] = ()
    validation_depth: ValidationLevel = ValidationLevel.VALIDATION
    proof_required: bool = False
    risk_tolerance: float = 0.5
    completion_criteria: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True, slots=True)
class MissionConstraints:
    """Constraints a planner must never violate.

    Scope and authorization are immutable: no planner, AI proposal or tool
    output may ever expand scope or override authorization.

    Attributes:
        scope: authorized scope definition (identifier or policy name).
        authorization_context: authorization/policy context identifier.
        included_targets: authorized target identifiers.
        excluded_assets: asset keys that must never be touched.
        excluded_capabilities: capability names that are forbidden.
        time_budget_seconds: mission wall-clock budget.
        execution_budget_seconds: aggregate execution budget.
        max_concurrency: maximum parallel actions.
        rate_limit_per_minute: per-target rate limit.
        risk_threshold: maximum acceptable action risk in ``[0, 1]``.
        proof_policy: proof policy identifier (Sprint 021/022).
        credential_policy: credential policy identifier.
        network_policy: network egress policy identifier.
        data_retention_policy: data retention policy identifier.
        tenant: isolation key.

    """

    scope: str = ""
    authorization_context: str = "default"
    included_targets: tuple[str, ...] = ()
    excluded_assets: tuple[str, ...] = ()
    excluded_capabilities: tuple[str, ...] = ()
    time_budget_seconds: int = 0
    execution_budget_seconds: int = 0
    max_concurrency: int = 4
    rate_limit_per_minute: int = 60
    risk_threshold: float = 0.8
    proof_policy: str = "proof-policy/1.0.0"
    credential_policy: str = "credential-policy/1.0.0"
    network_policy: str = "network-policy/1.0.0"
    data_retention_policy: str = "data-retention/1.0.0"
    tenant: str = ""

    def allows_asset(self, asset_key: str) -> bool:
        """Return ``True`` when ``asset_key`` is not excluded."""
        return asset_key not in self.excluded_assets

    def allows_capability(self, capability: str) -> bool:
        """Return ``True`` when ``capability`` is not excluded."""
        return capability not in self.excluded_capabilities

    def allows_target(self, target: str) -> bool:
        """Return ``True`` when ``target`` is authorized."""
        if not self.included_targets:
            return True
        return target in self.included_targets


@dataclass(frozen=True, slots=True)
class DynamicDependency:
    """A typed dependency between action nodes.

    Attributes:
        dependency_id: stable dependency identifier.
        source_action_id: the node that is the source of the relation.
        target_action_id: the node affected by the relation.
        kind: :class:`DependencyKind`.
        rationale: why the dependency exists.

    """

    dependency_id: str
    source_action_id: str
    target_action_id: str
    kind: DependencyKind = DependencyKind.DEPENDS_ON
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "dependency_id": self.dependency_id,
            "source_action_id": self.source_action_id,
            "target_action_id": self.target_action_id,
            "kind": self.kind.value,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class ConditionalBranch:
    """A conditional branch construct in the execution graph.

    Attributes:
        branch_id: stable branch identifier.
        kind: :class:`BranchKind`.
        condition: expression evaluated against evidence (empty = unconditional).
        then_action_ids: actions to schedule when the condition holds.
        else_action_ids: actions to schedule when it does not hold.
        goto_action_id: target for GOTO/REPLAN-style constructs.
        wait_for_evidence: evidence requirement for WAIT_FOR_EVIDENCE.
        rationale: why this branch exists.

    """

    branch_id: str
    kind: BranchKind
    condition: str = ""
    then_action_ids: tuple[str, ...] = ()
    else_action_ids: tuple[str, ...] = ()
    goto_action_id: str = ""
    wait_for_evidence: str = ""
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "branch_id": self.branch_id,
            "kind": self.kind.value,
            "condition": self.condition,
            "then_action_ids": list(self.then_action_ids),
            "else_action_ids": list(self.else_action_ids),
            "goto_action_id": self.goto_action_id,
            "wait_for_evidence": self.wait_for_evidence,
            "rationale": self.rationale,
        }


@dataclass(slots=True)
class ActionNode:
    """A single planned action in the mission execution graph.

    A node represents an *action* — not simply a tool invocation. It carries
    the preconditions, expected observations, information gain, evidence and
    proof value, risk, cost and the candidate tool set. ``status`` is runtime
    mutable; all other fields are treated as immutable after scheduling.

    Attributes:
        action_id: stable action identifier.
        mission_id: owning mission.
        objective: mission objective at scheduling time.
        action_type: canonical :class:`ActionType`.
        asset: asset key (or target key) the action applies to.
        capability: capability name required to satisfy the action.
        tool_candidate_set: ordered candidate tool ids.
        selected_tool: currently selected tool id.
        preconditions: precondition expressions.
        depends_on: ids of actions that must finish first.
        expected_observations: observations the action should produce.
        expected_information_gain: estimated information gain in ``[0, 1]``.
        expected_evidence: evidence the action is expected to produce.
        expected_proof_value: proof value estimate in ``[0, 1]``.
        hypothesis_id: hypothesis this action tests (empty = none).
        risk: execution risk estimate in ``[0, 1]``.
        cost: execution cost estimate in ``[0, 1]``.
        timeout_seconds: execution timeout.
        retry_policy: retry policy name.
        stop_conditions: stop-condition names.
        success_conditions: success-condition names.
        failure_conditions: failure-condition names.
        scope_requirements: scope identifiers required.
        authorization_requirements: authorization identifiers required.
        validation_level: safe-validation level of the action.
        status: runtime :class:`ActionStatus`.
        provenance: JSON-safe provenance map.
        priority: scheduling priority (lower = sooner).
        created_at / updated_at: timestamps.

    """

    action_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    objective: MissionObjective = MissionObjective.ATTACK_SURFACE_DISCOVERY
    action_type: ActionType = ActionType.DISCOVER_ENDPOINTS
    asset: str = ""
    capability: str = ""
    tool_candidate_set: tuple[str, ...] = ()
    selected_tool: str = ""
    preconditions: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    expected_observations: tuple[str, ...] = ()
    expected_information_gain: float = 0.0
    expected_evidence: tuple[str, ...] = ()
    expected_proof_value: float = 0.0
    hypothesis_id: str = ""
    risk: float = 0.0
    cost: float = 0.0
    timeout_seconds: int = 60
    retry_policy: str = "retry-once"
    stop_conditions: tuple[str, ...] = ()
    success_conditions: tuple[str, ...] = ()
    failure_conditions: tuple[str, ...] = ()
    scope_requirements: tuple[str, ...] = ()
    authorization_requirements: tuple[str, ...] = ()
    validation_level: ValidationLevel = ValidationLevel.DISCOVERY
    status: ActionStatus = ActionStatus.PROPOSED
    provenance: dict[str, Any] = field(default_factory=dict)
    priority: float = 100.0
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        if not isinstance(self.objective, MissionObjective):
            object.__setattr__(self, "objective", MissionObjective(self.objective))
        if not isinstance(self.action_type, ActionType):
            object.__setattr__(self, "action_type", ActionType(self.action_type))
        if not isinstance(self.validation_level, ValidationLevel):
            object.__setattr__(self, "validation_level", ValidationLevel(self.validation_level))
        if not isinstance(self.status, ActionStatus):
            object.__setattr__(self, "status", ActionStatus(self.status))

    def touch(self) -> None:
        """Refresh the updated timestamp."""
        self.updated_at = utcnow_iso()

    def mark(self, status: ActionStatus) -> None:
        """Transition this node's runtime status."""
        self.status = status
        self.touch()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "action_id": self.action_id,
            "mission_id": self.mission_id,
            "objective": self.objective.value,
            "action_type": self.action_type.value,
            "asset": self.asset,
            "capability": self.capability,
            "tool_candidate_set": list(self.tool_candidate_set),
            "selected_tool": self.selected_tool,
            "preconditions": list(self.preconditions),
            "depends_on": list(self.depends_on),
            "expected_observations": list(self.expected_observations),
            "expected_information_gain": self.expected_information_gain,
            "expected_evidence": list(self.expected_evidence),
            "expected_proof_value": self.expected_proof_value,
            "hypothesis_id": self.hypothesis_id,
            "risk": self.risk,
            "cost": self.cost,
            "timeout_seconds": self.timeout_seconds,
            "retry_policy": self.retry_policy,
            "stop_conditions": list(self.stop_conditions),
            "success_conditions": list(self.success_conditions),
            "failure_conditions": list(self.failure_conditions),
            "scope_requirements": list(self.scope_requirements),
            "authorization_requirements": list(self.authorization_requirements),
            "validation_level": self.validation_level.value,
            "status": self.status.value,
            "priority": self.priority,
            "provenance": self.provenance,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class ActionProposal:
    """A candidate action proposed by the decision engine (pre-approval).

    Attributes:
        proposal_id: stable proposal identifier.
        action: the proposed :class:`ActionNode`.
        score: ranking score.
        factors: explainable factor breakdown (factor → score).
        rationale: why this action and why now.
        alternatives: rejected alternative actions with reasons.
        ai_assisted: whether AI proposed or influenced the proposal.
        ai_overridden: whether policy overrode an AI suggestion.
        policy_applied: policy identifier applied.

    """

    proposal_id: str = field(default_factory=generate_id)
    action: ActionNode = field(default_factory=ActionNode)
    score: float = 0.0
    factors: dict[str, float] = field(default_factory=dict)
    rationale: str = ""
    alternatives: tuple[tuple[str, str], ...] = ()
    ai_assisted: bool = False
    ai_overridden: bool = False
    policy_applied: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "proposal_id": self.proposal_id,
            "action": self.action.to_dict(),
            "score": self.score,
            "factors": self.factors,
            "rationale": self.rationale,
            "alternatives": [list(item) for item in self.alternatives],
            "ai_assisted": self.ai_assisted,
            "ai_overridden": self.ai_overridden,
            "policy_applied": self.policy_applied,
        }


@dataclass(frozen=True, slots=True)
class PlanVersion:
    """A versioned snapshot of a mission plan.

    Attributes:
        plan_version: monotonic version number.
        parent_version: the version this revision was derived from (``0`` = root).
        reason: why this revision exists.
        trigger: :class:`ReplanTrigger` that produced it.
        changed_nodes: ids of action nodes changed by the revision.
        changed_dependencies: ids of dependencies changed by the revision.
        created_at: creation timestamp.
        created_by: originator label.
        decision_provenance: JSON-safe provenance of the revision decision.

    """

    plan_version: int = 1
    parent_version: int = 0
    reason: str = ""
    trigger: ReplanTrigger | None = None
    changed_nodes: tuple[str, ...] = ()
    changed_dependencies: tuple[str, ...] = ()
    created_at: str = field(default_factory=utcnow_iso)
    created_by: str = "planner"
    decision_provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "plan_version": self.plan_version,
            "parent_version": self.parent_version,
            "reason": self.reason,
            "trigger": self.trigger.value if self.trigger else None,
            "changed_nodes": list(self.changed_nodes),
            "changed_dependencies": list(self.changed_dependencies),
            "created_at": self.created_at,
            "created_by": self.created_by,
            "decision_provenance": self.decision_provenance,
        }


@dataclass(frozen=True, slots=True)
class PlanDeltaChange:
    """A single mutation inside a plan delta."""

    kind: PlanDeltaKind
    action_id: str = ""
    node: ActionNode | None = None
    dependency: DynamicDependency | None = None
    branch: ConditionalBranch | None = None
    tool_id: str = ""
    priority: float = 0.0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "kind": self.kind.value,
            "action_id": self.action_id,
            "node": self.node.to_dict() if self.node else None,
            "dependency": self.dependency.to_dict() if self.dependency else None,
            "branch": self.branch.to_dict() if self.branch else None,
            "tool_id": self.tool_id,
            "priority": self.priority,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class PlanDelta:
    """The result of a replanning pass.

    Replanning produces a delta — the full mission is never rebuilt
    unnecessarily.

    Attributes:
        delta_id: stable delta identifier.
        mission_id: owning mission.
        plan_version: version the delta produces.
        parent_version: version the delta revises.
        changes: the list of mutations.
        trigger: :class:`ReplanTrigger` that caused the replan.
        reason: human-readable reason.
        decision_provenance: JSON-safe provenance.

    """

    delta_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    plan_version: int = 1
    parent_version: int = 0
    changes: tuple[PlanDeltaChange, ...] = ()
    trigger: ReplanTrigger | None = None
    reason: str = ""
    decision_provenance: dict[str, Any] = field(default_factory=dict)

    def is_empty(self) -> bool:
        """Return ``True`` when the delta carries no changes."""
        return not self.changes

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "delta_id": self.delta_id,
            "mission_id": self.mission_id,
            "plan_version": self.plan_version,
            "parent_version": self.parent_version,
            "changes": [change.to_dict() for change in self.changes],
            "trigger": self.trigger.value if self.trigger else None,
            "reason": self.reason,
            "decision_provenance": self.decision_provenance,
        }


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """An explainable planning decision (why this action, why now, why this tool)."""

    decision_id: str = field(default_factory=generate_id)
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
    alternatives: tuple[tuple[str, str], ...] = ()
    decision_provenance: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "decision_id": self.decision_id,
            "mission_id": self.mission_id,
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "why_this_action": self.why_this_action,
            "why_now": self.why_now,
            "why_this_tool": self.why_this_tool,
            "information_provided": self.information_provided,
            "hypothesis_tested": self.hypothesis_tested,
            "evidence_expected": self.evidence_expected,
            "proof_enabled": self.proof_enabled,
            "alternatives": [list(item) for item in self.alternatives],
            "decision_provenance": self.decision_provenance,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class AttackPathStep:
    """A single node inside an attack path.

    Attributes:
        asset_key: graph node key.
        kind: :class:`AttackPathStepKind`.
        evidence_refs: evidence identifiers backing this step.
        validated: whether this step has been independently validated.
        assumptions: assumptions required for the step to hold.

    """

    asset_key: str = ""
    kind: AttackPathStepKind = AttackPathStepKind.EXPOSURE
    evidence_refs: tuple[str, ...] = ()
    validated: bool = False
    assumptions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "asset_key": self.asset_key,
            "kind": self.kind.value,
            "evidence_refs": list(self.evidence_refs),
            "validated": self.validated,
            "assumptions": list(self.assumptions),
        }


@dataclass(slots=True)
class AttackPath:
    """A security-relevant chain through the attack-surface graph.

    Attributes:
        path_id: stable path identifier.
        mission_id: owning mission.
        objective: mission objective the path serves.
        steps: ordered :class:`AttackPathStep` entries.
        state: :class:`AttackPathState`.
        score: aggregate path score.
        scores: per-dimension explainable scores.
        evidence_refs: evidence identifiers backing the path.
        assumptions: unresolved assumptions.
        discovered_at / validated_at / proved_at: timestamps.

    """

    path_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    objective: MissionObjective = MissionObjective.ATTACK_SURFACE_DISCOVERY
    steps: tuple[AttackPathStep, ...] = ()
    state: AttackPathState = AttackPathState.HYPOTHETICAL
    score: float = 0.0
    scores: dict[str, float] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    discovered_at: str = field(default_factory=utcnow_iso)
    validated_at: str | None = None
    proved_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "path_id": self.path_id,
            "mission_id": self.mission_id,
            "objective": self.objective.value,
            "steps": [step.to_dict() for step in self.steps],
            "state": self.state.value,
            "score": self.score,
            "scores": self.scores,
            "evidence_refs": list(self.evidence_refs),
            "assumptions": list(self.assumptions),
            "discovered_at": self.discovered_at,
            "validated_at": self.validated_at,
            "proved_at": self.proved_at,
        }


@dataclass(slots=True)
class Gap:
    """A recognised evidence or proof gap blocking a finding.

    Attributes:
        gap_id: stable gap identifier.
        mission_id: owning mission.
        finding_id: candidate finding the gap blocks.
        kind: :class:`EvidenceGapKind`.
        asset_key: affected asset.
        required_evidence: evidence still required.
        minimum_action: the minimum action that would close the gap.
        priority: how critical the gap is.

    """

    gap_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    finding_id: str = ""
    kind: EvidenceGapKind = EvidenceGapKind.EVIDENCE_GAP
    asset_key: str = ""
    required_evidence: tuple[str, ...] = ()
    minimum_action: str = ""
    priority: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceGapKind):
            self.kind = EvidenceGapKind(self.kind)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the gap to a JSON-safe mapping."""
        return {
            "gap_id": self.gap_id,
            "mission_id": self.mission_id,
            "finding_id": self.finding_id,
            "kind": self.kind.value,
            "asset_key": self.asset_key,
            "required_evidence": list(self.required_evidence),
            "minimum_action": self.minimum_action,
            "priority": self.priority,
        }


@dataclass(slots=True)
class ToolSelection:
    """A tool selection for an action node.

    Attributes:
        selection_id: stable selection identifier.
        mission_id / action_id: scoping identifiers.
        capability: capability the selection satisfies.
        tool_id: selected tool.
        alternatives: ordered fallback tool ids.
        score: selection score.
        reasons: explainable reasons.
        expected_evidence: evidence the tool is expected to produce.
        expected_proof_value: proof value estimate.
        risk: tool execution risk.
        cost: tool execution cost estimate.

    """

    selection_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    action_id: str = ""
    capability: str = ""
    tool_id: str = ""
    alternatives: tuple[str, ...] = ()
    score: float = 0.0
    reasons: tuple[str, ...] = ()
    expected_evidence: tuple[str, ...] = ()
    expected_proof_value: float = 0.0
    risk: float = 0.0
    cost: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "selection_id": self.selection_id,
            "mission_id": self.mission_id,
            "action_id": self.action_id,
            "capability": self.capability,
            "tool_id": self.tool_id,
            "alternatives": list(self.alternatives),
            "score": self.score,
            "reasons": list(self.reasons),
            "expected_evidence": list(self.expected_evidence),
            "expected_proof_value": self.expected_proof_value,
            "risk": self.risk,
            "cost": self.cost,
        }


@dataclass(frozen=True, slots=True)
class FailureRecord:
    """A classified tool failure for an action.

    Attributes:
        failure_id: stable failure identifier.
        mission_id / action_id: scoping identifiers.
        tool_id: tool that failed.
        failure_class: :class:`FailureClass`.
        management: :class:`FailureManagement` applied.
        error: error message.
        retries: retries performed.
        occurred_at: timestamp.

    """

    failure_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    action_id: str = ""
    tool_id: str = ""
    failure_class: FailureClass = FailureClass.UNKNOWN
    management: FailureManagement = FailureManagement.RETRY
    error: str = ""
    retries: int = 0
    occurred_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "failure_id": self.failure_id,
            "mission_id": self.mission_id,
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "failure_class": self.failure_class.value,
            "management": self.management.value,
            "error": self.error,
            "retries": self.retries,
            "occurred_at": self.occurred_at,
        }


@dataclass(frozen=True, slots=True)
class ToolFallbackRecord:
    """A recorded tool fallback (capability-equivalent substitution)."""

    fallback_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    action_id: str = ""
    primary_tool: str = ""
    fallback_tool: str = ""
    capability: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "fallback_id": self.fallback_id,
            "mission_id": self.mission_id,
            "action_id": self.action_id,
            "primary_tool": self.primary_tool,
            "fallback_tool": self.fallback_tool,
            "capability": self.capability,
            "reason": self.reason,
        }


@dataclass(slots=True)
class PlanCheckpoint:
    """A resumable snapshot of a mission.

    Attributes:
        checkpoint_id: stable checkpoint identifier.
        mission_id: owning mission.
        plan_version: plan version at checkpoint time.
        mission_state: mission state at checkpoint time.
        completed_actions: ids of completed actions.
        pending_actions: ids of pending actions.
        observations: observation identifiers recorded.
        evidence: evidence identifiers recorded.
        hypotheses: hypothesis identifiers open.
        proof_states: proof states per finding (JSON).
        tool_state: tool state snapshot (JSON).
        created_at: timestamp.

    """

    checkpoint_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    plan_version: int = 1
    mission_state: MissionState = MissionState.CREATED
    completed_actions: tuple[str, ...] = ()
    pending_actions: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    proof_states: dict[str, Any] = field(default_factory=dict)
    tool_state: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "checkpoint_id": self.checkpoint_id,
            "mission_id": self.mission_id,
            "plan_version": self.plan_version,
            "mission_state": self.mission_state.value,
            "completed_actions": list(self.completed_actions),
            "pending_actions": list(self.pending_actions),
            "observations": list(self.observations),
            "evidence": list(self.evidence),
            "hypotheses": list(self.hypotheses),
            "proof_states": self.proof_states,
            "tool_state": self.tool_state,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """A policy-gate decision for a proposed action.

    Attributes:
        decision_id: stable decision identifier.
        mission_id / action_id: scoping identifiers.
        gate: gate kind (``scope``, ``authorization``, ``safety``, ``rate_limit``, ``ai_policy``).
        allowed: whether the action passed the gate.
        reason: human-readable reason.
        detail: structured detail map.

    """

    decision_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    action_id: str = ""
    gate: str = "scope"
    allowed: bool = False
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "decision_id": self.decision_id,
            "mission_id": self.mission_id,
            "action_id": self.action_id,
            "gate": self.gate,
            "allowed": self.allowed,
            "reason": self.reason,
            "detail": self.detail,
        }
