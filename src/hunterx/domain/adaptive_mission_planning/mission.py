# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive mission aggregate and deterministic planner.

``AdaptiveMission`` is the planning aggregate: mission identity, objective,
mode, constraints, lifecycle state, execution graph, plan versions, plan
deltas, decision records, attack paths, gaps, checkpoints, failures, fallbacks
and tool selections. ``DeterministicMissionPlanner`` builds an initial,
explainable execution graph from a mission objective — the deterministic
fallback that keeps the system functional without AI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.adaptive_mission_planning.catalog import DeterministicPlanner
from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    ActionType,
    DependencyKind,
    MissionMode,
    MissionObjective,
    MissionState,
)
from hunterx.domain.adaptive_mission_planning.graph import AdaptiveExecutionGraph
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    AttackPath,
    DecisionRecord,
    DynamicDependency,
    FailureRecord,
    Gap,
    MissionConstraints,
    PlanCheckpoint,
    PlanDelta,
    PlanVersion,
    PolicyDecision,
    ToolFallbackRecord,
    ToolSelection,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class AdaptiveMission:
    """The planning aggregate of an adaptive mission.

    Attributes:
        mission_id: stable mission identifier.
        objective: canonical :class:`MissionObjective`.
        mode: :class:`MissionMode`.
        state: :class:`MissionState`.
        constraints: immutable :class:`MissionConstraints`.
        graph: the living :class:`AdaptiveExecutionGraph`.
        plan_version: current plan version.
        versions: replayable plan version history.
        deltas: plan deltas produced by replanning.
        decisions: explainable decision records.
        attack_paths: discovered attack paths (intelligence only).
        gaps: open evidence/proof gaps.
        checkpoints: persisted checkpoints.
        failures: classified tool failures.
        fallbacks: recorded tool fallbacks.
        tool_selections: recorded tool selections.
        policy_decisions: recorded policy-gate decisions.
        authorization_context: authorization tier.
        safety_ceiling: safety ceiling.
        tenant: isolation key.
        created_at / updated_at / completed_at: timestamps.

    """

    mission_id: str = field(default_factory=generate_id)
    objective: MissionObjective = MissionObjective.ATTACK_SURFACE_DISCOVERY
    mode: MissionMode = MissionMode.BALANCED
    state: MissionState = MissionState.CREATED
    constraints: MissionConstraints = field(default_factory=MissionConstraints)
    graph: AdaptiveExecutionGraph = field(default_factory=AdaptiveExecutionGraph)
    plan_version: int = 1
    versions: list[PlanVersion] = field(default_factory=list)
    deltas: list[PlanDelta] = field(default_factory=list)
    decisions: list[DecisionRecord] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    checkpoints: list[PlanCheckpoint] = field(default_factory=list)
    failures: list[FailureRecord] = field(default_factory=list)
    fallbacks: list[ToolFallbackRecord] = field(default_factory=list)
    tool_selections: list[ToolSelection] = field(default_factory=list)
    policy_decisions: list[PolicyDecision] = field(default_factory=list)
    authorization_context: str = "default"
    safety_ceiling: str = "low_impact_active"
    tenant: str = ""
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)
    completed_at: str | None = None

    def touch(self) -> None:
        """Refresh the updated timestamp."""
        self.updated_at = utcnow_iso()

    def transition(self, target: MissionState) -> None:
        """Transition the mission state (enforces the state machine)."""
        from hunterx.domain.adaptive_mission_planning.state import assert_transition

        assert_transition(self.state, target)
        self.state = target
        if target.is_terminal:
            self.completed_at = utcnow_iso()
        self.touch()

    def record_version(self, version: PlanVersion) -> None:
        """Append a plan version and bump the current version."""
        self.versions.append(version)
        self.plan_version = version.plan_version
        self.touch()

    def pending_actions(self) -> list[ActionNode]:
        """Return actions that are still open."""
        return [action for action in self.graph.actions.values() if not action.status.is_terminal]

    def completed_actions(self) -> list[ActionNode]:
        """Return actions that reached a terminal state."""
        return [action for action in self.graph.actions.values() if action.status.is_terminal]

    def progress(self) -> float:
        """Return completion progress in ``[0, 100]``."""
        total = len(self.graph.actions)
        if not total:
            return 0.0
        return round(len(self.completed_actions()) / total * 100.0, 1)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the mission summary to a JSON-safe mapping."""
        return {
            "mission_id": self.mission_id,
            "objective": self.objective.value,
            "mode": self.mode.value,
            "state": self.state.value,
            "plan_version": self.plan_version,
            "progress": self.progress(),
            "action_count": len(self.graph.actions),
            "attack_path_count": len(self.attack_paths),
            "gap_count": len(self.gaps),
            "decision_count": len(self.decisions),
            "checkpoint_count": len(self.checkpoints),
            "failure_count": len(self.failures),
            "authorization_context": self.authorization_context,
            "safety_ceiling": self.safety_ceiling,
            "tenant": self.tenant,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
        }


class DeterministicMissionPlanner:
    """Build an initial explainable execution graph from a mission objective."""

    def __init__(self, *, catalog: DeterministicPlanner | None = None) -> None:
        self.catalog = catalog or DeterministicPlanner()

    def create_initial_plan(self, mission: AdaptiveMission) -> PlanVersion:
        """Populate ``mission.graph`` from its objective and return the root version.

        The chain is capability-driven: each step depends on the previous one
        so the plan is a deterministic, dependency-ordered execution graph.
        """
        capabilities = self.catalog.discovery_chain(mission.objective)
        previous: ActionNode | None = None
        for capability in capabilities:
            node = ActionNode(
                mission_id=mission.mission_id,
                objective=mission.objective,
                action_type=_action_type(capability),
                capability=capability,
                depends_on=(previous.action_id,) if previous else (),
                expected_information_gain=0.7,
                expected_evidence=(f"evidence:{capability}",),
                expected_proof_value=0.5 if capability in ("proof_validation", "replay") else 0.0,
                status=ActionStatus.PROPOSED,
                provenance={"source": "deterministic_planner", "objective": mission.objective.value},
            )
            mission.graph.add_action(node)
            if previous is not None:
                mission.graph.add_dependency(
                    DynamicDependency(
                        dependency_id=generate_id(),
                        source_action_id=previous.action_id,
                        target_action_id=node.action_id,
                        kind=DependencyKind.DEPENDS_ON,
                        rationale="capability chain",
                    )
                )
            previous = node
        version = PlanVersion(
            plan_version=1,
            parent_version=0,
            reason=f"initial plan for objective '{mission.objective.value}'",
            created_by="deterministic_planner",
            decision_provenance={"capabilities": list(capabilities)},
        )
        mission.record_version(version)
        return version


_ACTION_TYPE_BY_CAPABILITY: dict[str, str] = {
    "asset_discovery": "discover_subdomains",
    "subdomain_enumeration": "discover_subdomains",
    "dns_enumeration": "enumerate_dns",
    "port_discovery": "identify_services",
    "service_detection": "identify_services",
    "technology_fingerprint": "identify_technology",
    "certificate_enumeration": "enumerate_dns",
    "endpoint_enumeration": "discover_endpoints",
    "content_discovery": "discover_endpoints",
    "javascript_analysis": "discover_endpoints",
    "parameter_discovery": "discover_parameters",
    "api_mapping": "map_api",
    "authentication_analysis": "analyze_authentication",
    "authorization_analysis": "test_authorization",
    "vulnerability_scanning": "validate_hypothesis",
    "proof_validation": "collect_proof",
    "replay": "replay_proof",
    "cloud_ownership_mapping": "map_api",
    "secret_detection": "investigate_behavior",
    "dependency_check": "generate_hypothesis",
}


def _action_type(capability: str) -> ActionType:
    """Return the canonical action type for ``capability``."""
    return ActionType(_ACTION_TYPE_BY_CAPABILITY.get(capability, "investigate_behavior"))
