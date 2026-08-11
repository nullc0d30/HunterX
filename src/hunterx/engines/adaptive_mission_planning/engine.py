# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Mission & Attack-Path Planning — engine facade.

Sprint 027. The :class:`AdaptiveMissionPlanningEngine` is the runtime aggregate
of the Adaptive Mission Planning layer: it creates missions, builds the initial
explainable execution graph, ranks candidate actions through the decision
engine, evaluates replanning signals, applies plan deltas, discovers and
scores attack paths, selects tools, records failures and fallbacks, and
persists checkpoints. It is injected with pure domain engines so it can be
assembled from the platform composition root or from test doubles.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from hunterx.domain.adaptive_mission_planning.attack_path import AttackPathEngine
from hunterx.domain.adaptive_mission_planning.catalog import DeterministicPlanner
from hunterx.domain.adaptive_mission_planning.checkpoint import CheckpointEngine
from hunterx.domain.adaptive_mission_planning.decision import (
    ActionDecisionEngine,
    DecisionInput,
    DecisionResult,
)
from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    MissionMode,
    MissionObjective,
    MissionState,
    ReplanTrigger,
)
from hunterx.domain.adaptive_mission_planning.graph import AdaptiveExecutionGraph
from hunterx.domain.adaptive_mission_planning.mission import (
    AdaptiveMission,
    DeterministicMissionPlanner,
)
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    ActionProposal,
    AttackPath,
    DecisionRecord,
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
from hunterx.domain.adaptive_mission_planning.policy import PolicyEngine
from hunterx.domain.adaptive_mission_planning.replan import ReplanningEngine, ReplanSignal
from hunterx.domain.adaptive_mission_planning.resource import ResourcePlanner, TimePlanner
from hunterx.domain.adaptive_mission_planning.scoring import ScoringModel
from hunterx.domain.adaptive_mission_planning.toolchain import (
    FailureClassifier,
    RecoveryEngine,
    ToolFallbackResolver,
    ToolSelectionEngine,
)
from hunterx.domain.exceptions.adaptive_mission_planning import (
    ActionNotFoundError,
    AdaptiveMissionNotFoundError,
    AdaptivePlanNotFoundError,
)
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph


class AdaptiveMissionPlanningEngine:
    """Runtime aggregate of the Adaptive Mission Planning layer.

    Attributes:
        missions: registered adaptive missions (in-memory index).
        planner: deterministic initial-plan builder.
        decision: action decision engine.
        replanning: replanning engine.
        attack_paths: attack-path engine.
        policy: policy gate engine.
        tools: tool selection engine.
        checkpoints: checkpoint engine.
        classifier: failure classifier.
        recovery: failure recovery engine.
        resources: resource planner.
        time_planner: time-aware planner.
        catalog: deterministic planning policies.

    """

    def __init__(
        self,
        *,
        deterministic_planner: DeterministicPlanner | None = None,
        mission_planner: DeterministicMissionPlanner | None = None,
        decision_engine: ActionDecisionEngine | None = None,
        replanning_engine: ReplanningEngine | None = None,
        attack_path_engine: AttackPathEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        tool_selection_engine: ToolSelectionEngine | None = None,
        checkpoint_engine: CheckpointEngine | None = None,
        failure_classifier: FailureClassifier | None = None,
        recovery_engine: RecoveryEngine | None = None,
        resource_planner: ResourcePlanner | None = None,
        time_planner: TimePlanner | None = None,
        scoring: ScoringModel | None = None,
    ) -> None:
        self.catalog = deterministic_planner or DeterministicPlanner()
        self.mission_planner = mission_planner or DeterministicMissionPlanner(catalog=self.catalog)
        self.decision = decision_engine or ActionDecisionEngine(scoring=scoring)
        self.replanning = replanning_engine or ReplanningEngine()
        self.attack_paths = attack_path_engine or AttackPathEngine()
        self.policy = policy_engine or PolicyEngine()
        self.tools = tool_selection_engine or ToolSelectionEngine()
        self.checkpoints = checkpoint_engine or CheckpointEngine()
        self.classifier = failure_classifier or FailureClassifier()
        self.recovery = recovery_engine or RecoveryEngine()
        self.resources = resource_planner or ResourcePlanner()
        self.time_planner = time_planner or TimePlanner()
        self._missions: dict[str, AdaptiveMission] = {}

    # -- mission lifecycle --------------------------------------------------

    def create_mission(
        self,
        *,
        objective: MissionObjective = MissionObjective.ATTACK_SURFACE_DISCOVERY,
        mode: MissionMode = MissionMode.BALANCED,
        constraints: MissionConstraints | None = None,
        authorization_context: str = "default",
        safety_ceiling: str = "low_impact_active",
        tenant: str = "",
        target: str = "",
    ) -> AdaptiveMission:
        """Create a mission and build its initial deterministic plan."""
        mission = AdaptiveMission(
            objective=objective,
            mode=mode,
            constraints=constraints or MissionConstraints(),
            authorization_context=authorization_context,
            safety_ceiling=safety_ceiling,
            tenant=tenant,
        )
        if target:
            mission.constraints = _with_target(mission.constraints, target)
        self.mission_planner.create_initial_plan(mission)
        mission.state = MissionState.SCOPING
        self._missions[mission.mission_id] = mission
        return mission

    def get_mission(self, mission_id: str) -> AdaptiveMission:
        """Return a mission by id or raise."""
        mission = self._missions.get(mission_id)
        if mission is None:
            raise AdaptiveMissionNotFoundError(mission_id)
        return mission

    def restore(self, mission: AdaptiveMission) -> AdaptiveMission:
        """Register an already-persisted mission back into the in-memory store.

        Used by the mission orchestration restart path: the adaptive aggregate
        is re-registered so ``transition``/``status`` work after a process
        restart or across CLI invocations.
        """
        self._missions[mission.mission_id] = mission
        return mission

    def missions(self) -> list[AdaptiveMission]:
        """Return all registered missions."""
        return list(self._missions.values())

    def status(self, mission_id: str) -> AdaptiveMission:
        """Return the current mission aggregate (status, progress, plan)."""
        return self.get_mission(mission_id)

    def transition(self, mission_id: str, target: MissionState) -> AdaptiveMission:
        """Transition the mission lifecycle state (explicit + event-driven)."""
        mission = self.get_mission(mission_id)
        mission.transition(target)
        return mission

    def pause(self, mission_id: str) -> AdaptiveMission:
        """Pause a mission."""
        return self.transition(mission_id, MissionState.PAUSED)

    def resume(self, mission_id: str) -> AdaptiveMission:
        """Resume a mission."""
        return self.transition(mission_id, MissionState.REASSESSMENT)

    def complete(self, mission_id: str) -> AdaptiveMission:
        """Complete a mission."""
        return self.transition(mission_id, MissionState.COMPLETED)

    def cancel(self, mission_id: str) -> AdaptiveMission:
        """Cancel a mission."""
        return self.transition(mission_id, MissionState.CANCELLED)

    def fail(self, mission_id: str) -> AdaptiveMission:
        """Fail a mission."""
        return self.transition(mission_id, MissionState.FAILED)

    # -- plan queries -------------------------------------------------------

    def get_plan(self, mission_id: str) -> AdaptiveExecutionGraph:
        """Return the current execution graph for ``mission_id``."""
        return self.get_mission(mission_id).graph

    def get_plan_history(self, mission_id: str) -> list[PlanVersion]:
        """Return the replayable plan version history."""
        return list(self.get_mission(mission_id).versions)

    def get_plan_version(self, mission_id: str, plan_version: int) -> PlanVersion:
        """Return a specific plan version or raise."""
        mission = self.get_mission(mission_id)
        for version in mission.versions:
            if version.plan_version == plan_version:
                return version
        raise AdaptivePlanNotFoundError(mission_id, plan_version)

    def get_action(self, mission_id: str, action_id: str) -> ActionNode:
        """Return an action node by id or raise."""
        mission = self.get_mission(mission_id)
        action = mission.graph.action(action_id)
        if action is None:
            raise ActionNotFoundError(action_id)
        return action

    # -- decision -----------------------------------------------------------

    def candidate_actions(self, mission_id: str, inp: DecisionInput | None = None) -> DecisionResult:
        """Rank policy-filtered candidate actions for ``mission_id``."""
        mission = self.get_mission(mission_id)
        if inp is None:
            inp = DecisionInput(
                mission_id=mission_id,
                objective=mission.objective,
                mode=mission.mode,
                constraints=mission.constraints,
                authorization_context=mission.authorization_context,
                safety_ceiling=mission.safety_ceiling,
            )
        result = self.decision.decide(inp)
        if result.decision is not None:
            mission.decisions.append(result.decision)
        return result

    def propose_actions(self, mission_id: str, result: DecisionResult) -> list[ActionProposal]:
        """Add approved proposals to the mission graph and return them.

        Every proposal is re-checked against the mission policy gates before
        being scheduled; a rejected proposal is never scheduled.
        """
        mission = self.get_mission(mission_id)
        scheduled: list[ActionProposal] = []
        for proposal in result.proposals:
            decision = self.policy.check_proposal(
                proposal.action,
                mission.constraints,
                authorization_context=mission.authorization_context,
                ai_proposed=proposal.ai_assisted,
            )
            mission.policy_decisions.append(decision)
            if not decision.allowed:
                continue
            proposal.action.mark(ActionStatus.APPROVED)
            mission.graph.add_action(proposal.action)
            scheduled.append(proposal)
        return scheduled

    def approve_action(self, mission_id: str, action_id: str) -> ActionNode:
        """Approve a proposed action for execution."""
        action = self.get_action(mission_id, action_id)
        if action.status is ActionStatus.PROPOSED:
            action.mark(ActionStatus.APPROVED)
        return action

    # -- replanning ---------------------------------------------------------

    def replan(
        self,
        mission_id: str,
        *,
        signal: ReplanSignal,
        reason: str = "",
    ) -> PlanDelta:
        """Evaluate a replanning signal, apply the delta and version the plan.

        Only the changed parts of the plan are mutated; the full mission is
        never rebuilt. Scope-changing signals (SCOPE_CHANGED) are handled by
        the delta's REMOVE_ACTION changes.
        """
        mission = self.get_mission(mission_id)
        current_version = mission.plan_version
        delta = self.replanning.build_delta(
            mission_id=mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=current_version,
            reason=reason or f"replan triggered by '{signal.trigger.value}'",
        )
        if not delta.is_empty():
            mission.graph.apply_delta(delta)
            mission.deltas.append(delta)
            mission.record_version(self.replanning.version_for(delta))
        else:
            version = self.replanning.version_for(delta)
            mission.record_version(version)
        if signal.trigger is ReplanTrigger.SCOPE_CHANGED:
            mission.transition(MissionState.REASSESSMENT)
        return delta

    def replan_for_change(
        self,
        mission_id: str,
        *,
        trigger: ReplanTrigger,
        asset_key: str = "",
        detail: dict[str, Any] | None = None,
        reason: str = "",
    ) -> PlanDelta:
        """Replan for a single canonical trigger."""
        return self.replan(
            mission_id,
            signal=ReplanSignal(trigger, asset_key=asset_key, detail=detail, priority=0.9),
            reason=reason,
        )

    # -- attack paths -------------------------------------------------------

    def discover_attack_paths(
        self,
        mission_id: str,
        surface: AttackSurfaceGraph | None = None,
        *,
        evidence_map: Mapping[str, Iterable[str]] | None = None,
        validated_map: dict[str, bool] | None = None,
    ) -> list[AttackPath]:
        """Discover and score attack paths over the attack-surface graph.

        Attack paths are intelligence only — they never trigger execution.
        """
        mission = self.get_mission(mission_id)
        if surface is None:
            return list(mission.attack_paths)
        paths = self.attack_paths.discover(
            surface,
            mission_id=mission_id,
            objective=mission.objective,
            evidence_map=evidence_map,
            validated_map=validated_map,
        )
        mission.attack_paths = paths
        return paths

    def reassess_paths(self, mission_id: str, *, evidence_map: Mapping[str, Iterable[str]], validated_map: dict[str, bool], proved_map: dict[str, bool]) -> list[AttackPath]:
        """Recompute attack-path validation states from current evidence."""
        mission = self.get_mission(mission_id)
        mission.attack_paths = [
            self.attack_paths.reassess(
                path,
                evidence_map=evidence_map,
                validated_map=validated_map,
                proved_map=proved_map,
            )
            for path in mission.attack_paths
        ]
        return mission.attack_paths

    def attack_paths_for(self, mission_id: str) -> list[AttackPath]:
        """Return attack paths for ``mission_id``."""
        return list(self.get_mission(mission_id).attack_paths)

    # -- tool selection -----------------------------------------------------

    def select_tool(self, mission_id: str, action_id: str) -> ToolSelection:
        """Select a tool for ``action_id`` and bind it onto the node."""
        action = self.get_action(mission_id, action_id)
        selection = self.tools.select(action)
        mission = self.get_mission(mission_id)
        mission.tool_selections.append(selection)
        return selection

    # -- failure recovery ---------------------------------------------------

    def record_failure(
        self,
        mission_id: str,
        action_id: str,
        *,
        tool_id: str = "",
        error: str = "",
        timeout: bool = False,
        exit_code: int | None = None,
    ) -> FailureRecord:
        """Classify a failure, decide management and record it."""
        mission = self.get_mission(mission_id)
        failure_class = self.classifier.classify(error=error, timeout=timeout, exit_code=exit_code)
        retries = len([f for f in mission.failures if f.action_id == action_id])
        alternatives_available = bool(self.tools.alternatives_for(tool_id, self.get_action(mission_id, action_id).capability))
        management, _ = self.recovery.decide(
            failure_class,
            retries=retries,
            alternatives_available=alternatives_available,
        )
        record = FailureRecord(
            mission_id=mission_id,
            action_id=action_id,
            tool_id=tool_id,
            failure_class=failure_class,
            management=management,
            error=error[:1000],
            retries=retries,
        )
        mission.failures.append(record)
        return record

    def fallback_tool(
        self,
        mission_id: str,
        action_id: str,
        *,
        primary_tool: str,
        capability: str,
    ) -> ToolFallbackRecord | None:
        """Resolve a capability-equivalent fallback for a failed tool."""
        mission = self.get_mission(mission_id)
        fallback = ToolFallbackResolver().resolve(
            primary_tool,
            capability,
            self.tools,
            mission_id=mission_id,
            action_id=action_id,
        )
        if fallback is not None:
            mission.fallbacks.append(fallback)
            action = mission.graph.action(action_id)
            if action is not None:
                action.selected_tool = fallback.fallback_tool
                action.touch()
        return fallback

    # -- checkpoints --------------------------------------------------------

    def create_checkpoint(
        self,
        mission_id: str,
        *,
        observations: tuple[str, ...] = (),
        evidence: tuple[str, ...] = (),
        hypotheses: tuple[str, ...] = (),
        proof_states: dict[str, Any] | None = None,
        tool_state: dict[str, Any] | None = None,
    ) -> PlanCheckpoint:
        """Snapshot the mission for resume."""
        mission = self.get_mission(mission_id)
        checkpoint = self.checkpoints.create(
            mission_id=mission_id,
            graph=mission.graph,
            plan_version=mission.plan_version,
            mission_state=mission.state,
            observations=observations,
            evidence=evidence,
            hypotheses=hypotheses,
            proof_states=proof_states,
            tool_state=tool_state,
        )
        mission.checkpoints.append(checkpoint)
        return checkpoint

    def resume_from_checkpoint(self, mission_id: str, checkpoint: PlanCheckpoint) -> AdaptiveMission:
        """Restore a mission from a checkpoint snapshot."""
        mission = self.get_mission(mission_id)
        self.checkpoints.resume(checkpoint, mission.graph)
        mission.transition(MissionState.REASSESSMENT)
        return mission

    # -- gaps ---------------------------------------------------------------

    def record_gap(self, mission_id: str, gap: Gap) -> Gap:
        """Record an open evidence/proof gap."""
        mission = self.get_mission(mission_id)
        mission.gaps.append(gap)
        return gap

    def evidence_gaps(self, mission_id: str) -> list[Gap]:
        """Return open evidence gaps."""
        return [gap for gap in self.get_mission(mission_id).gaps if gap.kind.value == "evidence_gap"]

    def proof_gaps(self, mission_id: str) -> list[Gap]:
        """Return open proof gaps."""
        return [gap for gap in self.get_mission(mission_id).gaps if gap.kind.value == "proof_gap"]

    # -- explainability -----------------------------------------------------

    def decision_explanation(self, mission_id: str, action_id: str = "") -> DecisionRecord | None:
        """Return the explainable decision record for ``action_id``."""
        mission = self.get_mission(mission_id)
        if action_id:
            for decision in reversed(mission.decisions):
                if decision.action_id == action_id:
                    return decision
            return None
        return mission.decisions[-1] if mission.decisions else None

    def explain_next_action(self, mission_id: str) -> dict[str, Any]:
        """Explain why the highest-ranked candidate action is next."""
        result = self.candidate_actions(mission_id)
        if not result.proposals:
            return {"explanation": "no actionable proposals", "proposals": []}
        best = result.proposals[0]
        return {
            "action_id": best.action.action_id,
            "action_type": best.action.action_type.value,
            "capability": best.action.capability,
            "score": best.score,
            "factors": best.factors,
            "rationale": best.rationale,
            "why_now": f"mission '{mission_id}' in {self.status(mission_id).state.value}",
            "alternatives": list(best.alternatives),
            "proposals": [proposal.to_dict() for proposal in result.proposals],
        }

    # -- resources / observability ------------------------------------------

    def resource_state(self, mission_id: str) -> dict[str, Any]:
        """Return the resource state of ``mission_id``."""
        mission = self.get_mission(mission_id)
        return self.resources.state(mission.graph).to_dict()

    def next_parallel_wave(self, mission_id: str) -> list[ActionNode]:
        """Return the next wave of ready, approved actions (parallel execution)."""
        mission = self.get_mission(mission_id)
        return mission.graph.ready_actions(approved_only=True)

    def can_schedule_more(self, mission_id: str) -> bool:
        """Return ``True`` when the mission has scheduling budget left."""
        mission = self.get_mission(mission_id)
        state = self.resources.state(mission.graph)
        return self.resources.can_schedule(state, mission.constraints)


def _with_target(constraints: MissionConstraints, target: str) -> MissionConstraints:
    import dataclasses

    if not constraints.included_targets:
        return dataclasses.replace(constraints, included_targets=(target,))
    return constraints


__all__ = [
    "ActionNode",
    "ActionProposal",
    "AdaptiveExecutionGraph",
    "AdaptiveMission",
    "AdaptiveMissionPlanningEngine",
    "AttackPath",
    "DecisionInput",
    "DecisionResult",
    "FailureRecord",
    "Gap",
    "MissionConstraints",
    "MissionMode",
    "MissionObjective",
    "MissionState",
    "PlanCheckpoint",
    "PlanDelta",
    "PlanVersion",
    "PolicyDecision",
    "ReplanSignal",
    "ReplanTrigger",
    "ToolFallbackRecord",
    "ToolSelection",
]
