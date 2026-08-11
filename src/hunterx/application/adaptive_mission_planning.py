# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Mission & Attack-Path Planning — use-case services.

``AdaptiveMissionPlanningService`` is the orchestrator: it bridges the pure
adaptive mission planning domain and the :class:`AdaptiveMissionPlanningEngine`
to the TIDB system-of-record, persists normalized planning entities (missions,
action nodes, dependencies, branches, plan versions, plan deltas, decisions,
attack paths, gaps, checkpoints, failures, tool fallbacks and tool
selections) and publishes ``mission.*`` events.

``AdaptiveMissionPlanningQueryService`` reads persisted planning records back
from the TIDB and answers the canonical queries (mission status, current plan,
plan history, candidate actions, attack paths, decision explanations,
coverage, evidence gaps and proof gaps).
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import (
    MissionMode,
    MissionObjective,
    MissionState,
    ReplanTrigger,
)
from hunterx.domain.adaptive_mission_planning.mission import AdaptiveMission
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    ActionProposal,
    AttackPath,
    ConditionalBranch,
    FailureRecord,
    Gap,
    MissionConstraints,
    PlanCheckpoint,
    PlanDelta,
    PlanVersion,
    ToolFallbackRecord,
    ToolSelection,
)
from hunterx.domain.entities.tidb.adaptive_mission_planning import (
    AdaptiveActionNodeRecord,
    AdaptiveAttackPathRecord,
    AdaptiveBranchRecord,
    AdaptiveDecisionRecord,
    AdaptiveDependencyRecord,
    AdaptiveFailureRecord,
    AdaptiveGapRecord,
    AdaptiveMissionRecord,
    AdaptivePlanCheckpointRecord,
    AdaptivePlanDeltaRecord,
    AdaptivePlanVersionRecord,
    AdaptiveToolFallbackRecord,
    AdaptiveToolSelectionRecord,
)
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.engines.adaptive_mission_planning.engine import (
    AdaptiveMissionPlanningEngine,
    DecisionInput,
    DecisionResult,
)


class AdaptiveMissionPlanningService:
    """Orchestrate the adaptive mission planning layer against the TIDB."""

    def __init__(
        self,
        *,
        engine: AdaptiveMissionPlanningEngine | None = None,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self._engine = engine or AdaptiveMissionPlanningEngine()
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache

    @property
    def engine(self) -> AdaptiveMissionPlanningEngine:
        """Return the underlying planning engine."""
        return self._engine

    # -- mission lifecycle --------------------------------------------------

    def create_mission(
        self,
        *,
        objective: MissionObjective | str = MissionObjective.ATTACK_SURFACE_DISCOVERY,
        mode: MissionMode | str = MissionMode.BALANCED,
        scope: str = "",
        included_targets: tuple[str, ...] = (),
        excluded_assets: tuple[str, ...] = (),
        excluded_capabilities: tuple[str, ...] = (),
        time_budget_seconds: int = 0,
        max_concurrency: int = 4,
        risk_threshold: float = 0.8,
        authorization_context: str = "default",
        safety_ceiling: str = "low_impact_active",
        tenant: str = "",
        target: str = "",
    ) -> AdaptiveMission:
        """Create an adaptive mission with its initial deterministic plan."""
        objective_enum = objective if isinstance(objective, MissionObjective) else MissionObjective(objective)
        mode_enum = mode if isinstance(mode, MissionMode) else MissionMode(mode)
        constraints = MissionConstraints(
            scope=scope,
            included_targets=included_targets,
            excluded_assets=excluded_assets,
            excluded_capabilities=excluded_capabilities,
            time_budget_seconds=time_budget_seconds,
            max_concurrency=max_concurrency,
            risk_threshold=risk_threshold,
            tenant=tenant,
        )
        mission = self._engine.create_mission(
            objective=objective_enum,
            mode=mode_enum,
            constraints=constraints,
            authorization_context=authorization_context,
            safety_ceiling=safety_ceiling,
            tenant=tenant,
            target=target,
        )
        self._persist_mission(mission)
        self._persist_graph(mission)
        for version in mission.versions:
            self._persist_version(mission, version)
        self._publish(
            "mission.plan.created",
            {
                "mission_id": mission.mission_id,
                "plan_version": mission.plan_version,
                "objective": mission.objective.value,
                "action_count": len(mission.graph.actions),
            },
        )
        return mission

    def status(self, mission_id: str) -> AdaptiveMission:
        """Return the current mission aggregate."""
        return self._engine.status(mission_id)

    def get(self, mission_id: str) -> AdaptiveMission:
        """Return a mission by id."""
        return self._engine.get_mission(mission_id)

    def list_missions(self, *, limit: int = 100, offset: int = 0) -> list[AdaptiveMission]:
        """Return registered missions."""
        missions = self._engine.missions()
        return missions[offset : offset + limit]

    def pause(self, mission_id: str) -> AdaptiveMission:
        """Pause a mission."""
        return self._engine.pause(mission_id)

    def transition(self, mission_id: str, target: MissionState) -> AdaptiveMission:
        """Transition the mission lifecycle state explicitly."""
        return self._engine.transition(mission_id, target)

    def resume(self, mission_id: str) -> AdaptiveMission:
        """Resume a mission (publishes ``mission.resumed``)."""
        mission = self._engine.resume(mission_id)
        self._persist_mission(mission)
        self._publish("mission.resumed", {"mission_id": mission_id, "plan_id": ""})
        return mission

    def cancel(self, mission_id: str) -> AdaptiveMission:
        """Cancel a mission."""
        return self._engine.cancel(mission_id)

    def complete(self, mission_id: str) -> AdaptiveMission:
        """Complete a mission."""
        return self._engine.complete(mission_id)

    def fail(self, mission_id: str) -> AdaptiveMission:
        """Fail a mission."""
        return self._engine.fail(mission_id)

    # -- plan queries -------------------------------------------------------

    def current_plan(self, mission_id: str) -> dict[str, Any]:
        """Return a JSON-safe view of the current execution graph."""
        graph = self._engine.get_plan(mission_id)
        return {
            "mission_id": mission_id,
            "plan_version": self._engine.get_mission(mission_id).plan_version,
            "actions": [action.to_dict() for action in graph.actions.values()],
            "dependencies": [dep.to_dict() for dep in graph.dependencies.values()],
            "branches": [branch.to_dict() for branch in graph.branches.values()],
            "parallel_groups": graph.parallel_groups(),
            "topological_order": graph.topological_order(),
            "ready": [action.action_id for action in graph.ready_actions()],
        }

    def plan_history(self, mission_id: str) -> list[PlanVersion]:
        """Return the replayable plan version history."""
        return self._engine.get_plan_history(mission_id)

    def plan_version(self, mission_id: str, version: int) -> PlanVersion:
        """Return a specific plan version."""
        return self._engine.get_plan_version(mission_id, version)

    def graph(self, mission_id: str) -> list[ActionNode]:
        """Return the action nodes of the current plan."""
        return list(self._engine.get_plan(mission_id).actions.values())

    # -- replanning ---------------------------------------------------------

    def replan(
        self,
        mission_id: str,
        *,
        trigger: ReplanTrigger,
        asset_key: str = "",
        detail: dict[str, Any] | None = None,
        reason: str = "",
    ) -> PlanDelta:
        """Replan a mission from a canonical trigger; persist the delta."""
        delta = self._engine.replan_for_change(
            mission_id,
            trigger=trigger,
            asset_key=asset_key,
            detail=detail,
            reason=reason,
        )
        mission = self._engine.get_mission(mission_id)
        self._persist_mission(mission)
        self._persist_graph(mission)
        self._persist_delta(mission, delta)
        for version in mission.versions:
            if version.plan_version == delta.plan_version:
                self._persist_version(mission, version)
        self._publish(
            "mission.plan.revised",
            {
                "mission_id": mission_id,
                "previous_version": delta.parent_version,
                "new_version": delta.plan_version,
                "trigger": delta.trigger.value if delta.trigger else "",
                "reason": delta.reason,
                "changed_action_count": len(delta.changes),
            },
        )
        return delta

    # -- decisions ----------------------------------------------------------

    def candidate_actions(
        self,
        mission_id: str,
        *,
        unknowns: tuple[Any, ...] = (),
        hypotheses: tuple[Any, ...] = (),
        available_tools: tuple[str, ...] = (),
        tool_health: dict[str, Any] | None = None,
        proof_state: dict[str, Any] | None = None,
        ai_proposals: tuple[ActionNode, ...] = (),
        ai_assisted: bool = False,
    ) -> DecisionResult:
        """Rank policy-filtered candidate actions for a mission."""
        mission = self._engine.get_mission(mission_id)
        result = self._engine.candidate_actions(
            mission_id,
            DecisionInput(
                mission_id=mission_id,
                objective=mission.objective,
                mode=mission.mode,
                intelligence={},
                coverage={},
                unknowns=unknowns,
                hypotheses=hypotheses,
                available_tools=available_tools,
                tool_health=tool_health or {},
                proof_state=proof_state or {},
                constraints=mission.constraints,
                authorization_context=mission.authorization_context,
                safety_ceiling=mission.safety_ceiling,
                ai_proposals=ai_proposals,
                ai_assisted=ai_assisted,
            ),
        )
        for proposal in result.proposals:
            self._publish(
                "mission.action.proposed",
                {
                    "mission_id": mission_id,
                    "action_id": proposal.action.action_id,
                    "action_type": proposal.action.action_type.value,
                    "capability": proposal.action.capability,
                    "score": proposal.score,
                    "ai_assisted": proposal.ai_assisted,
                },
            )
        return result

    def propose_actions(self, mission_id: str, result: DecisionResult) -> list[ActionProposal]:
        """Schedule approved proposals and persist them."""
        scheduled = self._engine.propose_actions(mission_id, result)
        mission = self._engine.get_mission(mission_id)
        self._persist_graph(mission)
        for proposal in scheduled:
            self._publish(
                "mission.action.approved",
                {
                    "mission_id": mission_id,
                    "action_id": proposal.action.action_id,
                    "capability": proposal.action.capability,
                },
            )
        return scheduled

    def approve_action(self, mission_id: str, action_id: str) -> ActionNode:
        """Approve a proposed action (publishes ``mission.action.approved``)."""
        action = self._engine.approve_action(mission_id, action_id)
        self._persist_action(mission_id, action)
        self._publish(
            "mission.action.approved",
            {"mission_id": mission_id, "action_id": action_id, "capability": action.capability},
        )
        return action

    def select_tool(self, mission_id: str, action_id: str) -> ToolSelection:
        """Select a tool for an action and persist the selection."""
        selection = self._engine.select_tool(mission_id, action_id)
        action = self._engine.get_action(mission_id, action_id)
        self._persist_action(mission_id, action)
        self._persist_selection(mission_id, selection)
        return selection

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
        """Record a classified failure (publishes ``mission.action.failed``)."""
        record = self._engine.record_failure(
            mission_id,
            action_id,
            tool_id=tool_id,
            error=error,
            timeout=timeout,
            exit_code=exit_code,
        )
        self._persist_failure(mission_id, record)
        self._publish(
            "mission.action.failed",
            {
                "mission_id": mission_id,
                "action_id": action_id,
                "tool_id": tool_id,
                "failure_class": record.failure_class.value,
                "management": record.management.value,
            },
        )
        return record

    def fallback_tool(self, mission_id: str, action_id: str, *, primary_tool: str, capability: str) -> ToolFallbackRecord | None:
        """Resolve and persist a capability-equivalent tool fallback."""
        fallback = self._engine.fallback_tool(
            mission_id,
            action_id,
            primary_tool=primary_tool,
            capability=capability,
        )
        if fallback is not None:
            self._persist_fallback(mission_id, fallback)
        return fallback

    # -- attack paths -------------------------------------------------------

    def discover_attack_paths(
        self,
        mission_id: str,
        surface: Any | None = None,
        *,
        evidence_map: dict[str, list[str]] | None = None,
        validated_map: dict[str, bool] | None = None,
    ) -> list[AttackPath]:
        """Discover and persist attack paths (intelligence only)."""
        paths = self._engine.discover_attack_paths(
            mission_id,
            surface,
            evidence_map=evidence_map,
            validated_map=validated_map,
        )
        self._persist_paths(mission_id, paths)
        self._publish(
            "mission.path.discovered",
            {"mission_id": mission_id, "path_count": len(paths)},
        )
        return paths

    def attack_paths(self, mission_id: str) -> list[AttackPath]:
        """Return attack paths for a mission."""
        return self._engine.attack_paths_for(mission_id)

    def reassess_paths(
        self,
        mission_id: str,
        *,
        evidence_map: dict[str, list[str]],
        validated_map: dict[str, bool],
        proved_map: dict[str, bool],
    ) -> list[AttackPath]:
        """Recompute attack-path validation states from current evidence."""
        return self._engine.reassess_paths(
            mission_id,
            evidence_map=evidence_map,
            validated_map=validated_map,
            proved_map=proved_map,
        )

    # -- gaps & explainability ----------------------------------------------

    def evidence_gaps(self, mission_id: str) -> list[Gap]:
        """Return open evidence gaps."""
        return self._engine.evidence_gaps(mission_id)

    def record_gap(self, mission_id: str, gap: Gap) -> Gap:
        """Record an open evidence/proof gap."""
        return self._engine.record_gap(mission_id, gap)

    def proof_gaps(self, mission_id: str) -> list[Gap]:
        """Return open proof gaps."""
        return self._engine.proof_gaps(mission_id)

    def decision_explanation(self, mission_id: str, action_id: str = "") -> dict[str, Any] | None:
        """Return the explainable decision record for an action."""
        record = self._engine.decision_explanation(mission_id, action_id)
        return record.to_dict() if record else None

    def explain_next(self, mission_id: str) -> dict[str, Any]:
        """Explain why the highest-ranked candidate action is next."""
        return self._engine.explain_next_action(mission_id)

    # -- checkpoints --------------------------------------------------------

    def checkpoint_create(
        self,
        mission_id: str,
        *,
        observations: tuple[str, ...] = (),
        evidence: tuple[str, ...] = (),
        hypotheses: tuple[str, ...] = (),
    ) -> PlanCheckpoint:
        """Snapshot the mission (publishes ``mission.checkpoint.created``)."""
        checkpoint = self._engine.create_checkpoint(
            mission_id,
            observations=observations,
            evidence=evidence,
            hypotheses=hypotheses,
        )
        self._persist_checkpoint(mission_id, checkpoint)
        self._publish(
            "mission.checkpoint.created",
            {
                "mission_id": mission_id,
                "checkpoint_id": checkpoint.checkpoint_id,
                "plan_version": checkpoint.plan_version,
                "completed_actions": list(checkpoint.completed_actions),
            },
        )
        return checkpoint

    def resume_from_checkpoint(self, mission_id: str, checkpoint_id: str) -> AdaptiveMission:
        """Restore a mission from a persisted checkpoint."""
        checkpoint = self._load_checkpoint(mission_id, checkpoint_id)
        mission = self._engine.resume_from_checkpoint(mission_id, checkpoint)
        self._persist_mission(mission)
        self._publish("mission.resumed", {"mission_id": mission_id, "checkpoint_id": checkpoint_id})
        return mission

    # -- coverage -----------------------------------------------------------

    def coverage(self, mission_id: str) -> dict[str, Any]:
        """Return a JSON-safe coverage view of the mission plan."""
        mission = self._engine.get_mission(mission_id)
        actions = mission.graph.actions.values()
        by_capability: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for action in actions:
            by_capability[action.capability] = by_capability.get(action.capability, 0) + 1
            by_status[action.status.value] = by_status.get(action.status.value, 0) + 1
        return {
            "mission_id": mission_id,
            "action_count": len(actions),
            "completed_actions": len(mission.completed_actions()),
            "progress": mission.progress(),
            "by_capability": by_capability,
            "by_status": by_status,
            "plan_version": mission.plan_version,
        }

    # -- persistence helpers ------------------------------------------------

    def _persist_mission(self, mission: AdaptiveMission) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptiveMissionRecord)
        repo.save(
            AdaptiveMissionRecord(
                id=mission.mission_id,
                mission_id=mission.mission_id,
                objective=mission.objective.value,
                mode=mission.mode.value,
                state=mission.state.value,
                plan_version=mission.plan_version,
                progress=mission.progress(),
                authorization_context=mission.authorization_context,
                safety_ceiling=mission.safety_ceiling,
                tenant=mission.tenant,
                target=mission.constraints.included_targets[0] if mission.constraints.included_targets else "",
            )
        )

    def _persist_graph(self, mission: AdaptiveMission) -> None:
        if self._stores is None:
            return
        for action in mission.graph.actions.values():
            self._persist_action(mission.mission_id, action)
        repo = self._stores.repository_for(AdaptiveDependencyRecord)
        for dep in mission.graph.dependencies.values():
            repo.save(
                AdaptiveDependencyRecord(
                    id=dep.dependency_id,
                    dependency_id=dep.dependency_id,
                    mission_id=mission.mission_id,
                    source_action_id=dep.source_action_id,
                    target_action_id=dep.target_action_id,
                    kind=dep.kind.value,
                    rationale=dep.rationale,
                )
            )
        branch_repo = self._stores.repository_for(AdaptiveBranchRecord)
        for branch in mission.graph.branches.values():
            branch_repo.save(_branch_to_record(mission.mission_id, branch))

    def _persist_action(self, mission_id: str, action: ActionNode) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptiveActionNodeRecord)
        repo.save(
            AdaptiveActionNodeRecord(
                id=action.action_id,
                action_id=action.action_id,
                mission_id=mission_id,
                action_type=action.action_type.value,
                asset=action.asset,
                capability=action.capability,
                selected_tool=action.selected_tool,
                tool_candidates=list(action.tool_candidate_set),
                hypothesis_id=action.hypothesis_id,
                expected_information_gain=action.expected_information_gain,
                expected_proof_value=action.expected_proof_value,
                risk=action.risk,
                cost=action.cost,
                timeout_seconds=action.timeout_seconds,
                validation_level=action.validation_level.value,
                status=action.status.value,
                priority=action.priority,
                depends_on=list(action.depends_on),
                provenance=action.provenance,
            )
        )

    def _persist_version(self, mission: AdaptiveMission, version: PlanVersion) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptivePlanVersionRecord)
        repo.save(
            AdaptivePlanVersionRecord(
                mission_id=mission.mission_id,
                plan_version=version.plan_version,
                parent_version=version.parent_version,
                reason=version.reason,
                trigger=version.trigger.value if version.trigger else "",
                changed_nodes=list(version.changed_nodes),
                changed_dependencies=list(version.changed_dependencies),
                created_by=version.created_by,
                decision_provenance=version.decision_provenance,
            )
        )

    def _persist_delta(self, mission: AdaptiveMission, delta: PlanDelta) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptivePlanDeltaRecord)
        repo.save(
            AdaptivePlanDeltaRecord(
                id=delta.delta_id,
                delta_id=delta.delta_id,
                mission_id=mission.mission_id,
                plan_version=delta.plan_version,
                parent_version=delta.parent_version,
                trigger=delta.trigger.value if delta.trigger else "",
                reason=delta.reason,
                changes=[change.to_dict() for change in delta.changes],
                decision_provenance=delta.decision_provenance,
            )
        )

    def _persist_paths(self, mission_id: str, paths: list[AttackPath]) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptiveAttackPathRecord)
        for path in paths:
            repo.save(_path_to_record(mission_id, path))

    def _persist_selection(self, mission_id: str, selection: ToolSelection) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptiveToolSelectionRecord)
        repo.save(
            AdaptiveToolSelectionRecord(
                id=selection.selection_id,
                selection_id=selection.selection_id,
                mission_id=mission_id,
                action_id=selection.action_id,
                capability=selection.capability,
                tool_id=selection.tool_id,
                alternatives=list(selection.alternatives),
                score=selection.score,
                reasons=list(selection.reasons),
                expected_evidence=list(selection.expected_evidence),
                expected_proof_value=selection.expected_proof_value,
                risk=selection.risk,
                cost=selection.cost,
            )
        )

    def _persist_failure(self, mission_id: str, record: FailureRecord) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptiveFailureRecord)
        repo.save(
            AdaptiveFailureRecord(
                id=record.failure_id,
                failure_id=record.failure_id,
                mission_id=mission_id,
                action_id=record.action_id,
                tool_id=record.tool_id,
                failure_class=record.failure_class.value,
                management=record.management.value,
                error=record.error,
                retries=record.retries,
            )
        )

    def _persist_fallback(self, mission_id: str, record: ToolFallbackRecord) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptiveToolFallbackRecord)
        repo.save(
            AdaptiveToolFallbackRecord(
                id=record.fallback_id,
                fallback_id=record.fallback_id,
                mission_id=mission_id,
                action_id=record.action_id,
                primary_tool=record.primary_tool,
                fallback_tool=record.fallback_tool,
                capability=record.capability,
                reason=record.reason,
            )
        )

    def _persist_checkpoint(self, mission_id: str, checkpoint: PlanCheckpoint) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(AdaptivePlanCheckpointRecord)
        repo.save(
            AdaptivePlanCheckpointRecord(
                id=checkpoint.checkpoint_id,
                checkpoint_id=checkpoint.checkpoint_id,
                mission_id=mission_id,
                plan_version=checkpoint.plan_version,
                mission_state=checkpoint.mission_state.value,
                completed_actions=list(checkpoint.completed_actions),
                pending_actions=list(checkpoint.pending_actions),
                observations=list(checkpoint.observations),
                evidence=list(checkpoint.evidence),
                hypotheses=list(checkpoint.hypotheses),
                proof_states=checkpoint.proof_states,
                tool_state=checkpoint.tool_state,
            )
        )

    def _load_checkpoint(self, mission_id: str, checkpoint_id: str) -> PlanCheckpoint:
        if self._stores is None:
            for checkpoint in self._engine.get_mission(mission_id).checkpoints:
                if checkpoint.checkpoint_id == checkpoint_id:
                    return checkpoint
            from hunterx.domain.exceptions.adaptive_mission_planning import AdaptiveMissionNotFoundError

            raise AdaptiveMissionNotFoundError(checkpoint_id)
        repo = self._stores.repository_for(AdaptivePlanCheckpointRecord)
        record = repo.get(checkpoint_id)
        if record is None:
            from hunterx.domain.exceptions.adaptive_mission_planning import AdaptiveMissionNotFoundError

            raise AdaptiveMissionNotFoundError(checkpoint_id)
        return _checkpoint_from_record(record)

    def _publish(self, event_type: str, payload: dict[str, object]) -> None:
        if self._event_bus is None:
            return
        from hunterx.domain.events import DomainEvent

        self._event_bus.publish(
            DomainEvent(
                event_type=event_type,
                payload=payload,
                source="application.adaptive_mission_planning",
            )
        )


class AdaptiveMissionPlanningQueryService:
    """Read persisted adaptive mission planning records from the TIDB."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache

    def mission_records(self, *, limit: int = 100, offset: int = 0) -> list[AdaptiveMissionRecord]:
        """Return persisted mission records."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptiveMissionRecord)
        return list(repo.list(limit=limit, offset=offset))

    def mission(self, mission_id: str) -> AdaptiveMissionRecord | None:
        """Return a persisted mission record by mission id."""
        if self._stores is None:
            return None
        repo = self._stores.repository_for(AdaptiveMissionRecord)
        for record in repo.list(limit=1000):
            if getattr(record, "mission_id", "") == mission_id:
                return record  # type: ignore[no-any-return]  # repo is generic over entity type
        return None

    def actions(self, mission_id: str) -> list[AdaptiveActionNodeRecord]:
        """Return persisted action node records for a mission."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptiveActionNodeRecord)
        return [record for record in repo.list(limit=5000) if record.mission_id == mission_id]

    def plan_versions(self, mission_id: str) -> list[AdaptivePlanVersionRecord]:
        """Return persisted plan version records for a mission."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptivePlanVersionRecord)
        return [record for record in repo.list(limit=5000) if record.mission_id == mission_id]

    def attack_paths(self, mission_id: str) -> list[AdaptiveAttackPathRecord]:
        """Return persisted attack path records for a mission."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptiveAttackPathRecord)
        return [record for record in repo.list(limit=5000) if record.mission_id == mission_id]

    def decisions(self, mission_id: str) -> list[AdaptiveDecisionRecord]:
        """Return persisted decision records for a mission."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptiveDecisionRecord)
        return [record for record in repo.list(limit=5000) if record.mission_id == mission_id]

    def gaps(self, mission_id: str) -> list[AdaptiveGapRecord]:
        """Return persisted gap records for a mission."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptiveGapRecord)
        return [record for record in repo.list(limit=5000) if record.mission_id == mission_id]

    def checkpoints(self, mission_id: str) -> list[AdaptivePlanCheckpointRecord]:
        """Return persisted checkpoint records for a mission."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptivePlanCheckpointRecord)
        return [record for record in repo.list(limit=5000) if record.mission_id == mission_id]

    def failures(self, mission_id: str) -> list[AdaptiveFailureRecord]:
        """Return persisted failure records for a mission."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(AdaptiveFailureRecord)
        return [record for record in repo.list(limit=5000) if record.mission_id == mission_id]


def _branch_to_record(mission_id: str, branch: ConditionalBranch) -> AdaptiveBranchRecord:
    return AdaptiveBranchRecord(
        id=branch.branch_id,
        branch_id=branch.branch_id,
        mission_id=mission_id,
        kind=branch.kind.value,
        condition=branch.condition,
        then_action_ids=list(branch.then_action_ids),
        else_action_ids=list(branch.else_action_ids),
        goto_action_id=branch.goto_action_id,
        wait_for_evidence=branch.wait_for_evidence,
        rationale=branch.rationale,
    )


def _path_to_record(mission_id: str, path: AttackPath) -> AdaptiveAttackPathRecord:
    return AdaptiveAttackPathRecord(
        id=path.path_id,
        path_id=path.path_id,
        mission_id=mission_id,
        objective=path.objective.value,
        state=path.state.value,
        score=path.score,
        scores=path.scores,
        steps=[step.to_dict() for step in path.steps],
        evidence_refs=list(path.evidence_refs),
        assumptions=list(path.assumptions),
    )


def _checkpoint_from_record(record: AdaptivePlanCheckpointRecord) -> PlanCheckpoint:
    return PlanCheckpoint(
        checkpoint_id=record.checkpoint_id,
        mission_id=record.mission_id,
        plan_version=record.plan_version,
        mission_state=MissionState(record.mission_state),
        completed_actions=tuple(record.completed_actions),
        pending_actions=tuple(record.pending_actions),
        observations=tuple(record.observations),
        evidence=tuple(record.evidence),
        hypotheses=tuple(record.hypotheses),
        proof_states=record.proof_states,
        tool_state=record.tool_state,
    )
