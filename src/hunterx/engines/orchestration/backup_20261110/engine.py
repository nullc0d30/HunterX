# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive Tool Orchestration engine (composition root).

Wires the mission lifecycle, planner, executor, scope guard, safety enforcer,
tool selector, retry/fallback/dedup/rate-limit engines, checkpoints, mission
memory, replanning, coverage, quality and events into one entry point that can
run a complete authorized security mission.

The engine transforms a mission objective into: scope resolution → planning →
capability-driven tool selection → adaptive execution → intelligence feedback
→ replanning → coverage/quality evaluation → reporting.

Persistence is provided through repository ports and a TIDB repository factory;
the engine never talks to a database directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.exceptions.orchestration import (
    ExecutionPlanNotFoundError,
    InvalidMissionStateError,
    OffensiveMissionNotFoundError,
)
from hunterx.domain.orchestration.enums import MissionState
from hunterx.domain.orchestration.models import ExecutionPlan, OffensiveMission, Policies
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.orchestration import (
    ExecutionPlanRepository,
    OffensiveMissionRepository,
)
from hunterx.domain.ports.stores import KnowledgeGraphPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.ports.tool_intelligence import ToolIntelligencePort
from hunterx.engines.orchestration.checkpoints import MissionCheckpoint, MissionCheckpointManager
from hunterx.engines.orchestration.coverage import CoverageModel, CoverageReport
from hunterx.engines.orchestration.dedup import ExecutionDeduplicator
from hunterx.engines.orchestration.events import MissionEventEmitter
from hunterx.engines.orchestration.executor import MissionExecutor, MissionRunResult
from hunterx.engines.orchestration.lifecycle import MissionLifecycle, MissionLifecycleOperator
from hunterx.engines.orchestration.memory import MissionMemoryStore
from hunterx.engines.orchestration.planner import IntelligenceSummary, MissionPlanner
from hunterx.engines.orchestration.quality import MissionQuality, MissionQualityScorer
from hunterx.engines.orchestration.replan import (
    DiscoveredAsset,
    ReplanDecision,
    ReplanningEngine,
    ReplanRequest,
)
from hunterx.engines.orchestration.scope import MissionScopeGuard
from hunterx.shared.ids import generate_id
from hunterx.shared.result import Failure, Result, Success
from hunterx.tools.sdk.engine import ExecutionEngine


@dataclass(frozen=True, slots=True)
class MissionRun:
    """The outcome of orchestrating a full mission run.

    Attributes:
        mission: the mission (with its final lifecycle state).
        plan: the execution plan that ran.
        run: the executor run result.
        coverage: the computed coverage report.
        quality: the computed mission quality score.
        checkpoint: the final checkpoint (when created).

    """

    mission: OffensiveMission
    plan: ExecutionPlan
    run: MissionRunResult
    coverage: CoverageReport | None = None
    quality: MissionQuality | None = None
    checkpoint: MissionCheckpoint | None = None


class OffensiveOrchestrationEngine:
    """Composition root of the offensive orchestration layer.

    Usage::

        engine = OffensiveOrchestrationEngine(
            missions=missions_repo, plans=plans_repo, execution_engine=engine, tip=tip,
        )
        mission = engine.create_mission(objective="assess example.com", mission_type=...)
        result = engine.run_mission(mission.mission_id, targets=["example.com"])
    """

    def __init__(
        self,
        missions: OffensiveMissionRepository | None = None,
        plans: ExecutionPlanRepository | None = None,
        execution_engine: ExecutionEngine | None = None,
        tip: ToolIntelligencePort | None = None,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        knowledge_graph: KnowledgeGraphPort | None = None,
        *,
        lifecycle: MissionLifecycle | None = None,
        planner: MissionPlanner | None = None,
        executor: MissionExecutor | None = None,
        checkpoints: MissionCheckpointManager | None = None,
        memory: MissionMemoryStore | None = None,
        replanning: ReplanningEngine | None = None,
        coverage: CoverageModel | None = None,
        quality: MissionQualityScorer | None = None,
        emitter: MissionEventEmitter | None = None,
        freshness_window_seconds: int = 0,
    ) -> None:
        from hunterx.infrastructure.memory.orchestration import (
            InMemoryExecutionPlanRepository,
            InMemoryOffensiveMissionRepository,
        )

        self._missions = missions or InMemoryOffensiveMissionRepository()
        self._plans = plans or InMemoryExecutionPlanRepository()
        self._stores = stores
        self._knowledge_graph = knowledge_graph
        self._lifecycle = lifecycle or MissionLifecycle()
        self._operator = MissionLifecycleOperator(self._lifecycle)
        self._planner = planner or MissionPlanner()
        self._emitter = emitter or MissionEventEmitter(event_bus)
        self._executor = executor or MissionExecutor(
            engine=execution_engine,
            tip=tip,
            deduplicator=ExecutionDeduplicator(freshness_window_seconds=freshness_window_seconds),
            freshness_window_seconds=freshness_window_seconds,
        )
        self._checkpoints = checkpoints or MissionCheckpointManager()
        self._memory = memory or MissionMemoryStore()
        self._replanning = replanning or ReplanningEngine()
        self._coverage = coverage or CoverageModel()
        self._quality = quality or MissionQualityScorer()

    # -- mission lifecycle ---------------------------------------------------

    def create_mission(
        self,
        *,
        objective: str,
        mission_type: Any,
        scope: Any = None,
        policies: Policies | None = None,
        targets: tuple[str, ...] = (),
        exclusions: tuple[str, ...] = (),
        authorization: Any = None,
        priority: str = "medium",
        mission_id: str | None = None,
    ) -> Result[OffensiveMission, Exception]:
        """Create a mission in the CREATED state."""
        from hunterx.domain.orchestration.models import (
            Authorization,
            MissionScope,
            TargetSet,
        )

        mission_type = _coerce_mission_type(mission_type)
        mission = OffensiveMission(
            mission_id=mission_id or generate_id(),
            mission_type=mission_type,
            objective=objective,
            scope=scope or MissionScope(roots=tuple(targets)),
            exclusions=tuple(exclusions),
            authorization=authorization or Authorization(),
            priority=priority,
            policies=policies or Policies(),
            target_set=TargetSet(targets=tuple(targets)),
            state=MissionState.CREATED,
        )
        try:
            self._missions.save(mission)
            self._emitter.scoping_started(mission.mission_id, mission_type=mission.mission_type.value)
            self._emitter.scoping_completed(mission.mission_id, roots=list(mission.scope.roots), excludes=list(mission.exclusions))
        except Exception as exc:  # noqa: BLE001 - surfaced as a result
            return Failure(exc)
        return Success(mission)

    def scope_mission(self, mission_id: str, *, scope: Any = None) -> Result[OffensiveMission, Exception]:
        """Resolve the mission scope and move to SCOPING → PLANNING."""
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(OffensiveMissionNotFoundError(mission_id))
        try:
            new_state = self._operator.scope(mission.state)
            mission = _with_state(mission, new_state)
            if scope is not None:
                from dataclasses import replace

                mission = replace(mission, scope=scope)
            self._missions.save(mission)
            self._emitter.scoping_completed(mission.mission_id, roots=list(mission.scope.roots), excludes=list(mission.exclusions))
        except Exception as exc:  # noqa: BLE001
            return Failure(exc)
        return Success(mission)

    def plan_mission(
        self,
        mission_id: str,
        *,
        intelligence: IntelligenceSummary | None = None,
    ) -> Result[ExecutionPlan, Exception]:
        """Plan a mission into an :class:`ExecutionPlan` (CREATED→SCOPING→PLANNING→READY)."""
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(OffensiveMissionNotFoundError(mission_id))
        try:
            if mission.state is MissionState.CREATED:
                mission = _with_state(mission, self._operator.scope(mission.state))
                self._emitter.scoping_completed(mission.mission_id, roots=list(mission.scope.roots), excludes=list(mission.exclusions))
            self._operator.plan(mission.state)
            mission = _with_state(mission, MissionState.PLANNING)
            self._emitter.planning_started(mission.mission_id, objective=mission.objective)
            summary = intelligence or self._summary_from_mission(mission)
            plan = self._planner.plan(
                mission_id=mission.mission_id,
                objective=mission.objective,
                intelligence=summary,
                scope=mission.scope,
                policies=mission.policies,
            )
            self._operator.ready(mission.state)
            mission = _with_state(mission, MissionState.READY, plan_id=plan.plan_id)
            self._missions.save(mission)
            self._plans.save(plan)
            self._emitter.plan_created(mission.mission_id, plan.plan_id, phases=len(plan.phases), steps=plan.total_steps(), version=plan.version)
            self._update_graph(mission, plan)
        except Exception as exc:  # noqa: BLE001
            return Failure(exc)
        return Success(plan)

    def run_mission(
        self,
        mission_id: str,
        *,
        tool_outputs: dict[str, dict[str, Any]] | None = None,
        stop_check: Any = None,
        checkpoint_after_steps: int = 0,
    ) -> Result[MissionRun, Exception]:
        """Run a ready mission end to end and return the aggregate outcome.

        Args:
            mission_id: the mission to run.
            tool_outputs: pre-normalized outputs keyed by step id (deterministic).
            stop_check: callable returning a stop reason when triggered.
            checkpoint_after_steps: create a checkpoint after this many steps
                (``0`` = disabled).

        """
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(OffensiveMissionNotFoundError(mission_id))
        if mission.plan_id is None:
            return Failure(InvalidMissionStateError("mission has not been planned"))
        plan = self._plans.get(mission.plan_id)
        if plan is None:
            return Failure(ExecutionPlanNotFoundError(mission.plan_id))
        try:
            self._operator.start(mission.state)
            mission = _with_state(mission, MissionState.RUNNING, started_at=True)
            self._missions.save(mission)

            run = self._executor.run(mission_id=mission_id, plan=plan, tool_outputs=tool_outputs, stop_check=stop_check)

            coverage = self._coverage.from_run(mission_id=mission_id, plan=plan, run=run)
            self._emitter.coverage_computed(mission_id, plan.plan_id, coverage=coverage.to_dict())

            quality = self._quality.score(
                mission_id=mission_id,
                plan_id=plan.plan_id,
                coverage=coverage,
                run=run,
                executed_steps=len(run.completed),
                total_steps=plan.total_steps(),
                failed_steps=len(run.failed),
                tool_successes=len([o for o in run.outcomes.values() if o.ok]),
                tool_attempts=max(1, len(run.outcomes)),
            )
            self._emitter.quality_computed(mission_id, plan.plan_id, score=quality.score)

            if checkpoint_after_steps > 0 and len(run.completed) >= checkpoint_after_steps:
                checkpoint = self._checkpoints.create(
                    mission_id=mission_id,
                    plan_id=plan.plan_id,
                    mission_state=MissionState.RUNNING.value,
                    plan_version=plan.version,
                    completed_steps=run.completed,
                    pending_steps=[step.step_id for step in plan.steps() if step.step_id not in run.completed and step.step_id not in run.failed and step.step_id not in run.blocked],
                    failed_steps=run.failed,
                    blocked_steps=run.blocked,
                    records=self._executor.records(),
                )
                self._emitter.checkpoint_created(mission_id, plan.plan_id, checkpoint.checkpoint_id, label="auto", completed_steps=run.completed)
            else:
                checkpoint = None

            for outcome in run.outcomes.values():
                if outcome.tool_id:
                    self._memory.update_from_outcome(mission_id=mission_id, target=outcome.tool_id, outcome=outcome)

            self._persist_records(mission_id, plan, run)

            if run.all_completed:
                mission = _with_state(mission, MissionState.COMPLETED, completed_at=True)
            elif run.failed and not run.blocked:
                mission = _with_state(mission, MissionState.FAILED, completed_at=True)
            else:
                mission = _with_state(mission, MissionState.PARTIAL, completed_at=True)
                self._emitter.partial(mission_id, plan.plan_id, gaps=run.gaps)
            self._missions.save(mission)

            return Success(
                MissionRun(
                    mission=mission,
                    plan=plan,
                    run=run,
                    coverage=coverage,
                    quality=quality,
                    checkpoint=checkpoint,
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a result
            try:
                mission = _with_state(self._missions.get(mission_id) or mission, MissionState.FAILED, completed_at=True)
                self._missions.save(mission)
            except Exception:  # noqa: BLE001 - best effort; nosec B110
                pass
            return Failure(exc)

    def pause_mission(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Pause a running mission."""
        return self._transition(mission_id, self._operator.pause)

    def resume_mission(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Resume a paused/waiting/replanning/blocked mission."""
        return self._transition(mission_id, self._operator.resume)

    def wait_mission(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Move a running mission into WAITING."""
        return self._transition(mission_id, self._operator.wait)

    def block_mission(self, mission_id: str, reason: str) -> Result[OffensiveMission, Exception]:
        """Block a running mission with a reason."""
        result = self._transition(mission_id, self._operator.block)
        if isinstance(result, Success):
            self._emitter.blocked(mission_id, result.value.plan_id or "", reason)
        return result

    def cancel_mission(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Cancel a mission from any active state."""
        return self._transition(mission_id, self._operator.cancel)

    def complete_mission(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Complete a mission."""
        return self._transition(mission_id, self._operator.complete)

    def fail_mission(self, mission_id: str, error: str) -> Result[OffensiveMission, Exception]:
        """Fail a mission from any active state."""
        result = self._transition(mission_id, self._operator.fail)
        if result.ok:
            self._persist_failure(mission_id, error)
        return result

    def replan_mission(
        self,
        mission_id: str,
        *,
        reason: str = "",
        discovered_assets: list[DiscoveredAsset] | None = None,
        new_technologies: list[str] | None = None,
        new_endpoints: list[str] | None = None,
        new_providers: list[str] | None = None,
    ) -> Result[ReplanDecision, Exception]:
        """Evaluate a replanning request and regenerate the plan when needed.

        Replanning never expands scope: newly discovered assets are classified
        and only in-scope assets continue automatically.
        """
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(OffensiveMissionNotFoundError(mission_id))
        try:
            guard = MissionScopeGuard(mission.scope)
            engine = ReplanningEngine(guard)
            decision = engine.evaluate(
                ReplanRequest(
                    mission_id=mission_id,
                    plan_id=mission.plan_id or "",
                    reason=reason,
                    discovered_assets=discovered_assets or [],
                    new_technologies=new_technologies or [],
                    new_endpoints=new_endpoints or [],
                    new_providers=new_providers or [],
                )
            )
            if decision.replan_needed:
                self._emitter.replanning_started(mission_id, mission.plan_id or "", reason=decision.reason)
                # Replanning is evaluated regardless of lifecycle state; the
                # REPLANNING lifecycle state is only entered from RUNNING.
                if self._lifecycle.can_transition(mission.state, MissionState.REPLANNING):
                    mission = _with_state(mission, self._operator.replan(mission.state))
                    self._missions.save(mission)
            return Success(decision)
        except Exception as exc:  # noqa: BLE001
            return Failure(exc)

    # -- queries -------------------------------------------------------------

    def get_mission(self, mission_id: str) -> OffensiveMission | None:
        """Return a mission by identifier."""
        return self._missions.get(mission_id)

    def get_plan(self, plan_id: str) -> ExecutionPlan | None:
        """Return a plan by identifier."""
        return self._plans.get(plan_id)

    def list_missions(self, *, limit: int = 100, offset: int = 0) -> list[OffensiveMission]:
        """Return a page of missions."""
        return list(self._missions.list(limit=limit, offset=offset))

    def list_by_state(self, state: MissionState | str) -> list[OffensiveMission]:
        """Return missions in a lifecycle state."""
        value = state.value if isinstance(state, MissionState) else state
        return list(self._missions.list_by_state(value))

    def checkpoint(self, mission_id: str, *, label: str = "") -> Result[MissionCheckpoint, Exception]:
        """Create a checkpoint for a mission's latest plan."""
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(OffensiveMissionNotFoundError(mission_id))
        if mission.plan_id is None:
            return Failure(InvalidMissionStateError("mission has not been planned"))
        plan = self._plans.get(mission.plan_id)
        if plan is None:
            return Failure(ExecutionPlanNotFoundError(mission.plan_id))
        checkpoint = self._checkpoints.create(
            mission_id=mission_id,
            plan_id=mission.plan_id,
            mission_state=mission.state.value,
            plan_version=plan.version,
            label=label,
            pending_steps=[step.step_id for step in plan.steps()],
        )
        self._emitter.checkpoint_created(mission_id, mission.plan_id, checkpoint.checkpoint_id, label=label)
        return Success(checkpoint)

    def memory(self, *, mission_id: str = "", target: str = "") -> Any:
        """Return target mission memory."""
        if target:
            return self._memory.memory(mission_id=mission_id, target=target)
        return self._memory

    def engine(self) -> Any:
        """Return the internal mission executor (advanced use)."""
        return self._executor

    # -- helpers -------------------------------------------------------------

    def _transition(self, mission_id: str, operation: Any) -> Result[OffensiveMission, Exception]:
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(OffensiveMissionNotFoundError(mission_id))
        try:
            new_state = operation(mission.state)
            mission = _with_state(mission, new_state)
            self._missions.save(mission)
        except Exception as exc:  # noqa: BLE001
            return Failure(exc)
        return Success(mission)

    def _summary_from_mission(self, mission: OffensiveMission) -> IntelligenceSummary:
        return IntelligenceSummary(
            mission_type=mission.mission_type,
            targets=tuple(mission.target_set.targets),
            scope=mission.scope,
        )

    def _persist_records(self, mission_id: str, plan: ExecutionPlan, run: MissionRunResult) -> None:
        if self._stores is None:
            return
        records = self._executor.records()
        try:
            from hunterx.domain.entities.tidb.orchestration import (
                ExecutionPolicyDecision as TidbExecutionPolicyDecision,
            )
            from hunterx.domain.entities.tidb.orchestration import (
                MissionFailure as TidbMissionFailure,
            )
            from hunterx.domain.entities.tidb.orchestration import (
                MissionPlanRecord,
                MissionStepRecord,
                ToolSelectionRecord,
            )
            from hunterx.domain.entities.tidb.orchestration import (
                MissionTaskHistory as TidbMissionTaskHistory,
            )
            from hunterx.domain.entities.tidb.orchestration import (
                ToolFallback as TidbToolFallback,
            )

            self._stores.repository_for(MissionPlanRecord).save(
                MissionPlanRecord(
                    plan_id=plan.plan_id,
                    mission_id=mission_id,
                    plan_version=plan.version,
                    objective=plan.objective,
                    state="executed",
                    scope=plan.scope.to_dict(),
                    policies=plan.policies.to_dict(),
                )
            )
            for phase in plan.phases:
                for step in phase.steps:
                    self._stores.repository_for(MissionStepRecord).save(
                        MissionStepRecord(
                            step_id=step.step_id,
                            plan_id=plan.plan_id,
                            phase_id=step.phase_id,
                            action=step.action,
                            capability=step.capability,
                            tool_id=step.tool_id,
                            target=step.target,
                            target_type=step.target_type,
                            parameters=dict(step.parameters),
                            depends_on=list(step.depends_on),
                            condition=step.condition,
                            safety_class=step.safety_class,
                        )
                    )
            for selection in records["selection"]:
                self._stores.repository_for(ToolSelectionRecord).save(
                    ToolSelectionRecord(
                        selection_id=generate_id(),
                        mission_id=_str_of(selection, "mission_id"),
                        plan_id=_str_of(selection, "plan_id"),
                        step_id=_str_of(selection, "step_id"),
                        capability=_str_of(selection, "capability"),
                        tool_id=_str_of(selection, "tool_id"),
                    )
                )
            for fallback in records["fallback"]:
                self._stores.repository_for(TidbToolFallback).save(
                    TidbToolFallback(
                        fallback_id=generate_id(),
                        mission_id=mission_id,
                        plan_id=plan.plan_id,
                        step_id=_str_of(fallback, "step_id"),
                        primary_tool=_str_of(fallback, "primary_tool"),
                        fallback_tool=_str_of(fallback, "fallback_tool"),
                        reason=_str_of(fallback, "reason"),
                    )
                )
            for decision in records["scope"] + records["safety"] + records["rate_limit"]:
                self._stores.repository_for(TidbExecutionPolicyDecision).save(
                    TidbExecutionPolicyDecision(
                        decision_id=generate_id(),
                        mission_id=_str_of(decision, "mission_id"),
                        plan_id=_str_of(decision, "plan_id"),
                        step_id=_str_of(decision, "step_id"),
                        target=_str_of(decision, "target"),
                        kind=_str_of(decision, "kind"),
                        allowed=_bool_of(decision, "allowed"),
                        reason=_str_of(decision, "reason"),
                        detail=_dict_of(decision, "detail"),
                    )
                )
            for outcome in run.outcomes.values():
                self._stores.repository_for(TidbMissionTaskHistory).save(
                    TidbMissionTaskHistory(
                        history_id=generate_id(),
                        mission_id=mission_id,
                        plan_id=plan.plan_id,
                        step_id=outcome.step_id,
                        execution_id=outcome.execution_id,
                        tool_id=outcome.tool_id,
                        target="",
                        state=outcome.state.value,
                        duration_ms=outcome.duration_ms,
                        error=outcome.error,
                    )
                )
                if not outcome.ok and outcome.failure_class.value:
                    self._stores.repository_for(TidbMissionFailure).save(
                        TidbMissionFailure(
                            failure_id=generate_id(),
                            mission_id=mission_id,
                            plan_id=plan.plan_id,
                            step_id=outcome.step_id,
                            execution_id=outcome.execution_id,
                            tool_id=outcome.tool_id,
                            target="",
                            failure_class=outcome.failure_class.value,
                            management="blocked" if outcome.state.value == "blocked" else "deferred",
                            error=outcome.error,
                        )
                    )
        except Exception:  # noqa: BLE001 - persistence must never break the mission
            return

    def _persist_failure(self, mission_id: str, error: str) -> None:
        if self._stores is None:
            return
        try:
            from hunterx.domain.entities.tidb.orchestration import MissionFailure

            self._stores.repository_for(MissionFailure).save(
                MissionFailure(
                    failure_id=generate_id(),
                    mission_id=mission_id,
                    error=error,
                    failure_class="permanent",
                    management="mission-fatal",
                )
            )
        except Exception:  # noqa: BLE001
            return

    def _update_graph(self, mission: OffensiveMission, plan: ExecutionPlan) -> None:
        if self._knowledge_graph is None:
            return
        try:
            self._knowledge_graph.upsert_node(
                mission.mission_id,
                labels=["OffensiveMission"],
                properties={
                    "mission_type": mission.mission_type.value,
                    "objective": mission.objective,
                    "state": mission.state.value,
                },
            )
            self._knowledge_graph.upsert_node(
                plan.plan_id,
                labels=["ExecutionPlan"],
                properties={"objective": plan.objective, "steps": plan.total_steps()},
            )
            self._knowledge_graph.upsert_relationship(
                "plans",
                mission.mission_id,
                plan.plan_id,
                properties={"version": plan.version},
            )
        except Exception:  # noqa: BLE001
            return


def _with_state(mission: OffensiveMission, state: MissionState, *, plan_id: str | None = None, started_at: bool = False, completed_at: bool = False) -> OffensiveMission:
    """Return a copy of ``mission`` with the new state and timestamps."""
    from dataclasses import replace

    from hunterx.shared.time import utcnow_iso

    changes: dict[str, Any] = {"state": state, "updated_at": utcnow_iso()}
    if plan_id is not None:
        changes["plan_id"] = plan_id
    if started_at and mission.started_at is None:
        changes["started_at"] = utcnow_iso()
    if completed_at:
        changes["completed_at"] = utcnow_iso()
    return replace(mission, **changes)


def _coerce_mission_type(value: Any) -> Any:
    from hunterx.domain.orchestration.enums import MissionType

    if isinstance(value, MissionType):
        return value
    try:
        return MissionType(value)
    except ValueError:
        return MissionType(str(value))


def _str_of(mapping: dict[str, object], key: str) -> str:
    """Return the string value of ``mapping[key]`` (or empty)."""
    value = mapping.get(key)
    return str(value) if value is not None else ""


def _bool_of(mapping: dict[str, object], key: str) -> bool:
    """Return the boolean value of ``mapping[key]`` (default False)."""
    value = mapping.get(key)
    return bool(value)


def _dict_of(mapping: dict[str, object], key: str) -> dict[str, object]:
    """Return the dict value of ``mapping[key]`` (default empty)."""
    value = mapping.get(key)
    return dict(value) if isinstance(value, dict) else {}
