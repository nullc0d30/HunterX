# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission planning engine.

Orchestrates the mission planning lifecycle: create → queue → plan → ready →
start → (pause / wait / retry) → complete / cancel / fail → archive. The
engine composes the profile engine, configuration resolver, planner, execution
graph builder, checkpoint manager, timeline recorder and state machine, and
persists every change through the plan repository port. No tool is executed.
"""

from __future__ import annotations

from hunterx.domain.events import DomainEvent
from hunterx.domain.exceptions import (
    InvalidStateTransitionError,
    MissionPlanningError,
    MissionPlanNotFoundError,
    MissionPlanValidationError,
)
from hunterx.domain.mission_planning import (
    Checkpoint,
    ExecutionGraph,
    MissionPlan,
    MissionPlanningStatus,
    MissionRequest,
    MissionTimelineEntry,
)
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)
from hunterx.engines.mission_planning.checkpoints import CheckpointManager
from hunterx.engines.mission_planning.config import ConfigurationResolver
from hunterx.engines.mission_planning.graph import ExecutionGraphBuilder
from hunterx.engines.mission_planning.planner import MissionPlanner
from hunterx.engines.mission_planning.profiles import MissionProfileEngine
from hunterx.engines.mission_planning.state import MissionPlanTransition
from hunterx.engines.mission_planning.timeline import (
    EVENT_CREATED,
    EVENT_PLANNED,
    MissionTimeline,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.result import Failure, Result, Success
from hunterx.shared.time import utcnow_iso

#: Canonical event types published to the event bus on lifecycle milestones.
_BUS_EVENTS: dict[MissionPlanningStatus, str] = {
    MissionPlanningStatus.EXECUTING: "mission.started",
    MissionPlanningStatus.COMPLETED: "mission.completed",
    MissionPlanningStatus.CANCELLED: "mission.cancelled",
    MissionPlanningStatus.FAILED: "mission.failed",
}


class MissionPlanningEngine:
    """Composition root for the mission planning subsystem.

    Every public operation returns a :class:`Result`; failures carry a
    :class:`HunterXError`-derived exception with code ``MISSION``.
    """

    def __init__(
        self,
        *,
        plans: MissionPlanRepository,
        profiles: MissionProfileRepository | None = None,
        templates: MissionTemplateRepository | None = None,
        checkpoints: CheckpointRepository | None = None,
        timeline_repository: MissionTimelineRepository | None = None,
        event_bus: EventBusPort | None = None,
        profile_engine: MissionProfileEngine | None = None,
        planner: MissionPlanner | None = None,
        resolver: ConfigurationResolver | None = None,
        transitions: MissionPlanTransition | None = None,
        graph_builder: ExecutionGraphBuilder | None = None,
    ) -> None:
        self._plans = plans
        self._profiles = profile_engine or MissionProfileEngine(
            profiles=profiles,
            templates=templates,
        )
        self._resolver = resolver or ConfigurationResolver()
        self._planner = planner or MissionPlanner(self._resolver)
        self._transitions = transitions or MissionPlanTransition()
        self._graph_builder = graph_builder or ExecutionGraphBuilder()
        self._checkpoints = CheckpointManager(checkpoints)
        self._timeline = MissionTimeline(timeline_repository)
        self._event_bus = event_bus

    # -- lifecycle ---------------------------------------------------------

    def create_mission(self, request: MissionRequest) -> Result[MissionPlan, Exception]:
        """Validate a request, create and enqueue a mission plan."""
        try:
            profile = self._profiles.resolve_profile(request.profile_id)
            if request.template_id is not None:
                self._profiles.resolve_template(request.template_id)
            plan = MissionPlan(
                mission_id=generate_id(),
                profile_id=request.profile_id,
                template_id=request.template_id,
                mission_type=request.mission_type,
                name=request.name,
                targets=request.targets,
                variables=dict(request.variables),
                config=dict(request.config),
                priority=request.priority,
            )
            errors = self._planner.validate(plan, profile)
            if errors:
                return Failure(
                    MissionPlanValidationError(
                        "mission request failed profile validation: " + "; ".join(errors),
                        errors=errors,
                    )
                )
            plan = self._transitions.queue(plan)
            self._plans.save(plan)
            self._timeline.record(
                plan.mission_id,
                EVENT_CREATED,
                plan_id=plan.plan_id,
                **{"status": "created"},
            )
            self._timeline.record_status(plan)
            return Success(plan)
        except MissionPlanningError as exc:
            return Failure(exc)

    def enqueue_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Transition a created plan into the queue."""
        return self._transition(plan_id, MissionPlanningStatus.QUEUED)

    def plan_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Expand a queued plan into phases/steps and mark it ready."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        try:
            plan = self._transitions.start_planning(plan)
            profile = self._profiles.resolve_profile(plan.profile_id)
            template = self._profiles.get_template(plan.template_id) if plan.template_id else None
            self._planner.expand(plan, profile, template)
            self._timeline.record(
                plan.mission_id,
                EVENT_PLANNED,
                plan_id=plan.plan_id,
                **{"phases": len(plan.phases), "steps": plan.total_steps},
            )
            plan = self._transitions.mark_ready(plan)
            self._plans.save(plan)
            self._timeline.record_status(plan)
            return Success(plan)
        except MissionPlanningError as exc:
            return Failure(exc)

    def start_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Begin executing a ready plan."""
        return self._transition(plan_id, MissionPlanningStatus.EXECUTING)

    def pause_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Pause an executing plan."""
        return self._transition(plan_id, MissionPlanningStatus.PAUSED)

    def resume_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Resume a paused plan."""
        return self._transition(plan_id, MissionPlanningStatus.EXECUTING)

    def wait_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Hold an executing plan (e.g. awaiting approval)."""
        return self._transition(plan_id, MissionPlanningStatus.WAITING)

    def unwait_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Return a waiting plan to execution."""
        return self._transition(plan_id, MissionPlanningStatus.EXECUTING)

    def retry_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Enter the retrying state after a transient failure."""
        return self._transition(plan_id, MissionPlanningStatus.RETRYING)

    def resume_retry(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Resume execution after a retry is scheduled."""
        return self._transition(plan_id, MissionPlanningStatus.EXECUTING)

    def complete_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Mark an executing plan completed."""
        return self._transition(plan_id, MissionPlanningStatus.COMPLETED)

    def cancel_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Cancel a plan from any active state."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        return self._transition(plan_id, MissionPlanningStatus.CANCELLED)

    def fail_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Fail a plan from any active state."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        return self._transition(plan_id, MissionPlanningStatus.FAILED)

    def archive_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Archive a terminal plan."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        return self._transition(plan_id, MissionPlanningStatus.ARCHIVED)

    def _transition(
        self,
        plan_id: str,
        target: MissionPlanningStatus,
    ) -> Result[MissionPlan, Exception]:
        """Load, transition, persist and publish a plan."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        try:
            plan = self._transitions.transition(plan, target)
        except InvalidStateTransitionError as exc:
            return Failure(exc)
        self._plans.save(plan)
        self._timeline.record_status(plan)
        self._transition_events(plan)
        return Success(plan)

    def _transition_events(self, plan: MissionPlan) -> None:
        """Publish the canonical event for a plan's status to the event bus."""
        if self._event_bus is None:
            return
        event_type = _BUS_EVENTS.get(plan.status)
        if event_type is None:
            return
        self._event_bus.publish(
            DomainEvent(
                event_type=event_type,
                payload={"mission_id": plan.mission_id, "plan_id": plan.plan_id},
                source="mission.planning",
            )
        )

    # -- plan queries ------------------------------------------------------

    def get_plan(self, plan_id: str) -> MissionPlan | None:
        """Return a plan by identifier, or ``None``."""
        return self._plans.get(plan_id)

    def status(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Return the current plan for ``plan_id``."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        return Success(plan)

    def list_plans(self, *, limit: int = 100, offset: int = 0) -> list[MissionPlan]:
        """List persisted plans."""
        return list(self._plans.list(limit=limit, offset=offset))

    def update_mission(
        self,
        plan_id: str,
        *,
        name: str | None = None,
        targets: tuple[str, ...] | None = None,
        variables: dict[str, object] | None = None,
        config: dict[str, object] | None = None,
        priority: str | None = None,
    ) -> Result[MissionPlan, Exception]:
        """Update editable fields of a plan that has not been executed.

        Editing is permitted only while the plan is ``created``, ``queued`` or
        ``planning``; a planned or executed mission must be cancelled first.
        """
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        if plan.status not in (
            MissionPlanningStatus.CREATED,
            MissionPlanningStatus.QUEUED,
            MissionPlanningStatus.PLANNING,
        ):
            return Failure(
                InvalidStateTransitionError(
                    plan.status.value,
                    "update",
                )
            )
        try:
            if name is not None:
                plan.name = name
            if targets is not None:
                if not targets:
                    return Failure(MissionPlanValidationError("mission must declare at least one target."))
                plan.targets = tuple(targets)
            if variables is not None:
                plan.variables = dict(variables)
            if config is not None:
                plan.config = dict(config)
            if priority is not None:
                plan.priority = priority
            plan.updated_at = utcnow_iso()
            self._plans.save(plan)
            return Success(plan)
        except MissionPlanningError as exc:
            return Failure(exc)

    # -- execution graph ---------------------------------------------------

    def build_graph(self, plan_id: str) -> Result[ExecutionGraph, Exception]:
        """Build the execution graph (DAG) for a planned mission."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        try:
            graph = self._graph_builder.build(plan)
            self._timeline.graph_built(plan, node_count=len(graph.nodes))
            return Success(graph)
        except MissionPlanningError as exc:
            return Failure(exc)

    # -- checkpoints -------------------------------------------------------

    def checkpoint_create(
        self,
        plan_id: str,
        label: str,
        *,
        rerun_from: str | None = None,
    ) -> Result[Checkpoint, Exception]:
        """Snapshot a plan into a checkpoint."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        try:
            checkpoint = self._checkpoints.create(plan, label, rerun_from=rerun_from)
            self._timeline.checkpoint_created(plan, checkpoint.checkpoint_id, label)
            return Success(checkpoint)
        except MissionPlanningError as exc:
            return Failure(exc)

    def checkpoint_list(self, plan_id: str) -> list[Checkpoint]:
        """Return checkpoints for a plan."""
        return self._checkpoints.list_for_plan(plan_id)

    def checkpoint_restore(self, checkpoint_id: str) -> Result[MissionPlan, Exception]:
        """Restore a plan from a checkpoint (supports partial rerun)."""
        try:
            checkpoint = self._checkpoints.get(checkpoint_id)
        except MissionPlanningError as exc:
            return Failure(exc)
        plan = self._plans.get(checkpoint.plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(checkpoint.plan_id))
        try:
            restored = self._checkpoints.restore(checkpoint)
            self._plans.save(restored)
            self._timeline.checkpoint_restored(plan, checkpoint_id)
            return Success(restored)
        except MissionPlanningError as exc:
            return Failure(exc)

    # -- timeline ----------------------------------------------------------

    def history(self, mission_id: str) -> list[MissionTimelineEntry]:
        """Return a mission's timeline entries."""
        return self._timeline.history(mission_id)
