# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission state machine.

Owns the ratified mission lifecycle: Created → Queued → Planning → Ready →
Executing → (Paused / Waiting / Retrying) → Completed / Cancelled / Failed →
Archived. The machine is pure transition logic over
:class:`~hunterx.domain.mission_planning.MissionPlanningStatus`; callers apply
it to a plan through :class:`MissionPlanTransition`.
"""

from __future__ import annotations

from hunterx.domain.exceptions import InvalidStateTransitionError
from hunterx.domain.mission_planning import MissionPlan, MissionPlanningStatus
from hunterx.shared.time import utcnow_iso

#: Allowed (source -> target) lifecycle transitions. Terminal states admit only
#: the archival edge; every non-terminal state can be cancelled or failed.
_ALLOWED: dict[MissionPlanningStatus, frozenset[MissionPlanningStatus]] = {
    MissionPlanningStatus.CREATED: frozenset({MissionPlanningStatus.QUEUED}),
    MissionPlanningStatus.QUEUED: frozenset(
        {
            MissionPlanningStatus.PLANNING,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
        }
    ),
    MissionPlanningStatus.PLANNING: frozenset(
        {
            MissionPlanningStatus.READY,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
        }
    ),
    MissionPlanningStatus.READY: frozenset(
        {
            MissionPlanningStatus.EXECUTING,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
        }
    ),
    MissionPlanningStatus.EXECUTING: frozenset(
        {
            MissionPlanningStatus.PAUSED,
            MissionPlanningStatus.WAITING,
            MissionPlanningStatus.RETRYING,
            MissionPlanningStatus.COMPLETED,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
        }
    ),
    MissionPlanningStatus.PAUSED: frozenset(
        {
            MissionPlanningStatus.EXECUTING,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
        }
    ),
    MissionPlanningStatus.WAITING: frozenset(
        {
            MissionPlanningStatus.EXECUTING,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
        }
    ),
    MissionPlanningStatus.RETRYING: frozenset(
        {
            MissionPlanningStatus.EXECUTING,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
        }
    ),
    MissionPlanningStatus.COMPLETED: frozenset({MissionPlanningStatus.ARCHIVED}),
    MissionPlanningStatus.FAILED: frozenset({MissionPlanningStatus.ARCHIVED}),
    MissionPlanningStatus.CANCELLED: frozenset({MissionPlanningStatus.ARCHIVED}),
    MissionPlanningStatus.ARCHIVED: frozenset(),
}

#: Convenience entry points for common lifecycle operations.
_STARTER = {
    "queue": (MissionPlanningStatus.CREATED, MissionPlanningStatus.QUEUED),
    "plan": (MissionPlanningStatus.QUEUED, MissionPlanningStatus.PLANNING),
    "ready": (MissionPlanningStatus.PLANNING, MissionPlanningStatus.READY),
    "start": (MissionPlanningStatus.READY, MissionPlanningStatus.EXECUTING),
    "pause": (MissionPlanningStatus.EXECUTING, MissionPlanningStatus.PAUSED),
    "resume": (MissionPlanningStatus.PAUSED, MissionPlanningStatus.EXECUTING),
    "wait": (MissionPlanningStatus.EXECUTING, MissionPlanningStatus.WAITING),
    "unwait": (MissionPlanningStatus.WAITING, MissionPlanningStatus.EXECUTING),
    "retry": (MissionPlanningStatus.EXECUTING, MissionPlanningStatus.RETRYING),
    "resume_retry": (MissionPlanningStatus.RETRYING, MissionPlanningStatus.EXECUTING),
    "complete": (MissionPlanningStatus.EXECUTING, MissionPlanningStatus.COMPLETED),
    "cancel": None,
    "fail": None,
    "archive": None,
}


class MissionStateMachine:
    """Validate and apply mission lifecycle transitions."""

    def can_transition(
        self,
        source: MissionPlanningStatus,
        target: MissionPlanningStatus,
    ) -> bool:
        """Return ``True`` when ``source`` may transition to ``target``."""
        allowed = _ALLOWED.get(source, frozenset())
        return target in allowed

    def assert_transition(
        self,
        source: MissionPlanningStatus,
        target: MissionPlanningStatus,
    ) -> MissionPlanningStatus:
        """Validate a transition, raising :class:`InvalidStateTransitionError`."""
        if not self.can_transition(source, target):
            raise InvalidStateTransitionError(source.value, target.value)
        return target

    def allowed_targets(self, source: MissionPlanningStatus) -> tuple[MissionPlanningStatus, ...]:
        """Return every state reachable from ``source``."""
        return tuple(sorted(_ALLOWED.get(source, frozenset()), key=lambda state: state.value))

    def path(
        self,
        source: MissionPlanningStatus,
        target: MissionPlanningStatus,
    ) -> list[MissionPlanningStatus]:
        """Return the ordered hops from ``source`` to ``target``.

        Direct edges are returned immediately; indirect edges are routed through
        the canonical lifecycle path. An empty list means the hop is impossible.
        """
        if self.can_transition(source, target):
            return [source, target]
        canonical = [
            MissionPlanningStatus.CREATED,
            MissionPlanningStatus.QUEUED,
            MissionPlanningStatus.PLANNING,
            MissionPlanningStatus.READY,
            MissionPlanningStatus.EXECUTING,
            MissionPlanningStatus.PAUSED,
            MissionPlanningStatus.WAITING,
            MissionPlanningStatus.RETRYING,
        ]
        if source in canonical and target in canonical:
            start = canonical.index(source)
            end = canonical.index(target)
            if start < end:
                return canonical[start : end + 1]
        return []

    def terminal(self) -> tuple[MissionPlanningStatus, ...]:
        """Return every terminal state."""
        return tuple(
            status for status in MissionPlanningStatus if status.is_terminal
        )

    def apply(self, plan: MissionPlan, target: MissionPlanningStatus) -> MissionPlan:
        """Return a copy of ``plan`` transitioned to ``target``.

        The original plan is never mutated. Timestamps (started/completed) are
        refreshed when the transition enters or leaves an active state.
        """
        self.assert_transition(plan.status, target)
        started_at = plan.started_at
        completed_at = plan.completed_at
        if started_at is None and target is MissionPlanningStatus.EXECUTING:
            started_at = utcnow_iso()
        if target.is_terminal:
            completed_at = utcnow_iso()
        return MissionPlan(
            plan_id=plan.plan_id,
            mission_id=plan.mission_id,
            profile_id=plan.profile_id,
            template_id=plan.template_id,
            mission_type=plan.mission_type,
            name=plan.name,
            status=target,
            phases=plan.phases,
            targets=plan.targets,
            variables=plan.variables,
            config=plan.config,
            priority=plan.priority,
            approval_level=plan.approval_level,
            progress=plan.progress,
            estimated_duration_seconds=plan.estimated_duration_seconds,
            created_at=plan.created_at,
            updated_at=utcnow_iso(),
            started_at=started_at,
            completed_at=completed_at,
        )


class MissionPlanTransition:
    """Fluent lifecycle facade over a :class:`MissionPlan`.

    Wraps the pure state machine so callers (engine/API) apply named operations
    such as ``queue``, ``plan``, ``start``, ``pause`` or ``complete`` without
    hand-coding transitions. ``cancel`` and ``fail`` accept any active state.
    """

    def __init__(self, machine: MissionStateMachine | None = None) -> None:
        self._machine = machine or MissionStateMachine()

    def _hop(self, plan: MissionPlan, name: str) -> MissionPlan:
        edge = _STARTER.get(name)
        if edge is None:
            raise InvalidStateTransitionError(plan.status.value, name)
        return self._machine.apply(plan, edge[1])

    def queue(self, plan: MissionPlan) -> MissionPlan:
        """Transition a created plan into the queue."""
        return self._hop(plan, "queue")

    def start_planning(self, plan: MissionPlan) -> MissionPlan:
        """Transition a queued plan into planning."""
        return self._hop(plan, "plan")

    def mark_ready(self, plan: MissionPlan) -> MissionPlan:
        """Transition a planned mission into the ready state."""
        return self._hop(plan, "ready")

    def start(self, plan: MissionPlan) -> MissionPlan:
        """Begin executing a ready plan."""
        return self._hop(plan, "start")

    def pause(self, plan: MissionPlan) -> MissionPlan:
        """Pause an executing plan."""
        return self._hop(plan, "pause")

    def resume(self, plan: MissionPlan) -> MissionPlan:
        """Resume a paused plan."""
        return self._hop(plan, "resume")

    def wait(self, plan: MissionPlan) -> MissionPlan:
        """Put an executing plan on hold (e.g. awaiting approval)."""
        return self._hop(plan, "wait")

    def unwait(self, plan: MissionPlan) -> MissionPlan:
        """Return a waiting plan to execution."""
        return self._hop(plan, "unwait")

    def retry(self, plan: MissionPlan) -> MissionPlan:
        """Enter the retrying state after a transient failure."""
        return self._hop(plan, "retry")

    def resume_retry(self, plan: MissionPlan) -> MissionPlan:
        """Resume execution after a retry is scheduled."""
        return self._hop(plan, "resume_retry")

    def complete(self, plan: MissionPlan) -> MissionPlan:
        """Mark an executing plan completed."""
        return self._hop(plan, "complete")

    def cancel(self, plan: MissionPlan) -> MissionPlan:
        """Cancel a plan from any active state."""
        return self._machine.apply(plan, MissionPlanningStatus.CANCELLED)

    def fail(self, plan: MissionPlan) -> MissionPlan:
        """Fail a plan from any active state."""
        return self._machine.apply(plan, MissionPlanningStatus.FAILED)

    def archive(self, plan: MissionPlan) -> MissionPlan:
        """Archive a terminal plan."""
        return self._machine.apply(plan, MissionPlanningStatus.ARCHIVED)

    def transition(self, plan: MissionPlan, target: MissionPlanningStatus) -> MissionPlan:
        """Apply an arbitrary validated transition to ``plan``."""
        return self._machine.apply(plan, target)
