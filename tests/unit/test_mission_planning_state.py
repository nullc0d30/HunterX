# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the mission planning state machine."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import InvalidStateTransitionError
from hunterx.domain.mission_planning import MissionPlan, MissionPlanningStatus
from hunterx.engines.mission_planning.state import MissionPlanTransition, MissionStateMachine


def _plan(status: MissionPlanningStatus = MissionPlanningStatus.CREATED) -> MissionPlan:
    return MissionPlan(name="M", status=status)


class TestMissionStateMachine:
    def test_ratified_path(self) -> None:
        machine = MissionStateMachine()
        states = [
            MissionPlanningStatus.CREATED,
            MissionPlanningStatus.QUEUED,
            MissionPlanningStatus.PLANNING,
            MissionPlanningStatus.READY,
            MissionPlanningStatus.EXECUTING,
        ]
        for source, target in zip(states, states[1:], strict=False):
            assert machine.can_transition(source, target)
        assert machine.can_transition(MissionPlanningStatus.EXECUTING, MissionPlanningStatus.COMPLETED)
        assert machine.can_transition(MissionPlanningStatus.COMPLETED, MissionPlanningStatus.ARCHIVED)

    def test_invalid_transition_raises(self) -> None:
        machine = MissionStateMachine()
        with pytest.raises(InvalidStateTransitionError):
            machine.assert_transition(
                MissionPlanningStatus.CREATED,
                MissionPlanningStatus.COMPLETED,
            )

    def test_terminal_states_only_archive(self) -> None:
        machine = MissionStateMachine()
        for terminal in machine.terminal():
            assert machine.allowed_targets(terminal) == (MissionPlanningStatus.ARCHIVED,) or terminal is MissionPlanningStatus.ARCHIVED

    def test_archived_is_sink(self) -> None:
        machine = MissionStateMachine()
        assert machine.allowed_targets(MissionPlanningStatus.ARCHIVED) == ()
        assert not machine.can_transition(MissionPlanningStatus.ARCHIVED, MissionPlanningStatus.EXECUTING)

    def test_path(self) -> None:
        machine = MissionStateMachine()
        path = machine.path(MissionPlanningStatus.CREATED, MissionPlanningStatus.EXECUTING)
        assert path == [
            MissionPlanningStatus.CREATED,
            MissionPlanningStatus.QUEUED,
            MissionPlanningStatus.PLANNING,
            MissionPlanningStatus.READY,
            MissionPlanningStatus.EXECUTING,
        ]
        assert machine.path(MissionPlanningStatus.COMPLETED, MissionPlanningStatus.EXECUTING) == []

    def test_cancel_and_fail_from_active_states(self) -> None:
        machine = MissionStateMachine()
        for active in (
            MissionPlanningStatus.QUEUED,
            MissionPlanningStatus.PLANNING,
            MissionPlanningStatus.READY,
            MissionPlanningStatus.EXECUTING,
            MissionPlanningStatus.PAUSED,
            MissionPlanningStatus.WAITING,
            MissionPlanningStatus.RETRYING,
        ):
            assert machine.can_transition(active, MissionPlanningStatus.CANCELLED)
            assert machine.can_transition(active, MissionPlanningStatus.FAILED)


class TestMissionPlanTransition:
    def test_full_lifecycle(self) -> None:
        transition = MissionPlanTransition()
        plan = _plan()
        plan = transition.queue(plan)
        assert plan.status is MissionPlanningStatus.QUEUED
        plan = transition.start_planning(plan)
        assert plan.status is MissionPlanningStatus.PLANNING
        plan = transition.mark_ready(plan)
        assert plan.status is MissionPlanningStatus.READY
        plan = transition.start(plan)
        assert plan.status is MissionPlanningStatus.EXECUTING
        assert plan.started_at is not None
        plan = transition.pause(plan)
        assert plan.status is MissionPlanningStatus.PAUSED
        plan = transition.resume(plan)
        assert plan.status is MissionPlanningStatus.EXECUTING
        plan = transition.wait(plan)
        assert plan.status is MissionPlanningStatus.WAITING
        plan = transition.unwait(plan)
        assert plan.status is MissionPlanningStatus.EXECUTING
        plan = transition.complete(plan)
        assert plan.status is MissionPlanningStatus.COMPLETED
        assert plan.completed_at is not None
        plan = transition.archive(plan)
        assert plan.status is MissionPlanningStatus.ARCHIVED

    def test_retry_cycle(self) -> None:
        transition = MissionPlanTransition()
        plan = _plan(MissionPlanningStatus.EXECUTING)
        plan = transition.retry(plan)
        assert plan.status is MissionPlanningStatus.RETRYING
        plan = transition.resume_retry(plan)
        assert plan.status is MissionPlanningStatus.EXECUTING

    def test_original_plan_is_not_mutated(self) -> None:
        transition = MissionPlanTransition()
        original = _plan()
        transition.queue(original)
        assert original.status is MissionPlanningStatus.CREATED

    def test_identity_preserved(self) -> None:
        transition = MissionPlanTransition()
        plan = _plan()
        plan_id = plan.plan_id
        mission_id = plan.mission_id
        queued = transition.queue(plan)
        assert queued.plan_id == plan_id
        assert queued.mission_id == mission_id

    def test_cancel_uses_validated_transition(self) -> None:
        transition = MissionPlanTransition()
        plan = _plan(MissionPlanningStatus.READY)
        cancelled = transition.cancel(plan)
        assert cancelled.status is MissionPlanningStatus.CANCELLED

    def test_invalid_named_op_raises(self) -> None:
        transition = MissionPlanTransition()
        with pytest.raises(InvalidStateTransitionError):
            transition.start(_plan(MissionPlanningStatus.CREATED))
