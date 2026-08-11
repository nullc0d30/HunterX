# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: mission lifecycle state machine."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import InvalidStateTransitionError
from hunterx.domain.orchestration.enums import MissionState
from hunterx.engines.orchestration.lifecycle import (
    MissionLifecycle,
    MissionLifecycleOperator,
)


def test_canonical_lifecycle_path() -> None:
    lifecycle = MissionLifecycle()
    state = MissionState.CREATED
    for expected in (
        MissionState.SCOPING,
        MissionState.PLANNING,
        MissionState.READY,
        MissionState.RUNNING,
        MissionState.COMPLETED,
    ):
        assert lifecycle.can_transition(state, expected)
        state = expected
    assert state is MissionState.COMPLETED


def test_running_branches() -> None:
    lifecycle = MissionLifecycle()
    running = MissionState.RUNNING
    assert lifecycle.can_transition(running, MissionState.PAUSED)
    assert lifecycle.can_transition(running, MissionState.WAITING)
    assert lifecycle.can_transition(running, MissionState.REPLANNING)
    assert lifecycle.can_transition(running, MissionState.BLOCKED)
    assert lifecycle.can_transition(running, MissionState.PARTIAL)
    assert lifecycle.can_transition(running, MissionState.CANCELLED)
    assert lifecycle.can_transition(running, MissionState.FAILED)


def test_illegal_transition_raises() -> None:
    lifecycle = MissionLifecycle()
    assert not lifecycle.can_transition(MissionState.CREATED, MissionState.RUNNING)
    with pytest.raises(InvalidStateTransitionError):
        lifecycle.assert_transition(MissionState.CREATED, MissionState.RUNNING)


def test_terminal_states_are_terminal() -> None:
    lifecycle = MissionLifecycle()
    for terminal in lifecycle.terminal():
        assert terminal.is_terminal
        assert lifecycle.allowed_targets(terminal) == ()


def test_pause_resume_cycle() -> None:
    op = MissionLifecycleOperator()
    state = MissionState.RUNNING
    state = op.pause(state)
    assert state is MissionState.PAUSED
    state = op.resume(state)
    assert state is MissionState.RUNNING


def test_cancel_from_any_active_state() -> None:
    op = MissionLifecycleOperator()
    for active in (
        MissionState.CREATED,
        MissionState.SCOPING,
        MissionState.PLANNING,
        MissionState.READY,
        MissionState.RUNNING,
        MissionState.PAUSED,
        MissionState.WAITING,
        MissionState.REPLANNING,
        MissionState.BLOCKED,
    ):
        assert op.cancel(active) is MissionState.CANCELLED


def test_fail_from_any_active_state() -> None:
    op = MissionLifecycleOperator()
    for active in (
        MissionState.CREATED,
        MissionState.SCOPING,
        MissionState.PLANNING,
        MissionState.READY,
        MissionState.RUNNING,
    ):
        assert op.fail(active) is MissionState.FAILED


def test_completed_cannot_replan() -> None:
    op = MissionLifecycleOperator()
    with pytest.raises(InvalidStateTransitionError):
        op.replan(MissionState.COMPLETED)
