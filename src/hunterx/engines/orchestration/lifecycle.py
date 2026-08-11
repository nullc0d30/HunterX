# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission lifecycle state machine.

The canonical mission lifecycle (CREATED → SCOPING → PLANNING → READY →
RUNNING → … → COMPLETED | PARTIAL | FAILED | CANCELLED). Every transition is
validated against an explicit transition table; illegal transitions raise
:class:`InvalidStateTransitionError`.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.exceptions import InvalidStateTransitionError
from hunterx.domain.orchestration.enums import MissionState

#: Explicit transition table. Only the listed targets are legal from a source.
_ALLOWED: dict[MissionState, frozenset[MissionState]] = {
    MissionState.CREATED: frozenset({MissionState.SCOPING, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.SCOPING: frozenset({MissionState.PLANNING, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.PLANNING: frozenset({MissionState.READY, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.READY: frozenset({MissionState.RUNNING, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.RUNNING: frozenset(
        {
            MissionState.PAUSED,
            MissionState.WAITING,
            MissionState.REPLANNING,
            MissionState.BLOCKED,
            MissionState.COMPLETED,
            MissionState.PARTIAL,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.PAUSED: frozenset({MissionState.RUNNING, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.WAITING: frozenset({MissionState.RUNNING, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.REPLANNING: frozenset({MissionState.RUNNING, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.BLOCKED: frozenset({MissionState.RUNNING, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.COMPLETED: frozenset(),
    MissionState.PARTIAL: frozenset(),
    MissionState.FAILED: frozenset(),
    MissionState.CANCELLED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class Transition:
    """A validated mission-state transition.

    Attributes:
        source: the originating state.
        target: the destination state.
        allowed: whether the transition is permitted.
        reason: explanation when not permitted.
        name: canonical transition name.

    """

    source: MissionState
    target: MissionState
    allowed: bool = True
    reason: str = ""
    name: str = ""


class MissionLifecycle:
    """Validates and applies mission-state transitions.

    Transitions are pure: ``apply`` returns a new state and never mutates the
    input. Every transition is validated against :data:`_ALLOWED`.
    """

    def can_transition(self, source: MissionState, target: MissionState) -> bool:
        """Return ``True`` when ``source`` → ``target`` is legal."""
        return target in _ALLOWED.get(source, frozenset())

    def assert_transition(self, source: MissionState, target: MissionState) -> MissionState:
        """Assert a transition is legal, raising otherwise.

        Raises:
            InvalidStateTransitionError: when the transition is illegal.

        """
        if not self.can_transition(source, target):
            raise InvalidStateTransitionError(source.value, target.value)
        return target

    def allowed_targets(self, source: MissionState) -> tuple[MissionState, ...]:
        """Return the legal target states from ``source``."""
        return tuple(sorted(_ALLOWED.get(source, frozenset()), key=lambda s: s.value))

    def terminal(self) -> tuple[MissionState, ...]:
        """Return the terminal mission states."""
        return (
            MissionState.COMPLETED,
            MissionState.PARTIAL,
            MissionState.FAILED,
            MissionState.CANCELLED,
        )

    def transition(self, source: MissionState, target: MissionState) -> Transition:
        """Build a :class:`Transition` for a source/target pair."""
        if self.can_transition(source, target):
            return Transition(source=source, target=target, allowed=True, name=f"{source.value}.{target.value}")
        return Transition(
            source=source,
            target=target,
            allowed=False,
            reason=f"{source.value!r} -> {target.value!r} is not a legal mission transition",
            name="invalid",
        )


class MissionLifecycleOperator:
    """Fluent named lifecycle operations over :class:`MissionLifecycle`."""

    def __init__(self, lifecycle: MissionLifecycle | None = None) -> None:
        self._lifecycle = lifecycle or MissionLifecycle()

    def scope(self, state: MissionState) -> MissionState:
        """Begin scope resolution."""
        return self._lifecycle.assert_transition(state, MissionState.SCOPING)

    def plan(self, state: MissionState) -> MissionState:
        """Begin planning after scoping."""
        return self._lifecycle.assert_transition(state, MissionState.PLANNING)

    def ready(self, state: MissionState) -> MissionState:
        """Mark the mission ready after planning."""
        return self._lifecycle.assert_transition(state, MissionState.READY)

    def start(self, state: MissionState) -> MissionState:
        """Start execution."""
        return self._lifecycle.assert_transition(state, MissionState.RUNNING)

    def pause(self, state: MissionState) -> MissionState:
        """Pause execution."""
        return self._lifecycle.assert_transition(state, MissionState.PAUSED)

    def resume(self, state: MissionState) -> MissionState:
        """Resume execution from paused/waiting/replanning/blocked."""
        return self._lifecycle.assert_transition(state, MissionState.RUNNING)

    def wait(self, state: MissionState) -> MissionState:
        """Move into a waiting state (external dependency)."""
        return self._lifecycle.assert_transition(state, MissionState.WAITING)

    def replan(self, state: MissionState) -> MissionState:
        """Move into replanning."""
        return self._lifecycle.assert_transition(state, MissionState.REPLANNING)

    def block(self, state: MissionState) -> MissionState:
        """Block execution."""
        return self._lifecycle.assert_transition(state, MissionState.BLOCKED)

    def complete(self, state: MissionState) -> MissionState:
        """Complete the mission."""
        return self._lifecycle.assert_transition(state, MissionState.COMPLETED)

    def partial(self, state: MissionState) -> MissionState:
        """Complete the mission partially with explicit gaps."""
        return self._lifecycle.assert_transition(state, MissionState.PARTIAL)

    def cancel(self, state: MissionState) -> MissionState:
        """Cancel the mission from any active state."""
        return self._lifecycle.assert_transition(state, MissionState.CANCELLED)

    def fail(self, state: MissionState) -> MissionState:
        """Fail the mission from any active state."""
        return self._lifecycle.assert_transition(state, MissionState.FAILED)
