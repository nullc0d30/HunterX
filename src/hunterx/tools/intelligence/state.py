# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool state machine.

Defines the lifecycle states of a tool and the legal transitions between them:

    registered → installed → verified → available → running → completed | failed

``deprecated`` and ``disabled`` are reachable modifier states. The machine
rejects illegal transitions deterministically.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolStateTransitionError
from hunterx.domain.tool_intelligence import ToolState

#: Legal transitions: source state → set of target states.
_TRANSITIONS: dict[ToolState, frozenset[ToolState]] = {
    ToolState.REGISTERED: frozenset(
        {ToolState.INSTALLED, ToolState.DEPRECATED, ToolState.DISABLED}
    ),
    ToolState.INSTALLED: frozenset(
        {ToolState.VERIFIED, ToolState.DEPRECATED, ToolState.DISABLED}
    ),
    ToolState.VERIFIED: frozenset({ToolState.AVAILABLE, ToolState.DEPRECATED, ToolState.DISABLED}),
    ToolState.AVAILABLE: frozenset(
        {
            ToolState.RUNNING,
            ToolState.DEPRECATED,
            ToolState.DISABLED,
            ToolState.INSTALLED,
        }
    ),
    ToolState.RUNNING: frozenset({ToolState.COMPLETED, ToolState.FAILED}),
    ToolState.COMPLETED: frozenset({ToolState.AVAILABLE, ToolState.DEPRECATED, ToolState.DISABLED}),
    ToolState.FAILED: frozenset({ToolState.AVAILABLE, ToolState.DEPRECATED, ToolState.DISABLED}),
    ToolState.DEPRECATED: frozenset({ToolState.DISABLED}),
    ToolState.DISABLED: frozenset({ToolState.AVAILABLE, ToolState.REGISTERED}),
}

#: States treated as "usable" (installed and ready for execution).
_USABLE: frozenset[ToolState] = frozenset(
    {ToolState.INSTALLED, ToolState.VERIFIED, ToolState.AVAILABLE, ToolState.COMPLETED}
)


class ToolStateMachine:
    """Deterministic lifecycle state machine for tools."""

    def can_transition(self, source: ToolState, target: ToolState) -> bool:
        """Return ``True`` when ``source → target`` is a legal transition."""
        return target in _TRANSITIONS.get(source, frozenset())

    def transition(self, source: ToolState, target: ToolState, *, tool_id: str = "") -> ToolState:
        """Transition ``source`` to ``target``, raising on illegal moves.

        Raises:
            ToolStateTransitionError: if the transition is not permitted.

        """
        if not self.can_transition(source, target):
            raise ToolStateTransitionError(
                tool_id or "state.machine",
                source.value,
                target.value,
                reason="transition not permitted",
            )
        return target

    @staticmethod
    def is_usable(state: ToolState) -> bool:
        """Return ``True`` when ``state`` allows execution."""
        return state in _USABLE

    @staticmethod
    def is_terminal(state: ToolState) -> bool:
        """Return ``True`` for terminal states (failed/deprecated/disabled)."""
        return state in (ToolState.FAILED, ToolState.DEPRECATED, ToolState.DISABLED)

    @staticmethod
    def allowed_targets(state: ToolState) -> list[str]:
        """Return the legal target state names for ``state``."""
        return sorted(target.value for target in _TRANSITIONS.get(state, frozenset()))
