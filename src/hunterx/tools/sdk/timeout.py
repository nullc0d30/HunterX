# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Timeout manager.

Tracks the deadline of an execution and detects deadline expiry. Timeouts are
computed from the execution context (explicit timeout or resource-limit
default) and enforced by the pipeline around the tool run.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolTimeoutError
from hunterx.domain.execution import ExecutionContext
from hunterx.shared.time import monotonic_ms


class TimeoutManager:
    """Compute and check execution deadlines.

    Usage::

        manager = TimeoutManager()
        manager.arm(context)
        ...
        manager.check(context)   # raises ToolTimeoutError when expired
        manager.remaining_s(context)
    """

    def __init__(self) -> None:
        self._deadlines: dict[str, float] = {}

    def arm(self, context: ExecutionContext) -> None:
        """Start the deadline clock for ``context``.

        A context with no effective timeout is never expired (deadline 0).
        """
        timeout = context.timeout_effective
        if timeout <= 0:
            self._deadlines[context.execution_id] = 0.0
            return
        self._deadlines[context.execution_id] = monotonic_ms() + timeout * 1000.0

    def disarm(self, execution_id: str) -> None:
        """Stop tracking a completed execution."""
        self._deadlines.pop(execution_id, None)

    def expired(self, context: ExecutionContext) -> bool:
        """Return ``True`` when the execution has exceeded its timeout."""
        deadline = self._deadlines.get(context.execution_id, 0.0)
        if deadline <= 0:
            return False
        return monotonic_ms() > deadline

    def remaining_ms(self, context: ExecutionContext) -> float:
        """Return the remaining budget in milliseconds (``0`` when expired)."""
        deadline = self._deadlines.get(context.execution_id, 0.0)
        if deadline <= 0:
            return 0.0
        return max(0.0, deadline - monotonic_ms())

    def remaining_s(self, context: ExecutionContext) -> float:
        """Return the remaining budget in seconds (``0`` when expired)."""
        return self.remaining_ms(context) / 1000.0

    def check(self, context: ExecutionContext) -> None:
        """Raise :class:`ToolTimeoutError` when the deadline has expired."""
        if self.expired(context):
            raise ToolTimeoutError(context.tool_id, context.timeout_effective)
