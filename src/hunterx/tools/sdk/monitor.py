# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution monitor.

Streams execution progress to callbacks and records lifecycle checkpoints.
The monitor is the pipeline's observer hook: every phase transition is
reported to registered callbacks and appended to an in-memory timeline.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionResult, ExecutionStatus
from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class ProgressPoint:
    """A lifecycle checkpoint recorded for one execution.

    Attributes:
        status: the execution status at the point.
        phase: free-form phase label (e.g. ``execute``, ``normalize``).
        message: human readable description.
        at: ISO timestamp of the checkpoint.

    """

    status: ExecutionStatus
    phase: str
    message: str
    at: str = field(default_factory=utcnow_iso)


MonitorCallback = Callable[[ExecutionContext, ExecutionStatus, str, dict[str, Any]], None]


class ExecutionMonitor:
    """Record progress points and notify callbacks of phase changes.

    Usage::

        monitor = ExecutionMonitor()
        monitor.on_progress(handler)
        monitor.report(context, status=ExecutionStatus.RUNNING, phase="execute")
        timeline = monitor.timeline(execution_id)
    """

    def __init__(self) -> None:
        self._callbacks: list[MonitorCallback] = []
        self._timeline: dict[str, list[ProgressPoint]] = {}
        self._lock = threading.RLock()

    def on_progress(self, callback: MonitorCallback) -> None:
        """Register a callback invoked on every progress report."""
        self._callbacks.append(callback)

    def report(
        self,
        context: ExecutionContext,
        *,
        status: ExecutionStatus,
        phase: str,
        message: str = "",
        **metadata: Any,
    ) -> None:
        """Record a checkpoint and notify all callbacks."""
        point = ProgressPoint(status=status, phase=phase, message=message)
        with self._lock:
            self._timeline.setdefault(context.execution_id, []).append(point)
            callbacks = list(self._callbacks)
        for callback in callbacks:
            callback(context, status, phase, metadata)

    def timeline(self, execution_id: str) -> list[ProgressPoint]:
        """Return the recorded checkpoints for ``execution_id``."""
        with self._lock:
            return list(self._timeline.get(execution_id, []))

    def last(self, execution_id: str) -> ProgressPoint | None:
        """Return the most recent checkpoint, or ``None``."""
        points = self.timeline(execution_id)
        return points[-1] if points else None

    def clear(self, execution_id: str) -> None:
        """Drop the timeline for one execution."""
        with self._lock:
            self._timeline.pop(execution_id, None)

    def completed_status(self, result: ExecutionResult) -> ExecutionStatus:
        """Map a finished result to a terminal status."""
        if result.status in (ExecutionStatus.COMPLETED, ExecutionStatus.FAILED):
            return result.status
        if result.status is ExecutionStatus.TIMED_OUT:
            return ExecutionStatus.TIMED_OUT
        return ExecutionStatus.FAILED
