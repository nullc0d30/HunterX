# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution session.

Tracks a single tool execution from start to finish. A session owns the
execution context, result, artifacts and lifecycle, and provides thread-safe
state transitions so concurrent monitors can safely observe it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from hunterx.domain.execution import (
    ExecutionContext,
    ExecutionResult,
    ExecutionStatus,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class ExecutionArtifact:
    """An artifact produced by an execution.

    Attributes:
        path: filesystem path to the artifact.
        kind: artifact kind (file, screenshot, pcap, log, ...).
        content_type: optional MIME type.
        size_bytes: artifact size in bytes.

    """

    path: str
    kind: str = "file"
    content_type: str = ""
    size_bytes: int = 0


class ExecutionSession:
    """Lifecycle holder for one tool execution.

    Usage::

        session = ExecutionSession.create(context)
        session.begin()
        try:
            ...
            session.finish(result)
        except Exception as exc:
            session.fail(result, error=str(exc))
    """

    def __init__(self, context: ExecutionContext) -> None:
        self.context = context
        self.execution_id = context.execution_id
        self.session_id = generate_id()
        self.started_at: str | None = None
        self.completed_at: str | None = None
        self.result: ExecutionResult | None = None
        self.artifacts: list[ExecutionArtifact] = []
        self._lock = threading.RLock()

    @classmethod
    def create(cls, context: ExecutionContext) -> ExecutionSession:
        """Create a session bound to ``context``."""
        return cls(context)

    def begin(self) -> None:
        """Mark the session as running."""
        with self._lock:
            self.started_at = utcnow_iso()

    def finish(self, result: ExecutionResult) -> None:
        """Attach a finished result and record completion time."""
        with self._lock:
            self.result = result
            self.completed_at = utcnow_iso()

    def fail(self, result: ExecutionResult) -> None:
        """Attach a failed result and record completion time."""
        self.finish(result)

    def attach(self, path: str, *, kind: str = "file", content_type: str = "", size_bytes: int = 0) -> None:
        """Register an artifact produced by the execution."""
        with self._lock:
            self.artifacts.append(
                ExecutionArtifact(path=path, kind=kind, content_type=content_type, size_bytes=size_bytes)
            )

    @property
    def status(self) -> ExecutionStatus:
        """The current status of the session."""
        with self._lock:
            if self.result is not None:
                return self.result.status
            if self.started_at is None:
                return ExecutionStatus.PENDING
            return ExecutionStatus.RUNNING

    @property
    def has_completed(self) -> bool:
        """``True`` once a terminal result has been attached."""
        with self._lock:
            return self.status.is_terminal

    def output_summary(self) -> str:
        """Return a one-line summary of the captured output (for logging)."""
        if self.result is None or self.result.output is None:
            return "<no output>"
        output = self.result.output
        formats = sorted(fmt.value for fmt in output.formats)
        preview = (output.stdout or output.txt or output.xml or "")[:160]
        return f"[{','.join(formats)}] {preview}"
