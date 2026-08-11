# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Distributed tracing adapters.

The :class:`InMemoryTracer` implements the tracer port with an in-process span
tree. Spans form a hierarchy through ``parent_span_id``; a thread-local current
span allows context propagation across components running on the same thread,
and mission/execution timelines can be reconstructed by filtering a trace by
mission attributes.
"""

from __future__ import annotations

import contextvars
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.ports.observability import TracerPort
from hunterx.shared.ids import generate_id

#: Thread-local current span (thread-safe propagation within a process).
_current: contextvars.ContextVar[Span | None] = contextvars.ContextVar(
    "hunterx_current_span", default=None
)


@dataclass(slots=True)
class Span:
    """A single traced operation within a trace.

    Attributes:
        span_id: unique span identifier.
        trace_id: identifier of the enclosing trace.
        parent_span_id: parent span identifier, or ``None`` for root spans.
        name: operation name.
        start_ms: monotonic start timestamp.
        end_ms: monotonic end timestamp (set on completion).
        attributes: structured span metadata.
        status: completion status (``ok`` or ``error``).

    """

    span_id: str
    trace_id: str
    name: str
    parent_span_id: str | None
    start_ms: float
    end_ms: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the span for export."""
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "started_at": self.start_ms,
            "ended_at": self.end_ms,
            "duration_ms": round(self.end_ms - self.start_ms, 3) if self.end_ms else None,
            "status": self.status,
            "attributes": dict(self.attributes),
        }


class InMemoryTracer(TracerPort):
    """In-process span tree tracer with thread-local propagation."""

    def __init__(self) -> None:
        self._spans: dict[str, Span] = {}
        self._traces: dict[str, list[str]] = {}
        self._lock = threading.RLock()

    # -- tracing API --------------------------------------------------------

    def start_span(
        self,
        name: str,
        *,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Any:
        """Start a child (or root) span and make it current."""
        current = _current.get()
        resolved_parent = parent_span_id or (current.span_id if current else None)
        resolved_trace = trace_id or (current.trace_id if current else generate_id())
        span = Span(
            span_id=generate_id(),
            trace_id=resolved_trace,
            name=name,
            parent_span_id=resolved_parent,
            start_ms=time.monotonic() * 1000,
            attributes=dict(attributes or {}),
        )
        with self._lock:
            self._spans[span.span_id] = span
            self._traces.setdefault(span.trace_id, []).append(span.span_id)
        _current.set(span)
        return span

    def end_span(self, *, attributes: dict[str, Any] | None = None) -> Any | None:
        """End the current span and return its serialized form."""
        span = _current.get()
        if span is None:
            return None
        if attributes:
            span.attributes.update(attributes)
        span.end_ms = time.monotonic() * 1000
        # Restore the parent span as current, if any.
        if span.parent_span_id:
            parent = self._spans.get(span.parent_span_id)
            _current.set(parent if parent is not None else None)
        else:
            _current.set(None)
        return span.to_dict()

    def current_span(self) -> Any | None:
        """Return the current span context, or ``None``."""
        span = _current.get()
        return span.to_dict() if span is not None else None

    def trace(self, trace_id: str) -> list[dict[str, Any]] | None:
        """Return every span belonging to a trace, in start order."""
        with self._lock:
            span_ids = self._traces.get(trace_id)
            if span_ids is None:
                return None
            return [self._spans[sid].to_dict() for sid in span_ids]

    # -- introspection ------------------------------------------------------

    def traces(self) -> list[str]:
        """Return every known trace id, most recent first."""
        with self._lock:
            return list(reversed(list(self._traces)))

    def span_count(self) -> int:
        """Return the number of recorded spans."""
        with self._lock:
            return len(self._spans)
