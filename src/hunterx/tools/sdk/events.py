# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution event bus.

Domain events emitted during a tool execution: started, completed, failed,
timeout, retry, output collected, normalization complete and database updated.
The event bus delivers to registered subscribers synchronously and records
each event for replay/audit.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.events.types import EventType
from hunterx.shared.time import utcnow_iso

EventCallback = Callable[[EventType, dict[str, Any]], None]


@dataclass(slots=True)
class RecordedEvent:
    """An event delivered on the bus.

    Attributes:
        event_type: the event kind.
        data: the event payload.
        emitted_at: ISO timestamp of emission.

    """

    event_type: EventType
    data: dict[str, Any]
    emitted_at: str = field(default_factory=utcnow_iso)


def _base(event_type: EventType, execution_id: str, tool_id: str) -> dict[str, Any]:
    return {
        "execution_id": execution_id,
        "tool_id": tool_id,
        "emitted_at": utcnow_iso(),
        "event_type": event_type.value,
    }


class ExecutionEventBus:
    """Thread-safe event bus for execution lifecycle events.

    Usage::

        bus = ExecutionEventBus()
        bus.subscribe(on_event)
        bus.started(execution_id, tool_id, context_id)
        events = bus.events()
    """

    def __init__(self) -> None:
        self._subscribers: list[EventCallback] = []
        self._records: list[RecordedEvent] = []
        self._lock = threading.RLock()

    def subscribe(self, callback: EventCallback) -> None:
        """Register a callback for all emitted events."""
        with self._lock:
            self._subscribers.append(callback)

    def _emit(self, event_type: EventType, data: dict[str, Any]) -> None:
        record = RecordedEvent(event_type=event_type, data=data)
        with self._lock:
            self._records.append(record)
            subscribers = list(self._subscribers)
        for callback in subscribers:
            callback(event_type, data)

    # -- lifecycle events ----------------------------------------------------

    def started(self, execution_id: str, tool_id: str, context_id: str | None = None) -> None:
        """Emit ``ExecutionStartedEvent``."""
        data = _base(EventType.EXECUTION_STARTED, execution_id, tool_id)
        data["context_id"] = context_id
        self._emit(EventType.EXECUTION_STARTED, data)

    def completed(self, execution_id: str, tool_id: str, summary: str = "") -> None:
        """Emit ``ExecutionCompletedEvent``."""
        data = _base(EventType.EXECUTION_COMPLETED, execution_id, tool_id)
        data["summary"] = summary
        self._emit(EventType.EXECUTION_COMPLETED, data)

    def failed(self, execution_id: str, tool_id: str, failure_kind: str, message: str) -> None:
        """Emit ``ExecutionFailedEvent``."""
        data = _base(EventType.EXECUTION_FAILED, execution_id, tool_id)
        data["failure_kind"] = failure_kind
        data["message"] = message
        self._emit(EventType.EXECUTION_FAILED, data)

    def timed_out(self, execution_id: str, tool_id: str, timeout_seconds: float) -> None:
        """Emit ``ExecutionTimedOutEvent``."""
        data = _base(EventType.EXECUTION_TIMED_OUT, execution_id, tool_id)
        data["timeout_seconds"] = timeout_seconds
        self._emit(EventType.EXECUTION_TIMED_OUT, data)

    def retried(self, execution_id: str, tool_id: str, attempt: int, reason: str) -> None:
        """Emit ``ExecutionRetriedEvent``."""
        data = _base(EventType.EXECUTION_RETRIED, execution_id, tool_id)
        data["attempt"] = attempt
        data["reason"] = reason
        self._emit(EventType.EXECUTION_RETRIED, data)

    # -- pipeline events ------------------------------------------------------

    def output_collected(self, execution_id: str, tool_id: str, formats: list[str], size_bytes: int) -> None:
        """Emit ``OutputCollectedEvent``."""
        data = _base(EventType.OUTPUT_COLLECTED, execution_id, tool_id)
        data["formats"] = formats
        data["size_bytes"] = size_bytes
        self._emit(EventType.OUTPUT_COLLECTED, data)

    def normalization_complete(self, execution_id: str, tool_id: str, findings: int) -> None:
        """Emit ``NormalizationCompleteEvent``."""
        data = _base(EventType.NORMALIZATION_COMPLETE, execution_id, tool_id)
        data["findings"] = findings
        self._emit(EventType.NORMALIZATION_COMPLETE, data)

    def database_updated(self, execution_id: str, tool_id: str, stored_ids: list[str]) -> None:
        """Emit ``DatabaseUpdatedEvent``."""
        data = _base(EventType.DATABASE_UPDATED, execution_id, tool_id)
        data["stored_ids"] = stored_ids
        self._emit(EventType.DATABASE_UPDATED, data)

    # -- inspection ------------------------------------------------------------

    def events(self) -> list[RecordedEvent]:
        """Return a snapshot of all recorded events."""
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        """Drop all recorded events and subscribers."""
        with self._lock:
            self._records.clear()
            self._subscribers.clear()
