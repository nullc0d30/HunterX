# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Event persistence: append-only store, dead-letter queue and replay.

The :class:`InMemoryEventStore` keeps an append-only, paginated history of
every event published through the bus and supports replaying it (optionally
filtered by type). :class:`InMemoryDeadLetterQueue` quarantines events whose
handlers failed so they can be inspected and requeued.
"""

from __future__ import annotations

import threading
from typing import Any

from hunterx.domain.events import DomainEvent
from hunterx.domain.events.enums import EventStatus
from hunterx.domain.ports.observability import DeadLetterQueuePort, EventStorePort


class InMemoryEventStore(EventStorePort):
    """Append-only in-memory event history with replay support."""

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def append(self, event: DomainEvent) -> None:
        """Persist an event."""
        with self._lock:
            self._events.append({**event.to_dict(), "status": EventStatus.RECEIVED.value})

    def mark(self, event_id: str, status: str) -> None:
        """Update the delivery status of a persisted event."""
        with self._lock:
            for row in self._events:
                if row["event_id"] == event_id:
                    row["status"] = status
                    return

    def get(self, event_id: str) -> dict[str, Any] | None:
        """Return a persisted event mapping by id, or ``None``."""
        with self._lock:
            for row in self._events:
                if row["event_id"] == event_id:
                    return dict(row)
            return None

    def list(self, *, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Return a paginated slice of persisted events."""
        with self._lock:
            return [dict(row) for row in self._events[offset : offset + limit]]

    def count(self) -> int:
        """Return the number of persisted events."""
        with self._lock:
            return len(self._events)

    def replay(self, *, event_type: str | None = None, limit: int = 0) -> list[DomainEvent]:
        """Return persisted events (optionally filtered) for replay.

        ``event_type`` supports exact types and category prefixes (``mission.*``).
        """
        with self._lock:
            selected = [row for row in self._events if _type_matches(row["event_type"], event_type)]
            if limit > 0:
                selected = selected[:limit]
            return [_row_to_event(row) for row in selected]


def _type_matches(event_type: str, pattern: str | None) -> bool:
    """Return ``True`` when ``event_type`` matches a type pattern."""
    if pattern is None:
        return True
    if pattern.endswith(".*"):
        return event_type.startswith(f"{pattern[:-2]}.")
    return event_type == pattern


def _row_to_event(row: dict[str, Any]) -> DomainEvent:
    """Rebuild a :class:`DomainEvent` from a persisted mapping."""
    from hunterx.domain.events import EventCategory, EventSeverity

    return DomainEvent(
        event_id=row["event_id"],
        event_type=row["event_type"],
        occurred_at=row["occurred_at"],
        source=row["source"],
        correlation_id=row.get("correlation_id"),
        causation_id=row.get("causation_id"),
        mission_id=row.get("mission_id"),
        execution_id=row.get("execution_id"),
        consumer=row.get("consumer"),
        severity=EventSeverity(row.get("severity", "info")),
        category=EventCategory(row.get("category", "system")),
        payload_version=row.get("payload_version", 1),
        payload=dict(row.get("payload", {})),
    )


class InMemoryDeadLetterQueue(DeadLetterQueuePort):
    """Holding area for events whose handlers could not process them."""

    def __init__(self) -> None:
        self._items: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def push(self, event: DomainEvent, error: str) -> None:
        """Move an unprocessable event into the dead-letter queue."""
        with self._lock:
            self._items.append({**event.to_dict(), "error": error, "status": EventStatus.DEAD.value})

    def list(self) -> list[dict[str, Any]]:
        """Return every dead-lettered event with its failure reason."""
        with self._lock:
            return [dict(item) for item in self._items]

    def count(self) -> int:
        """Return the number of dead-lettered events."""
        with self._lock:
            return len(self._items)

    def requeue(self, event_id: str) -> DomainEvent | None:
        """Return a dead-lettered event for redelivery (or ``None``)."""
        with self._lock:
            for index, item in enumerate(self._items):
                if item["event_id"] == event_id:
                    del self._items[index]
                    return _row_to_event(item)
            return None
