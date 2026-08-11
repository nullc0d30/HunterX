# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Domain events.

Domain events are immutable facts describing something that happened inside
the platform. They are published on the event bus and consumed by internal
subsystems and by external plugins. Event payloads must be JSON-serializable.

Every event carries the TIDB-style metadata envelope: event id, correlation
and causation ids, mission/execution scope, producer/consumer, severity,
category and payload version. See :mod:`hunterx.domain.events.enums`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.events.enums import EventCategory, EventSeverity
from hunterx.domain.events.spec import EventRegistry, EventSpec
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

__all__ = [
    "DomainEvent",
    "EventCategory",
    "EventSeverity",
    "EventRegistry",
    "EventSpec",
]


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Base class for every domain event.

    Attributes:
        event_id: unique identifier (auto-generated ULID).
        event_type: stable machine name (e.g. ``"finding.created"``).
        occurred_at: UTC ISO-8601 timestamp (auto-filled).
        source: originating component or plugin name (producer).
        payload: JSON-serializable event data.
        correlation_id: id correlating a logical workflow across events.
        causation_id: id of the event that caused this one.
        mission_id: scoping mission identifier, if any.
        execution_id: scoping execution identifier, if any.
        consumer: target consumer, if routed to a specific subsystem.
        severity: operational severity of the event.
        category: subsystem category the event belongs to.
        payload_version: schema version of the payload.

    """

    event_type: str
    payload: dict[str, object]
    source: str = "hunterx"
    event_id: str = field(default_factory=generate_id)
    occurred_at: str = field(default_factory=utcnow_iso)
    correlation_id: str | None = None
    causation_id: str | None = None
    mission_id: str | None = None
    execution_id: str | None = None
    consumer: str | None = None
    severity: EventSeverity = EventSeverity.INFO
    category: EventCategory = EventCategory.SYSTEM
    payload_version: int = 1

    @property
    def producer(self) -> str:
        """Return the producing component (alias for ``source``)."""
        return self.source

    def to_dict(self) -> dict[str, object]:
        """Serialize the event to a JSON-safe mapping."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "source": self.source,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "consumer": self.consumer,
            "severity": self.severity.value,
            "category": self.category.value,
            "payload_version": self.payload_version,
            "payload": self.payload,
        }
