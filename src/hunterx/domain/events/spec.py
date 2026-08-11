# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Event spec and registry.

An :class:`EventSpec` declares the contract for one canonical event type:
its category, default severity, current payload version and a human-readable
description. The :class:`EventRegistry` is the authoritative catalog of every
event the platform knows how to publish and consume, and is the backbone of
event versioning (a consumer may assert compatibility with a payload version).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.events.enums import EventCategory, EventSeverity


@dataclass(frozen=True, slots=True)
class EventSpec:
    """Canonical contract for one event type.

    Attributes:
        event_type: stable machine name (``"<category>.<action>"``).
        category: subsystem category.
        severity: default severity applied when none is provided.
        payload_version: current schema version of the payload.
        description: human-readable purpose of the event.
        versions: mapping of ``payload_version`` to a short schema summary.

    """

    event_type: str
    category: EventCategory
    severity: EventSeverity = EventSeverity.INFO
    payload_version: int = 1
    description: str = ""
    versions: Mapping[int, str] = field(default_factory=dict)

    def supports(self, payload_version: int) -> bool:
        """Return ``True`` when ``payload_version`` is a known schema version."""
        return payload_version == self.payload_version or payload_version in self.versions


class EventRegistry:
    """Catalog of canonical event types.

    Registration is idempotent; re-registering the same type replaces the
    spec. Unregistered event types are tolerated at publish time but surface
    in :meth:`unknown_types` so drift can be detected and audited.
    """

    def __init__(self) -> None:
        self._specs: dict[str, EventSpec] = {}

    def register(self, spec: EventSpec) -> None:
        """Register or replace an :class:`EventSpec`."""
        self._specs[spec.event_type] = spec

    def register_many(self, specs: list[EventSpec]) -> None:
        """Register several specs in one call."""
        for spec in specs:
            self.register(spec)

    def get(self, event_type: str) -> EventSpec | None:
        """Return the spec for ``event_type``, or ``None`` when unregistered."""
        return self._specs.get(event_type)

    def require(self, event_type: str) -> EventSpec:
        """Return the spec for ``event_type``, raising when unknown."""
        spec = self._specs.get(event_type)
        if spec is None:
            raise KeyError(f"Event type {event_type!r} is not registered")
        return spec

    def has(self, event_type: str) -> bool:
        """Return ``True`` when ``event_type`` is registered."""
        return event_type in self._specs

    def specs(self) -> list[EventSpec]:
        """Return every registered spec, ordered by event type."""
        return [self._specs[name] for name in sorted(self._specs)]

    def for_category(self, category: EventCategory) -> list[EventSpec]:
        """Return specs belonging to ``category``."""
        return [spec for spec in self.specs() if spec.category == category]

    def categories(self) -> list[EventCategory]:
        """Return every category that has at least one registered spec."""
        seen: list[EventCategory] = []
        for spec in self.specs():
            if spec.category not in seen:
                seen.append(spec.category)
        return seen

    def unknown_types(self, event_types: list[str]) -> list[str]:
        """Return the subset of ``event_types`` that are not registered."""
        return [name for name in event_types if name not in self._specs]

    def to_dict(self) -> list[dict[str, Any]]:
        """Serialize the registry for dashboards and tooling."""
        return [
            {
                "event_type": spec.event_type,
                "category": spec.category.value,
                "severity": spec.severity.value,
                "payload_version": spec.payload_version,
                "description": spec.description,
            }
            for spec in self.specs()
        ]
