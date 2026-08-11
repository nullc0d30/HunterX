# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Observability facade.

Re-exports the public observability contracts and the default in-memory
implementations so subsystems can depend on one stable module.
"""

from __future__ import annotations

from hunterx.application.observability import ObservabilityService
from hunterx.domain.events import DomainEvent
from hunterx.domain.events.audit import AuditEventFactory
from hunterx.domain.events.catalog import build_registry
from hunterx.domain.events.enums import (
    EventCategory,
    EventPriority,
    EventSeverity,
    EventStatus,
)
from hunterx.domain.events.spec import EventRegistry, EventSpec
from hunterx.domain.ports.observability import (
    DeadLetterQueuePort,
    EventFilter,
    EventHandler,
    EventStorePort,
    HealthProbePort,
    HealthRegistryPort,
    MetricsPort,
    ObservabilityEventBusPort,
    TelemetryProviderPort,
    TracerPort,
)
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.event_bus.store import (
    InMemoryDeadLetterQueue,
    InMemoryEventStore,
)
from hunterx.infrastructure.health import HealthProbe, HealthRegistry
from hunterx.infrastructure.metrics import InMemoryMetrics
from hunterx.infrastructure.telemetry.providers import (
    MemoryTelemetryProvider,
    PrometheusTelemetryProvider,
    build_provider,
)
from hunterx.infrastructure.tracing import InMemoryTracer

__all__ = [
    "DomainEvent",
    "EventCategory",
    "EventPriority",
    "EventSeverity",
    "EventStatus",
    "EventRegistry",
    "EventSpec",
    "AuditEventFactory",
    "build_registry",
    "ObservabilityEventBusPort",
    "EventStorePort",
    "DeadLetterQueuePort",
    "MetricsPort",
    "TracerPort",
    "HealthRegistryPort",
    "HealthProbePort",
    "TelemetryProviderPort",
    "EventFilter",
    "EventHandler",
    "InMemoryEventBus",
    "InMemoryEventStore",
    "InMemoryDeadLetterQueue",
    "InMemoryMetrics",
    "InMemoryTracer",
    "HealthProbe",
    "HealthRegistry",
    "MemoryTelemetryProvider",
    "PrometheusTelemetryProvider",
    "build_provider",
    "ObservabilityService",
]
