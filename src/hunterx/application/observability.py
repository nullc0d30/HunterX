# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Observability application service.

The unified internal API over the observability platform: publishing and
subscribing to events, collecting metrics, tracing spans, checking health and
exporting telemetry. Subsystems (engines, tools, plugins, schedulers) use this
service instead of reaching into infrastructure directly.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.events import DomainEvent
from hunterx.domain.events.enums import EventPriority
from hunterx.domain.events.spec import EventRegistry
from hunterx.domain.ports.observability import (
    DeadLetterQueuePort,
    EventFilter,
    EventHandler,
    EventStorePort,
    HealthRegistryPort,
    MetricsPort,
    ObservabilityEventBusPort,
    TelemetryProviderPort,
    TracerPort,
)


class ObservabilityService:
    """Facade over the event bus and observability subsystems.

    Attributes:
        bus: the enriched event bus.
        registry: canonical event catalog.
        metrics: metric collector.
        tracer: distributed tracer.
        health: health probe registry.
        store: event persistence (may be ``None``).
        dead_letter: dead-letter queue (may be ``None``).
        telemetry: aggregate telemetry provider.

    """

    def __init__(
        self,
        *,
        bus: ObservabilityEventBusPort,
        registry: EventRegistry,
        metrics: MetricsPort,
        tracer: TracerPort,
        health: HealthRegistryPort,
        store: EventStorePort | None = None,
        dead_letter: DeadLetterQueuePort | None = None,
        telemetry: TelemetryProviderPort | None = None,
    ) -> None:
        self.bus = bus
        self.registry = registry
        self.metrics = metrics
        self.tracer = tracer
        self.health = health
        self.store = store
        self.dead_letter = dead_letter
        self._telemetry = telemetry

    # -- events -------------------------------------------------------------

    def publish(
        self,
        event: DomainEvent,
        *,
        priority: EventPriority = EventPriority.NORMAL,
    ) -> None:
        """Publish a domain event on the bus."""
        self.bus.publish(event, priority=priority)

    def subscribe(
        self,
        event_type: str,
        handler: EventHandler,
        *,
        priority: EventPriority = EventPriority.NORMAL,
        filter: EventFilter | None = None,
    ) -> None:
        """Subscribe ``handler`` to ``event_type`` (exact or ``cat.*``)."""
        self.bus.subscribe(event_type, handler, priority=priority, filter=filter)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a subscription."""
        self.bus.unsubscribe(event_type, handler)

    def event_catalog(self) -> list[dict[str, Any]]:
        """Return the serialized canonical event catalog."""
        return self.registry.to_dict()

    # -- metrics ------------------------------------------------------------

    def increment(self, name: str, *, value: int = 1, tags: dict[str, str] | None = None) -> None:
        """Increment a counter metric."""
        self.metrics.increment(name, value=value, tags=tags)

    def gauge(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Record a gauge metric."""
        self.metrics.gauge(name, value, tags=tags)

    def histogram(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Observe a histogram metric."""
        self.metrics.histogram(name, value, tags=tags)

    def duration(self, name: str, seconds: float, *, tags: dict[str, str] | None = None) -> None:
        """Record a duration metric."""
        self.metrics.duration(name, seconds, tags=tags)

    def metrics_snapshot(self) -> dict[str, Any]:
        """Return a serializable metrics snapshot."""
        return self.metrics.snapshot()

    # -- tracing ------------------------------------------------------------

    def start_span(
        self,
        name: str,
        *,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Any:
        """Start a span and make it current."""
        return self.tracer.start_span(
            name, trace_id=trace_id, parent_span_id=parent_span_id, attributes=attributes
        )

    def end_span(self, *, attributes: dict[str, Any] | None = None) -> Any | None:
        """End the current span."""
        return self.tracer.end_span(attributes=attributes)

    def trace(self, trace_id: str) -> list[dict[str, Any]] | None:
        """Return every span of a trace."""
        return self.tracer.trace(trace_id)

    # -- health -------------------------------------------------------------

    def check_health(self) -> dict[str, Any]:
        """Run all health probes and return a unified status report."""
        return self.health.check_all()

    # -- persistence / replay / dlq -----------------------------------------

    def persisted_events(self, *, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Return a paginated slice of persisted events (empty when no store)."""
        if self.store is None:
            return []
        return self.store.list(offset=offset, limit=limit)

    def replay(self, *, event_type: str | None = None, limit: int = 0) -> list[DomainEvent]:
        """Replay persisted events (optionally filtered)."""
        if self.store is None:
            return []
        return self.store.replay(event_type=event_type, limit=limit)

    def dead_letter_events(self) -> list[dict[str, Any]]:
        """Return dead-lettered events (empty when no DLQ)."""
        if self.dead_letter is None:
            return []
        return self.dead_letter.list()

    def requeue_dead_letter(self, event_id: str) -> DomainEvent | None:
        """Requeue a dead-lettered event onto the bus."""
        if self.dead_letter is None:
            return None
        event = self.dead_letter.requeue(event_id)
        if event is not None:
            self.bus.publish(event)
        return event

    # -- telemetry ----------------------------------------------------------

    def export_telemetry(self) -> str:
        """Return the provider telemetry export payload."""
        if self._telemetry is None:
            return ""
        return self._telemetry.export()
