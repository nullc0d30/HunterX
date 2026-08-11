# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Observability ports.

The observability contracts every subsystem depends on: an enriched event bus
(publish/subscribe with routing, filtering and priorities), an event store
with dead-letter queue and replay, metrics, distributed tracing and health
probes. Infrastructure adapters implement these ports; the domain never
imports a concrete adapter.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from typing import Any

from hunterx.domain.events import DomainEvent
from hunterx.domain.events.enums import EventPriority
from hunterx.domain.events.spec import EventRegistry
from hunterx.domain.ports.messaging import EventBusPort as MessagingEventBusPort

#: Predicate deciding whether a subscriber should receive an event.
EventFilter = Callable[[DomainEvent], bool]

#: Synchronous subscriber callback.
EventHandler = Callable[[DomainEvent], None]


class ObservabilityEventBusPort(MessagingEventBusPort):
    """Enriched publish/subscribe contract.

    Extends the messaging contract with category-prefix routing, per-subscriber
    filtering, delivery priorities and introspection.
    """

    @abc.abstractmethod
    def publish(
        self,
        event: DomainEvent,
        *,
        priority: EventPriority = EventPriority.NORMAL,
    ) -> None:
        """Dispatch ``event`` to all matching handlers."""

    @abc.abstractmethod
    def subscribe(
        self,
        event_type: str,
        handler: EventHandler,
        *,
        priority: EventPriority = EventPriority.NORMAL,
        filter: EventFilter | None = None,
    ) -> None:
        """Subscribe ``handler`` to ``event_type`` (exact or ``cat.*`` prefix)."""

    @abc.abstractmethod
    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a previously registered subscription."""

    @abc.abstractmethod
    def subscriptions(self) -> list[dict[str, Any]]:
        """Return an introspection snapshot of active subscriptions."""


class EventStorePort(abc.ABC):
    """Append-only persistence for published events, with replay and DLQ."""

    @abc.abstractmethod
    def append(self, event: DomainEvent) -> None:
        """Persist an event."""

    @abc.abstractmethod
    def mark(self, event_id: str, status: str) -> None:
        """Update the delivery status of a persisted event."""

    @abc.abstractmethod
    def get(self, event_id: str) -> dict[str, Any] | None:
        """Return a persisted event mapping by id, or ``None``."""

    @abc.abstractmethod
    def list(self, *, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Return a paginated slice of persisted events."""

    @abc.abstractmethod
    def count(self) -> int:
        """Return the number of persisted events."""

    @abc.abstractmethod
    def replay(self, *, event_type: str | None = None, limit: int = 0) -> list[DomainEvent]:
        """Return persisted events (optionally filtered) for replay."""


class DeadLetterQueuePort(abc.ABC):
    """Holding area for events whose handlers could not process them."""

    @abc.abstractmethod
    def push(self, event: DomainEvent, error: str) -> None:
        """Move an unprocessable event into the dead-letter queue."""

    @abc.abstractmethod
    def list(self) -> list[dict[str, Any]]:
        """Return every dead-lettered event with its failure reason."""

    @abc.abstractmethod
    def count(self) -> int:
        """Return the number of dead-lettered events."""

    @abc.abstractmethod
    def requeue(self, event_id: str) -> DomainEvent | None:
        """Return a dead-lettered event for redelivery (or ``None``)."""


class MetricsPort(abc.ABC):
    """Numeric metric collection: counters, gauges and histograms."""

    @abc.abstractmethod
    def increment(self, name: str, *, value: int = 1, tags: dict[str, str] | None = None) -> None:
        """Increment a counter metric."""

    @abc.abstractmethod
    def gauge(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Record the current value of a gauge metric."""

    @abc.abstractmethod
    def histogram(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Observe a sample into a histogram metric."""

    @abc.abstractmethod
    def duration(self, name: str, seconds: float, *, tags: dict[str, str] | None = None) -> None:
        """Record a duration (seconds) into a histogram metric."""

    @abc.abstractmethod
    def snapshot(self) -> dict[str, Any]:
        """Return a serializable snapshot of all metrics."""


class TracerPort(abc.ABC):
    """Distributed tracing: span creation, hierarchy and context propagation."""

    @abc.abstractmethod
    def start_span(
        self,
        name: str,
        *,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Any:
        """Start a child (or root) span and make it current."""

    @abc.abstractmethod
    def end_span(self, *, attributes: dict[str, Any] | None = None) -> Any | None:
        """End the current span and return its serialized form."""

    @abc.abstractmethod
    def current_span(self) -> Any | None:
        """Return the current span context, or ``None``."""

    @abc.abstractmethod
    def trace(self, trace_id: str) -> list[dict[str, Any]] | None:
        """Return every span belonging to a trace, in start order."""


class HealthProbePort(abc.ABC):
    """A single component health probe."""

    name: str

    @abc.abstractmethod
    def check(self) -> tuple[str, str]:
        """Return ``(status, detail)`` where status is ok|degraded|down."""


class HealthRegistryPort(abc.ABC):
    """Registry of component health probes."""

    @abc.abstractmethod
    def register(self, probe: HealthProbePort) -> None:
        """Register a component probe."""

    @abc.abstractmethod
    def check_all(self) -> dict[str, dict[str, str]]:
        """Run every probe and return ``{component: {status, detail}}``."""


class TelemetryProviderPort(abc.ABC):
    """Aggregate metrics, tracing and logging provider."""

    @abc.abstractmethod
    def metrics(self) -> MetricsPort:
        """Return the metrics collector."""

    @abc.abstractmethod
    def tracer(self) -> TracerPort:
        """Return the tracer."""

    @abc.abstractmethod
    def export(self) -> str:
        """Return a provider-specific export payload (e.g. Prometheus text)."""


# Re-export the canonical registry type so callers can type the registry.
Registry = EventRegistry
