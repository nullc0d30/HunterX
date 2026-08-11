# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Managers facade.

Thin manager facades over the platform ports. These are the stable, named
components the sprint blueprint calls out (Cache Manager, Queue Manager,
Event Bus, Dependency Manager). Each facade delegates to an injected port so
backends stay swappable.
"""

from __future__ import annotations

from typing import Any, TypeVar

from hunterx.domain.events import DomainEvent
from hunterx.domain.ports.messaging import CachePort, EventBusPort, Handler, QueuePort
from hunterx.shared.di import Container

T = TypeVar("T")


class CacheManager:
    """Namespaced access to a cache backend."""

    def __init__(self, backend: CachePort, *, namespace: str = "hunterx") -> None:
        self._backend = backend
        self._namespace = namespace

    def _key(self, key: str) -> str:
        return f"{self._namespace}:{key}"

    def get(self, key: str) -> Any | None:
        """Return a cached value or ``None``."""
        return self._backend.get(self._key(key))

    def set(self, key: str, value: Any, *, ttl_seconds: int | None = None) -> None:
        """Cache a value with an optional TTL."""
        self._backend.set(self._key(key), value, ttl_seconds=ttl_seconds)

    def delete(self, key: str) -> None:
        """Evict a key."""
        self._backend.delete(self._key(key))

    def flush(self) -> None:
        """Clear the entire cache backend."""
        self._backend.flush()


class QueueManager:
    """Enqueue and dispatch work through a queue backend."""

    def __init__(self, backend: QueuePort) -> None:
        self._backend = backend

    def enqueue(self, job_type: str, payload: dict[str, Any]) -> str:
        """Enqueue a job and return its identifier."""
        return self._backend.enqueue(job_type, payload)

    def claim(self, *, timeout_seconds: float = 5.0) -> tuple[str, str, dict[str, Any]] | None:
        """Claim a job from the queue or return ``None``."""
        return self._backend.dequeue(timeout_seconds=timeout_seconds)

    def ack(self, job_id: str) -> None:
        """Acknowledge a claimed job."""
        self._backend.ack(job_id)

    def nack(self, job_id: str, *, requeue: bool = False) -> None:
        """Reject a claimed job, optionally requeueing it."""
        self._backend.nack(job_id, requeue=requeue)


class EventBus:
    """Publish/subscribe facade over the event bus port."""

    def __init__(self, backend: EventBusPort) -> None:
        self._backend = backend

    def publish(self, event: DomainEvent) -> None:
        """Publish a domain event."""
        self._backend.publish(event)

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Subscribe a handler to an event type."""
        self._backend.subscribe(event_type, handler)

    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        """Unsubscribe a handler from an event type."""
        self._backend.unsubscribe(event_type, handler)


class DependencyManager:
    """Facade over the shared service container."""

    def __init__(self, container: Container[Any] | None = None) -> None:
        self._container = container or Container()

    @property
    def container(self) -> Container[Any]:
        """Return the underlying container."""
        return self._container

    def register(self, key: type[T], factory: Any, *, singleton: bool = False) -> None:
        """Register a factory for a key."""
        self._container.register(key, factory, singleton=singleton)

    def register_instance(self, key: type[T], instance: T) -> None:
        """Register an already-built instance."""
        self._container.register_instance(key, instance)

    def resolve(self, key: type[T]) -> T:
        """Resolve a service by key."""
        return self._container.resolve(key)
