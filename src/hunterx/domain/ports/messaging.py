# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Messaging ports: event bus, queue and cache."""

from __future__ import annotations

import abc
from collections.abc import Callable
from typing import Any

from hunterx.domain.events import DomainEvent

Handler = Callable[[DomainEvent], None]


class EventBusPort(abc.ABC):
    """In-process / distributed event bus contract."""

    @abc.abstractmethod
    def publish(self, event: DomainEvent) -> None:
        """Dispatch an event to all subscribed handlers."""

    @abc.abstractmethod
    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Subscribe ``handler`` to events of type ``event_type``."""

    @abc.abstractmethod
    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        """Remove a previously subscribed handler."""


class QueuePort(abc.ABC):
    """Work-queue contract for async task dispatch."""

    @abc.abstractmethod
    def enqueue(self, job_type: str, payload: dict[str, Any]) -> str:
        """Queue a job and return its identifier."""

    @abc.abstractmethod
    def dequeue(self, *, timeout_seconds: float = 5.0) -> tuple[str, str, dict[str, Any]] | None:
        """Claim a job, returning ``(job_id, job_type, payload)`` or ``None``."""

    @abc.abstractmethod
    def ack(self, job_id: str) -> None:
        """Mark a claimed job as successfully processed."""

    @abc.abstractmethod
    def nack(self, job_id: str, *, requeue: bool = False) -> None:
        """Reject a claimed job, optionally returning it to the queue."""


class CachePort(abc.ABC):
    """Distributed key-value cache contract."""

    @abc.abstractmethod
    def get(self, key: str) -> Any | None:
        """Return the cached value for ``key``, or ``None`` when absent."""

    @abc.abstractmethod
    def set(self, key: str, value: Any, *, ttl_seconds: int | None = None) -> None:
        """Store ``value`` under ``key`` with an optional TTL."""

    @abc.abstractmethod
    def delete(self, key: str) -> None:
        """Delete the cached value for ``key``."""

    @abc.abstractmethod
    def flush(self) -> None:
        """Remove all cached entries."""
