# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Event bus adapters.

The :class:`InMemoryEventBus` is the default (and only shipped) event bus. It
implements the enriched :class:`ObservabilityEventBusPort`: exact and
category-prefix routing (``mission.*``), per-subscriber filters, delivery
priorities, failure isolation and introspection. When an event store and a
dead-letter queue are attached, every published event is persisted and
unprocessable events are quarantined.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from hunterx.domain.events import DomainEvent
from hunterx.domain.events.enums import EventPriority, EventStatus
from hunterx.domain.ports.observability import (
    DeadLetterQueuePort,
    EventFilter,
    EventHandler,
    EventStorePort,
    ObservabilityEventBusPort,
)


@dataclass(slots=True)
class _Subscription:
    """A single subscriber registration."""

    event_type: str
    handler: EventHandler
    priority: EventPriority
    filter: EventFilter | None


class InMemoryEventBus(ObservabilityEventBusPort):
    """Synchronous in-process event bus with routing, filtering and priorities.

    Matching rules:

    - An exact subscription (``"mission.started"``) matches that exact type.
    - A category subscription (``"mission.*"``) matches every type whose
      category prefix equals ``mission``.
    - Subscribers with higher :class:`EventPriority` are invoked first.
    - An optional ``filter`` predicate decides per-event delivery.

    Handler failures are isolated per subscriber: one failing handler does not
    prevent others from running. The first failure is collected and re-raised
    by :meth:`publish` (matching the legacy contract). When a ``dead_letter``
    queue is attached, failed events are quarantined there.
    """

    def __init__(
        self,
        *,
        store: EventStorePort | None = None,
        dead_letter: DeadLetterQueuePort | None = None,
    ) -> None:
        self._subscribers: dict[str, list[_Subscription]] = defaultdict(list)
        self._lock = threading.RLock()
        self._store = store
        self._dead_letter = dead_letter

    # -- lifecycle ----------------------------------------------------------

    def attach_store(self, store: EventStorePort) -> None:
        """Attach an event store; published events are persisted from now on."""
        self._store = store

    def attach_dead_letter(self, dead_letter: DeadLetterQueuePort) -> None:
        """Attach a dead-letter queue; failed events are quarantined."""
        self._dead_letter = dead_letter

    # -- publish/subscribe --------------------------------------------------

    def publish(
        self,
        event: DomainEvent,
        *,
        priority: EventPriority = EventPriority.NORMAL,
    ) -> None:
        """Dispatch ``event`` to all matching handlers.

        The event is first persisted (when a store is attached), then delivered
        to matching subscribers ordered by priority. The ``priority`` argument
        is accepted for port compatibility; per-subscriber priorities govern
        the delivery order.
        """
        if self._store is not None:
            self._store.append(event)
        with self._lock:
            candidates = [sub for sub in self._all_subscriptions() if _matches(sub, event)]
            candidates.sort(key=lambda sub: sub.priority, reverse=True)

        first_error: Exception | None = None
        failed: DomainEvent | None = None
        for sub in candidates:
            if sub.filter is not None and not sub.filter(event):
                continue
            try:
                sub.handler(event)
            except Exception as exc:  # noqa: BLE001 - isolate handler failures
                if first_error is None:
                    first_error = exc
                    failed = event
        if failed is not None and self._dead_letter is not None:
            self._dead_letter.push(failed, str(first_error))
        if self._store is not None:
            self._store.mark(event.event_id, EventStatus.DELIVERED.value)
        if first_error is not None:
            raise first_error

    def subscribe(
        self,
        event_type: str,
        handler: EventHandler,
        *,
        priority: EventPriority = EventPriority.NORMAL,
        filter: EventFilter | None = None,
    ) -> None:
        """Subscribe ``handler`` to ``event_type`` (exact or ``cat.*``)."""
        sub = _Subscription(event_type=event_type, handler=handler, priority=priority, filter=filter)
        with self._lock:
            for existing in self._subscribers[event_type]:
                if existing.handler is handler:
                    return
            self._subscribers[event_type].append(sub)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a previously registered subscription."""
        with self._lock:
            subs = self._subscribers.get(event_type, [])
            self._subscribers[event_type] = [sub for sub in subs if sub.handler is not handler]

    def subscriptions(self) -> list[dict[str, Any]]:
        """Return an introspection snapshot of active subscriptions."""
        with self._lock:
            return [
                {
                    "event_type": sub.event_type,
                    "priority": sub.priority.value,
                    "filtered": sub.filter is not None,
                }
                for sub in self._all_subscriptions()
            ]

    # -- internal -----------------------------------------------------------

    def _all_subscriptions(self) -> list[_Subscription]:
        return [sub for subs in self._subscribers.values() for sub in subs]


def _matches(subscription: _Subscription, event: DomainEvent) -> bool:
    """Return ``True`` when a subscription's type pattern matches an event."""
    pattern = subscription.event_type
    if pattern.endswith(".*"):
        return event.event_type.startswith(f"{pattern[:-2]}.")
    if pattern.endswith(".#"):
        return event.event_type == pattern[:-2] or event.event_type.startswith(f"{pattern[:-2]}.")
    return event.event_type == pattern


# Backward-compatible alias: the messaging port name still resolves here.
EventBus = InMemoryEventBus
