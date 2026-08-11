# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the enriched event bus: routing, filtering, priorities,
persistence, dead-letter queue and replay."""

from __future__ import annotations

from hunterx.domain.events import DomainEvent
from hunterx.domain.events.enums import EventCategory, EventPriority, EventSeverity
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.event_bus.store import (
    InMemoryDeadLetterQueue,
    InMemoryEventStore,
)


def _event(event_type: str, **payload: object) -> DomainEvent:
    category = event_type.split(".")[0]
    return DomainEvent(
        event_type=event_type,
        payload=payload,
        category=EventCategory(category),
        severity=EventSeverity.INFO,
    )


class TestRouting:
    def test_exact_type_subscription(self) -> None:
        bus = InMemoryEventBus()
        received: list[str] = []
        bus.subscribe("mission.started", lambda e: received.append(e.event_type))
        bus.publish(_event("mission.started"))
        bus.publish(_event("mission.completed"))
        assert received == ["mission.started"]

    def test_category_wildcard_subscription(self) -> None:
        bus = InMemoryEventBus()
        received: list[str] = []
        bus.subscribe("mission.*", lambda e: received.append(e.event_type))
        bus.publish(_event("mission.started"))
        bus.publish(_event("mission.failed"))
        bus.publish(_event("tool.executed"))
        assert received == ["mission.started", "mission.failed"]

    def test_unsubscribe(self) -> None:
        bus = InMemoryEventBus()
        received: list[str] = []

        def handler(event: DomainEvent) -> None:
            received.append(event.event_type)

        bus.subscribe("mission.*", handler)
        bus.unsubscribe("mission.*", handler)
        bus.publish(_event("mission.started"))
        assert received == []


class TestPriorities:
    def test_priority_ordering(self) -> None:
        bus = InMemoryEventBus()
        order: list[str] = []
        bus.subscribe("mission.*", lambda e: order.append("normal"), priority=EventPriority.NORMAL)
        bus.subscribe("mission.*", lambda e: order.append("critical"), priority=EventPriority.CRITICAL)
        bus.subscribe("mission.*", lambda e: order.append("low"), priority=EventPriority.LOW)
        bus.publish(_event("mission.started"))
        assert order == ["critical", "normal", "low"]

    def test_same_priority_keeps_subscription_order(self) -> None:
        bus = InMemoryEventBus()
        order: list[str] = []
        bus.subscribe("mission.*", lambda e: order.append("a"))
        bus.subscribe("mission.*", lambda e: order.append("b"))
        bus.publish(_event("mission.started"))
        assert order == ["a", "b"]


class TestFiltering:
    def test_filter_restricts_delivery(self) -> None:
        bus = InMemoryEventBus()
        received: list[DomainEvent] = []
        bus.subscribe(
            "mission.*",
            received.append,
            filter=lambda e: e.payload.get("critical") is True,
        )
        bus.publish(_event("mission.started", critical=False))
        bus.publish(_event("mission.started", critical=True))
        assert len(received) == 1
        assert received[0].payload["critical"] is True


class TestFailureIsolation:
    def test_failure_isolated_and_reraises(self) -> None:
        bus = InMemoryEventBus()
        ok: list[str] = []

        def failing(_event: DomainEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe("mission.*", failing)
        bus.subscribe("mission.*", lambda e: ok.append(e.event_type))
        import pytest

        with pytest.raises(RuntimeError, match="boom"):
            bus.publish(_event("mission.started"))
        assert ok == ["mission.started"]


class TestPersistenceAndReplay:
    def test_store_records_published_events(self) -> None:
        store = InMemoryEventStore()
        bus = InMemoryEventBus(store=store)
        bus.publish(_event("mission.started", mission_id="m1"))
        bus.publish(_event("tool.executed", tool="nmap"))
        assert store.count() == 2
        assert store.list()[0]["event_type"] == "mission.started"

    def test_replay_filters_by_type(self) -> None:
        store = InMemoryEventStore()
        bus = InMemoryEventBus(store=store)
        bus.publish(_event("mission.started"))
        bus.publish(_event("mission.failed"))
        bus.publish(_event("tool.executed"))
        replayed = store.replay(event_type="mission.*")
        assert [e.event_type for e in replayed] == ["mission.started", "mission.failed"]

    def test_replay_limited(self) -> None:
        store = InMemoryEventStore()
        bus = InMemoryEventBus(store=store)
        for _ in range(5):
            bus.publish(_event("mission.started"))
        assert len(store.replay(limit=2)) == 2

    def test_get_and_pagination(self) -> None:
        store = InMemoryEventStore()
        bus = InMemoryEventBus(store=store)
        bus.publish(_event("mission.started"))
        event_id = store.list()[0]["event_id"]
        assert store.get(event_id)["event_type"] == "mission.started"
        assert store.get("nope") is None
        assert store.list(offset=0, limit=1)[0]["event_id"] == event_id


class TestDeadLetterQueue:
    def test_failed_event_goes_to_dlq(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        store = InMemoryEventStore()
        bus = InMemoryEventBus(store=store, dead_letter=dlq)

        def failing(_event: DomainEvent) -> None:
            raise ValueError("handler failure")

        bus.subscribe("mission.*", failing)
        import pytest

        with pytest.raises(ValueError):
            bus.publish(_event("mission.started"))
        assert dlq.count() == 1
        assert dlq.list()[0]["error"] == "handler failure"
        assert dlq.list()[0]["event_type"] == "mission.started"

    def test_requeue_dead_letter(self) -> None:
        dlq = InMemoryDeadLetterQueue()
        store = InMemoryEventStore()
        bus = InMemoryEventBus(store=store, dead_letter=dlq)

        def failing(_event: DomainEvent) -> None:
            raise RuntimeError("x")

        bus.subscribe("mission.*", failing)
        import pytest

        with pytest.raises(RuntimeError):
            bus.publish(_event("mission.started"))
        event_id = dlq.list()[0]["event_id"]

        recovered = dlq.requeue(event_id)
        assert recovered is not None
        assert recovered.event_type == "mission.started"
        assert dlq.count() == 0


class TestIntrospection:
    def test_subscriptions_snapshot(self) -> None:
        bus = InMemoryEventBus()

        def handler(_event: DomainEvent) -> None:
            pass

        bus.subscribe("mission.*", handler, priority=EventPriority.HIGH, filter=lambda e: True)
        snapshot = bus.subscriptions()
        assert snapshot[0]["event_type"] == "mission.*"
        assert snapshot[0]["priority"] == EventPriority.HIGH.value
        assert snapshot[0]["filtered"] is True


class TestBackwardCompatibility:
    def test_legacy_publish_subscribe_signatures(self) -> None:
        bus = InMemoryEventBus()
        received: list[str] = []
        bus.subscribe("mission.started", lambda e: received.append(e.event_type))
        bus.publish(_event("mission.started"))
        assert received == ["mission.started"]
