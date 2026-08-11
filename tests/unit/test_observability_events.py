# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the event domain model: envelope, enums, registry, catalog."""

from __future__ import annotations

import pytest

from hunterx.domain.events import DomainEvent, EventCategory, EventRegistry, EventSeverity, EventSpec
from hunterx.domain.events.audit import AuditEventFactory
from hunterx.domain.events.catalog import build_catalog, build_registry
from hunterx.domain.events.enums import EventPriority


class TestEventEnvelope:
    def test_full_metadata_envelope(self) -> None:
        event = DomainEvent(
            event_type="mission.started",
            payload={"mission_id": "m1"},
            source="mission.engine",
            correlation_id="corr-1",
            causation_id="cause-1",
            mission_id="m1",
            execution_id="e1",
            consumer="reporting",
            severity=EventSeverity.WARNING,
            category=EventCategory.MISSION,
            payload_version=2,
        )
        assert event.event_id
        assert event.occurred_at
        assert event.correlation_id == "corr-1"
        assert event.causation_id == "cause-1"
        assert event.mission_id == "m1"
        assert event.execution_id == "e1"
        assert event.consumer == "reporting"
        assert event.severity == EventSeverity.WARNING
        assert event.category == EventCategory.MISSION
        assert event.payload_version == 2
        assert event.producer == "mission.engine"

    def test_defaults_are_system_information(self) -> None:
        event = DomainEvent(event_type="finding.created", payload={"a": 1})
        assert event.severity == EventSeverity.INFO
        assert event.category == EventCategory.SYSTEM
        assert event.payload_version == 1
        assert event.correlation_id is None
        assert event.causation_id is None

    def test_to_dict_includes_envelope(self) -> None:
        event = DomainEvent(event_type="finding.created", payload={"a": 1})
        payload = event.to_dict()
        assert payload["event_id"] == event.event_id
        assert payload["category"] == "system"
        assert payload["severity"] == "info"
        assert payload["payload_version"] == 1
        assert payload["correlation_id"] is None

    def test_legacy_construction_unchanged(self) -> None:
        event = DomainEvent(event_type="mission.started", payload={"mission_id": "m"})
        assert event.event_type == "mission.started"
        assert event.payload == {"mission_id": "m"}


class TestEventRegistry:
    def test_register_and_get(self) -> None:
        registry = EventRegistry()
        spec = EventSpec(
            event_type="mission.started",
            category=EventCategory.MISSION,
            payload_version=1,
            description="test",
        )
        registry.register(spec)
        assert registry.get("mission.started") is spec
        assert registry.has("mission.started")
        assert registry.require("mission.started") is spec

    def test_require_unknown_raises(self) -> None:
        registry = EventRegistry()
        with pytest.raises(KeyError):
            registry.require("nope.nothing")

    def test_for_category_and_categories(self) -> None:
        registry = EventRegistry()
        registry.register_many(
            [
                EventSpec("mission.started", EventCategory.MISSION),
                EventSpec("mission.failed", EventCategory.MISSION),
                EventSpec("tool.executed", EventCategory.TOOL),
            ]
        )
        assert len(registry.for_category(EventCategory.MISSION)) == 2
        assert EventCategory.MISSION in registry.categories()
        assert EventCategory.TOOL in registry.categories()

    def test_unknown_types(self) -> None:
        registry = EventRegistry()
        registry.register(EventSpec("a.b", EventCategory.SYSTEM))
        assert registry.unknown_types(["a.b", "x.y"]) == ["x.y"]

    def test_payload_version_support(self) -> None:
        spec = EventSpec("a.b", EventCategory.SYSTEM, payload_version=3, versions={1: "v1", 2: "v2"})
        assert spec.supports(1)
        assert spec.supports(3)
        assert not spec.supports(4)


class TestEventCatalog:
    def test_catalog_covers_all_13_categories(self) -> None:
        specs = build_catalog()
        categories = {spec.category for spec in specs}
        assert categories == set(EventCategory)

    def test_catalog_has_unique_event_types(self) -> None:
        specs = build_catalog()
        names = [spec.event_type for spec in specs]
        assert len(names) == len(set(names))

    def test_build_registry_has_canonical_types(self) -> None:
        registry = build_registry()
        assert registry.has("mission.started")
        assert registry.has("tool.executed")
        assert registry.has("database.updated")
        assert registry.has("security.authenticated")
        assert registry.has("ai.completed")


class TestAuditEventFactory:
    def test_authentication(self) -> None:
        event = AuditEventFactory.authentication("alice", succeeded=True)
        assert event.event_type == "security.authenticated"
        assert event.category == EventCategory.SECURITY
        assert event.payload["actor"] == "alice"

    def test_authorization_denied(self) -> None:
        event = AuditEventFactory.authorization("bob", "delete", allowed=False, resource="target/x")
        assert event.event_type == "security.denied"
        assert event.payload["allowed"] is False

    def test_mission_lifecycle(self) -> None:
        event = AuditEventFactory.mission_lifecycle("m1", "completed")
        assert event.event_type == "mission.completed"
        assert event.mission_id == "m1"

    def test_database_change(self) -> None:
        event = AuditEventFactory.database_change("INSERT", "targets", record_id="t1")
        assert event.event_type == "database.updated"
        assert event.payload["table"] == "targets"

    def test_priorities_are_int_comparable(self) -> None:
        assert EventPriority.CRITICAL > EventPriority.HIGH > EventPriority.NORMAL > EventPriority.LOW
        assert int(EventPriority.CRITICAL) == 3
