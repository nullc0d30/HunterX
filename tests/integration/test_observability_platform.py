# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the observability platform: service wiring, the
platform composition root, telemetry providers and dashboard models."""

from __future__ import annotations

from hunterx.application.observability import ObservabilityService
from hunterx.domain.entities.dashboard import dashboard_definitions
from hunterx.domain.events import DomainEvent
from hunterx.domain.events.catalog import build_registry
from hunterx.domain.events.enums import EventCategory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.event_bus.store import (
    InMemoryDeadLetterQueue,
    InMemoryEventStore,
)
from hunterx.infrastructure.health import HealthRegistry
from hunterx.infrastructure.metrics import InMemoryMetrics
from hunterx.infrastructure.telemetry.providers import (
    MemoryTelemetryProvider,
    build_provider,
)
from hunterx.infrastructure.tracing import InMemoryTracer
from hunterx.platform.assembler import build_platform


def _make_service() -> ObservabilityService:
    store = InMemoryEventStore()
    dlq = InMemoryDeadLetterQueue()
    bus = InMemoryEventBus(store=store, dead_letter=dlq)
    metrics = InMemoryMetrics()
    tracer = InMemoryTracer()
    return ObservabilityService(
        bus=bus,
        registry=build_registry(),
        metrics=metrics,
        tracer=tracer,
        health=HealthRegistry(),
        store=store,
        dead_letter=dlq,
        telemetry=MemoryTelemetryProvider(metrics=metrics, tracer=tracer),
    )


class TestObservabilityService:
    def test_publish_and_subscribe(self) -> None:
        svc = _make_service()
        seen: list[str] = []
        svc.subscribe("mission.*", lambda e: seen.append(e.event_type))
        event = DomainEvent(event_type="mission.started", payload={}, category=EventCategory.MISSION)
        svc.publish(event)
        assert seen == ["mission.started"]

    def test_event_catalog(self) -> None:
        svc = _make_service()
        catalog = svc.event_catalog()
        assert any(entry["event_type"] == "mission.started" for entry in catalog)
        assert len(catalog) >= 50

    def test_metrics_and_export(self) -> None:
        svc = _make_service()
        svc.increment("errors")
        svc.gauge("queue.size", 3)
        svc.duration("mission_duration_seconds", 1.5)
        snapshot = svc.metrics_snapshot()
        assert snapshot["counters"]["errors"] == 1
        assert snapshot["gauges"]["queue.size"] == 3
        export = svc.export_telemetry()
        assert "hunterx_errors 1" in export

    def test_tracing_roundtrip(self) -> None:
        svc = _make_service()
        svc.start_span("mission")
        svc.start_span("tool")
        svc.end_span()
        svc.end_span()
        traces = svc.tracer.traces()
        assert len(traces) == 1
        assert len(svc.trace(traces[0])) == 2

    def test_health(self) -> None:
        svc = _make_service()
        svc.health.register_callable("db", lambda: ("ok", "connected"))
        result = svc.check_health()
        assert result["db"]["status"] == "ok"

    def test_replay_via_service(self) -> None:
        svc = _make_service()
        svc.publish(DomainEvent(event_type="mission.started", payload={}, category=EventCategory.MISSION))
        svc.publish(DomainEvent(event_type="mission.completed", payload={}, category=EventCategory.MISSION))
        assert len(svc.persisted_events()) == 2
        replayed = svc.replay(event_type="mission.started")
        assert len(replayed) == 1
        assert replayed[0].event_type == "mission.started"

    def test_dead_letter_requeue_via_service(self) -> None:
        svc = _make_service()

        def failing(_event: DomainEvent) -> None:
            raise RuntimeError("x")

        svc.subscribe("mission.*", failing)
        import pytest

        with pytest.raises(RuntimeError):
            svc.publish(DomainEvent(event_type="mission.started", payload={}, category=EventCategory.MISSION))
        assert len(svc.dead_letter_events()) == 1
        svc.unsubscribe("mission.*", failing)
        event = svc.requeue_dead_letter(svc.dead_letter_events()[0]["event_id"])
        assert event is not None
        assert event.event_type == "mission.started"


class TestPlatformObservability:
    def test_platform_wires_observability(self) -> None:
        platform = build_platform()
        assert platform.observability is not None
        assert platform.event_registry.has("mission.started")
        assert len(platform.health.components()) == 10
        assert platform.observability.bus is platform.event_bus

    def test_platform_event_flow_persisted(self) -> None:
        platform = build_platform()
        platform.observability.publish(
            DomainEvent(event_type="tool.executed", payload={"tool": "nmap"}, category=EventCategory.TOOL)
        )
        assert len(platform.observability.persisted_events()) == 1

    def test_platform_health_check(self) -> None:
        platform = build_platform()
        report = platform.check_health() if hasattr(platform, "check_health") else platform.observability.check_health()
        assert len(report) == 10


class TestTelemetryProviders:
    def test_memory_provider(self) -> None:
        provider = build_provider("memory")
        provider.metrics().increment("x")
        assert "hunterx_x 1" in provider.export()

    def test_prometheus_provider(self) -> None:
        provider = build_provider("prometheus")
        provider.metrics().gauge("cpu", 12.5)
        assert "hunterx_cpu 12.5" in provider.export()

    def test_otel_provider_degrades_gracefully(self) -> None:
        provider = build_provider("otel")
        provider.metrics().increment("y")
        assert "hunterx_y 1" in provider.export()

    def test_unknown_kind_falls_back_to_memory(self) -> None:
        provider = build_provider("totally-unknown")
        assert isinstance(provider, MemoryTelemetryProvider)


class TestDashboardModels:
    def test_dashboard_definitions(self) -> None:
        dashboards = dashboard_definitions()
        names = {d["name"] for d in dashboards}
        assert names == {"overview", "missions", "health", "events"}
        overview = next(d for d in dashboards if d["name"] == "overview")
        assert overview["refresh_seconds"] == 15
        assert any(p["title"] == "Error Rate" for p in overview["panels"])
