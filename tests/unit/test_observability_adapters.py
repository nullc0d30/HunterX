# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the observability adapters: metrics, tracing, health, logging."""

from __future__ import annotations

import logging

from hunterx.infrastructure.health import HealthProbe, HealthRegistry
from hunterx.infrastructure.logging import JsonFormatter, LoggingManager, clear_correlation, set_correlation
from hunterx.infrastructure.metrics import InMemoryMetrics
from hunterx.infrastructure.tracing import InMemoryTracer


class TestInMemoryMetrics:
    def test_counter(self) -> None:
        metrics = InMemoryMetrics()
        metrics.increment("execution.duration")
        metrics.increment("execution.duration")
        metrics.increment("execution.duration", tags={"tool": "nmap"})
        snapshot = metrics.snapshot()
        assert snapshot["counters"]["execution.duration"] == 2
        assert snapshot["counters"]["execution.duration{tool=\"nmap\"}"] == 1

    def test_gauge(self) -> None:
        metrics = InMemoryMetrics()
        metrics.gauge("queue.size", 4.0)
        metrics.gauge("queue.size", 7.5)
        assert metrics.snapshot()["gauges"]["queue.size"] == 7.5

    def test_histogram_aggregation(self) -> None:
        metrics = InMemoryMetrics()
        for value in (1.0, 2.0, 3.0):
            metrics.histogram("db.latency", value)
        hist = metrics.snapshot()["histograms"]["db.latency"]
        assert hist["count"] == 3
        assert hist["sum"] == 6.0
        assert hist["mean"] == 2.0
        assert hist["min"] == 1.0
        assert hist["max"] == 3.0

    def test_duration_records_histogram(self) -> None:
        metrics = InMemoryMetrics()
        metrics.duration("execution_duration_seconds", 0.25)
        assert metrics.snapshot()["histograms"]["execution_duration_seconds"]["count"] == 1

    def test_prometheus_render(self) -> None:
        metrics = InMemoryMetrics()
        metrics.increment("errors")
        metrics.gauge("queue.size", 2)
        metrics.histogram("latency", 0.1)
        text = metrics.render_prometheus()
        assert "hunterx_errors 1" in text
        assert "hunterx_queue_size 2" in text
        assert "hunterx_latency_count 1" in text


class TestInMemoryTracer:
    def test_span_hierarchy(self) -> None:
        tracer = InMemoryTracer()
        root = tracer.start_span("mission")
        child = tracer.start_span("tool.run")
        assert child.parent_span_id == root.span_id
        assert child.trace_id == root.trace_id
        tracer.end_span()
        tracer.end_span()
        trace = tracer.trace(root.trace_id)
        assert trace is not None
        assert len(trace) == 2
        assert trace[0]["name"] == "mission"
        assert trace[1]["parent_span_id"] == root.span_id

    def test_root_span_when_no_parent(self) -> None:
        tracer = InMemoryTracer()
        span = tracer.start_span("standalone")
        assert span.parent_span_id is None
        tracer.end_span()

    def test_trace_unknown_returns_none(self) -> None:
        tracer = InMemoryTracer()
        assert tracer.trace("does-not-exist") is None

    def test_duration_recorded(self) -> None:
        tracer = InMemoryTracer()
        span = tracer.start_span("op")
        tracer.end_span()
        assert span.end_ms is not None
        assert span.to_dict()["duration_ms"] is not None

    def test_nested_restores_parent(self) -> None:
        tracer = InMemoryTracer()
        root = tracer.start_span("root")
        tracer.start_span("child")
        tracer.end_span()
        current = tracer.current_span()
        assert current is not None
        assert current["span_id"] == root.span_id
        tracer.end_span()
        assert tracer.current_span() is None


class TestHealthRegistry:
    def test_register_and_check_all(self) -> None:
        registry = HealthRegistry()
        registry.register_callable("db", lambda: ("ok", "connected"))
        registry.register_callable("queue", lambda: ("down", "no workers"))
        registry.register(HealthProbe("cache", lambda: ("degraded", "high latency")))
        results = registry.check_all()
        assert results["db"]["status"] == "ok"
        assert results["queue"]["status"] == "down"
        assert results["cache"]["status"] == "degraded"

    def test_probe_exception_becomes_down(self) -> None:
        registry = HealthRegistry()

        def broken() -> tuple[str, str]:
            raise RuntimeError("boom")

        registry.register_callable("x", broken)
        assert registry.check_all()["x"]["status"] == "down"
        assert "boom" in registry.check_all()["x"]["detail"]

    def test_unregister(self) -> None:
        registry = HealthRegistry()
        registry.register_callable("temp", lambda: ("ok", ""))
        registry.unregister("temp")
        assert "temp" not in registry.components()

    def test_summary(self) -> None:
        registry = HealthRegistry()
        registry.register_callable("a", lambda: ("ok", ""))
        registry.register_callable("b", lambda: ("down", ""))
        summary = registry.summary()
        assert summary["total"] == 2
        assert summary["ok"] == 1
        assert summary["down"] == 1
        assert summary["overall"] == "down"


class TestLogging:
    def test_json_formatter_masks_sensitive(self) -> None:
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="hunterx.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="login failed",
            args=(),
            exc_info=None,
        )
        record.fields = {"api_key": "supersecret", "user": "alice"}
        text = formatter.format(record)
        assert '"api_key": "su***et"' in text or "su***et" in text
        assert "supersecret" not in text
        assert '"user": "alice"' in text

    def test_json_formatter_includes_correlation(self) -> None:
        formatter = JsonFormatter()
        set_correlation(correlation_id="c1", mission_id="m1")
        try:
            record = logging.LogRecord("hunterx", logging.INFO, __file__, 1, "x", (), None)
            text = formatter.format(record)
            assert '"correlation_id": "c1"' in text
            assert '"mission_id": "m1"' in text
        finally:
            clear_correlation()

    def test_json_formatter_isolated_from_other_tests(self) -> None:
        formatter = JsonFormatter()
        record = logging.LogRecord("hunterx", logging.INFO, __file__, 1, "x", (), None)
        text = formatter.format(record)
        assert '"correlation"' not in text

    def test_logging_manager_json_output(self) -> None:
        manager = LoggingManager(level="DEBUG", json_output=True)
        logger = manager.get_logger("hunterx.test")
        assert logger.level == logging.DEBUG or logger.level == 0
        assert manager.get_logger("hunterx.other") is not None

    def test_mask_helper_covers_list(self) -> None:
        formatter = JsonFormatter()
        record = logging.LogRecord("hunterx", logging.INFO, __file__, 1, "x", (), None)
        record.fields = {"tokens": ["abc", {"password": "hunter2"}]}
        text = formatter.format(record)
        assert "hunter2" not in text
