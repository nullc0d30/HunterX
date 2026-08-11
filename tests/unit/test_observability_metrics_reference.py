# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Metrics reference tests.

Covers the twelve canonical metrics the platform must collect (Development
Bible `Performance Standards`): execution duration, tool runtime, queue size,
mission duration, error/success/failure rates, retry count, memory and CPU
usage, database latency and cache hit ratio.
"""

from __future__ import annotations

import pytest

from hunterx.infrastructure.metrics import InMemoryMetrics


class TestMetricReference:
    def _metrics(self) -> InMemoryMetrics:
        return InMemoryMetrics()

    def test_execution_duration(self) -> None:
        metrics = self._metrics()
        metrics.duration("execution_duration_seconds", 0.42)
        hist = metrics.snapshot()["histograms"]["execution_duration_seconds"]
        assert hist["count"] == 1
        assert hist["sum"] == pytest.approx(0.42)

    def test_tool_runtime(self) -> None:
        metrics = self._metrics()
        metrics.duration("tool_runtime_seconds", 2.5, tags={"tool": "nmap"})
        assert metrics.snapshot()["histograms"]["tool_runtime_seconds{tool=\"nmap\"}"]["count"] == 1

    def test_queue_size(self) -> None:
        metrics = self._metrics()
        metrics.gauge("queue_size", 10)
        metrics.gauge("queue_size", 0)
        assert metrics.snapshot()["gauges"]["queue_size"] == 0

    def test_mission_duration(self) -> None:
        metrics = self._metrics()
        metrics.duration("mission_duration_seconds", 60.0)
        assert metrics.snapshot()["histograms"]["mission_duration_seconds"]["sum"] == pytest.approx(60.0)

    def test_error_success_failure_rates(self) -> None:
        metrics = self._metrics()
        metrics.gauge("error_rate", 0.02)
        metrics.gauge("success_rate", 0.96)
        metrics.gauge("failure_rate", 0.02)
        gauges = metrics.snapshot()["gauges"]
        assert gauges["error_rate"] == 0.02
        assert gauges["success_rate"] == 0.96
        assert gauges["failure_rate"] == 0.02

    def test_retry_count(self) -> None:
        metrics = self._metrics()
        metrics.increment("retry_count")
        metrics.increment("retry_count", tags={"tool": "nuclei"})
        counters = metrics.snapshot()["counters"]
        assert counters["retry_count"] == 1
        assert counters["retry_count{tool=\"nuclei\"}"] == 1

    def test_memory_and_cpu_usage(self) -> None:
        metrics = self._metrics()
        metrics.gauge("memory_usage_bytes", 1_048_576)
        metrics.gauge("cpu_usage_percent", 32.5)
        gauges = metrics.snapshot()["gauges"]
        assert gauges["memory_usage_bytes"] == 1_048_576
        assert gauges["cpu_usage_percent"] == 32.5

    def test_database_latency(self) -> None:
        metrics = self._metrics()
        metrics.duration("database_latency_seconds", 0.005)
        assert metrics.snapshot()["histograms"]["database_latency_seconds"]["count"] == 1

    def test_cache_hit_ratio(self) -> None:
        metrics = self._metrics()
        metrics.gauge("cache_hit_ratio", 0.91)
        assert metrics.snapshot()["gauges"]["cache_hit_ratio"] == 0.91

    def test_all_twelve_metrics_rendered(self) -> None:
        metrics = self._metrics()
        metrics.duration("execution_duration_seconds", 0.1)
        metrics.duration("tool_runtime_seconds", 0.2)
        metrics.gauge("queue_size", 1)
        metrics.duration("mission_duration_seconds", 3.0)
        metrics.gauge("error_rate", 0.1)
        metrics.gauge("success_rate", 0.8)
        metrics.gauge("failure_rate", 0.1)
        metrics.increment("retry_count")
        metrics.gauge("memory_usage_bytes", 100)
        metrics.gauge("cpu_usage_percent", 10)
        metrics.duration("database_latency_seconds", 0.01)
        metrics.gauge("cache_hit_ratio", 0.5)
        text = metrics.render_prometheus()
        for name in (
            "execution_duration_seconds",
            "tool_runtime_seconds",
            "queue_size",
            "mission_duration_seconds",
            "error_rate",
            "success_rate",
            "failure_rate",
            "retry_count",
            "memory_usage_bytes",
            "cpu_usage_percent",
            "database_latency_seconds",
            "cache_hit_ratio",
        ):
            assert f"hunterx_{name.replace('.', '_')}" in text, name
