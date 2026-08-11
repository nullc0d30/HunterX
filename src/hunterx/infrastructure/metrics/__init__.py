# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Metrics adapters.

The :class:`InMemoryMetrics` collects counters, gauges and histograms with
optional tag dimensions. It powers the platform metric reference (execution
duration, tool runtime, queue size, mission duration, error/success/failure
rates, retry counts, memory/CPU usage, database latency, cache hit ratio) and
can render a Prometheus-compatible exposition format for scraping.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any

from hunterx.domain.ports.observability import MetricsPort


def _tags_key(name: str, tags: dict[str, str] | None) -> str:
    if not tags:
        return name
    labels = ",".join(f"{key}=\"{value}\"" for key, value in sorted(tags.items()))
    return f"{name}{{{labels}}}"


class InMemoryMetrics(MetricsPort):
    """Thread-safe in-memory metric collector.

    Metric kinds are tracked separately: counters accumulate, gauges hold the
    last set value and histograms keep raw samples (aggregated on snapshot).
    """

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.RLock()

    def increment(self, name: str, *, value: int = 1, tags: dict[str, str] | None = None) -> None:
        """Increment a counter metric."""
        with self._lock:
            self._counters[_tags_key(name, tags)] += value

    def gauge(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Record the current value of a gauge metric."""
        with self._lock:
            self._gauges[_tags_key(name, tags)] = value

    def histogram(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Observe a sample into a histogram metric."""
        with self._lock:
            self._histograms[_tags_key(name, tags)].append(float(value))

    def duration(self, name: str, seconds: float, *, tags: dict[str, str] | None = None) -> None:
        """Record a duration (seconds) into a histogram metric."""
        self.histogram(name, seconds, tags=tags)

    def snapshot(self) -> dict[str, Any]:
        """Return a serializable snapshot of all metrics."""
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {
                name: {
                    "count": len(samples),
                    "sum": round(sum(samples), 6),
                    "min": round(min(samples), 6) if samples else 0.0,
                    "max": round(max(samples), 6) if samples else 0.0,
                    "mean": round(sum(samples) / len(samples), 6) if samples else 0.0,
                }
                for name, samples in self._histograms.items()
            }
        return {"counters": counters, "gauges": gauges, "histograms": histograms}

    def render_prometheus(self) -> str:
        """Render the current metrics as Prometheus text exposition format."""
        lines: list[str] = ["# TYPE hunterx_metrics prometheus"]
        snapshot = self.snapshot()
        for key, value in snapshot["counters"].items():
            name, label = self._split_key(key)
            lines.append(f"hunterx_{_prometheus_name(name)}{label} {value}")
        for key, value in snapshot["gauges"].items():
            name, label = self._split_key(key)
            lines.append(f"hunterx_{_prometheus_name(name)}{label} {value}")
        for key, summary in snapshot["histograms"].items():
            name, label = self._split_key(key)
            name = _prometheus_name(name)
            lines.append(f"hunterx_{name}_count{label} {summary['count']}")
            lines.append(f"hunterx_{name}_sum{label} {summary['sum']}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _split_key(key: str) -> tuple[str, str]:
        if "{" in key:
            name, label = key.split("{", 1)
            return name, "{" + label
        return key, ""


def _prometheus_name(name: str) -> str:
    """Normalize a metric name for Prometheus (dots/underscores/dashes)."""
    return name.replace(".", "_").replace("-", "_")


#: Convenience shared instance for lightweight subsystems.
_shared: InMemoryMetrics | None = None


def shared_metrics() -> InMemoryMetrics:
    """Return a process-wide shared in-memory metrics collector."""
    global _shared
    if _shared is None:
        _shared = InMemoryMetrics()
    return _shared
