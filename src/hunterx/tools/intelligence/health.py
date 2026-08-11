# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool health monitor.

Tracks availability, execution failures, crash frequency, average runtime,
memory/CPU usage, timeouts and derives a reliability score for every tool.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import ToolHealthStats
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry


class ToolHealthMonitor:
    """Record health observations and maintain per-tool health stats.

    The reliability score decays with failures, crashes and timeouts and
    increases with successful runs.
    """

    def __init__(self, registry: ToolIntelligenceRegistry) -> None:
        self._registry = registry

    def get(self, tool_id: str) -> ToolHealthStats | None:
        """Return the current health stats for ``tool_id`` or ``None``."""
        return self._registry.get_health(tool_id)

    def record_success(self, tool_id: str, duration_ms: int = 0) -> ToolHealthStats:
        """Record a successful execution."""
        stats = self._get_or_create(tool_id)
        stats.samples += 1
        stats.availability = True
        stats.crash_frequency = max(0.0, stats.crash_frequency - 0.05)
        stats.average_runtime_ms = _running_average(
            stats.average_runtime_ms, stats.samples, float(duration_ms)
        )
        stats.reliability_score = min(1.0, stats.reliability_score + 0.05)
        self._registry.set_health(stats)
        return stats

    def record_failure(self, tool_id: str, *, crash: bool = False, timeout: bool = False) -> ToolHealthStats:
        """Record a failed execution (optionally a crash or timeout)."""
        stats = self._get_or_create(tool_id)
        stats.samples += 1
        stats.execution_failures += 1
        if crash:
            stats.crash_frequency += 0.1
        if timeout:
            stats.timeouts += 1
        stats.reliability_score = max(0.0, stats.reliability_score - 0.15)
        self._registry.set_health(stats)
        return stats

    def record_usage(
        self,
        tool_id: str,
        *,
        memory_mb: float = 0.0,
        cpu_pct: float = 0.0,
    ) -> ToolHealthStats:
        """Record resource usage samples for a tool."""
        stats = self._get_or_create(tool_id)
        stats.samples += 1
        if memory_mb:
            stats.memory_usage_mb = _running_average(
                stats.memory_usage_mb, stats.samples, memory_mb
            )
        if cpu_pct:
            stats.cpu_usage_pct = _running_average(
                stats.cpu_usage_pct, stats.samples, cpu_pct
            )
        self._registry.set_health(stats)
        return stats

    def set_availability(self, tool_id: str, available: bool) -> ToolHealthStats:
        """Explicitly set availability for a tool."""
        stats = self._get_or_create(tool_id)
        stats.availability = available
        self._registry.set_health(stats)
        return stats

    def _get_or_create(self, tool_id: str) -> ToolHealthStats:
        existing = self._registry.get_health(tool_id)
        if existing is not None:
            return existing
        return ToolHealthStats(tool_id=tool_id)


def _running_average(current: float, sample_count: int, new_value: float) -> float:
    """Return the running average after incorporating ``new_value``."""
    if sample_count <= 1:
        return new_value
    return current + (new_value - current) / sample_count
