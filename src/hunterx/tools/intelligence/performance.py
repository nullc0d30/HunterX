# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool performance analyzer.

Maintains historical statistics for every tool: average duration, average
findings, success rate, false positive rate, failure rate and execution cost.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import ToolPerformanceStats
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry


class ToolPerformanceAnalyzer:
    """Record execution outcomes and maintain rolling performance statistics."""

    def __init__(self, registry: ToolIntelligenceRegistry) -> None:
        self._registry = registry

    def get(self, tool_id: str) -> ToolPerformanceStats | None:
        """Return performance stats for ``tool_id`` or ``None``."""
        return self._registry.get_performance(tool_id)

    def record_execution(
        self,
        tool_id: str,
        *,
        duration_ms: int = 0,
        findings: int = 0,
        succeeded: bool = True,
        cost: float = 0.0,
    ) -> ToolPerformanceStats:
        """Record a single execution outcome and update rolling stats."""
        stats = self._get_or_create(tool_id)
        stats.samples += 1
        stats.average_duration_ms = _running_average(
            stats.average_duration_ms, stats.samples, float(duration_ms)
        )
        stats.average_findings = _running_average(
            stats.average_findings, stats.samples, float(findings)
        )
        if succeeded:
            stats.success_rate = _running_average(stats.success_rate, stats.samples, 1.0)
            stats.failure_rate = _running_average(stats.failure_rate, stats.samples, 0.0)
        else:
            stats.success_rate = _running_average(stats.success_rate, stats.samples, 0.0)
            stats.failure_rate = _running_average(stats.failure_rate, stats.samples, 1.0)
        stats.execution_cost = _running_average(stats.execution_cost, stats.samples, cost)
        self._registry.set_performance(stats)
        return stats

    def record_false_positive(self, tool_id: str, *, count: int = 1) -> ToolPerformanceStats:
        """Record that ``count`` findings from a tool were refuted."""
        stats = self._get_or_create(tool_id)
        if stats.samples:
            stats.false_positive_rate = min(
                1.0,
                stats.false_positive_rate + (float(count) / float(stats.samples)) * 0.1,
            )
        self._registry.set_performance(stats)
        return stats

    def reset(self, tool_id: str) -> ToolPerformanceStats:
        """Reset performance stats for ``tool_id`` to a fresh record."""
        stats = ToolPerformanceStats(tool_id=tool_id)
        self._registry.set_performance(stats)
        return stats

    def _get_or_create(self, tool_id: str) -> ToolPerformanceStats:
        existing = self._registry.get_performance(tool_id)
        if existing is not None:
            return existing
        return ToolPerformanceStats(tool_id=tool_id)


def _running_average(current: float, sample_count: int, new_value: float) -> float:
    """Return the running average after incorporating ``new_value``."""
    if sample_count <= 1:
        return new_value
    return current + (new_value - current) / sample_count
