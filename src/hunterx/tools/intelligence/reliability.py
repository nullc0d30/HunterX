# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reliability and availability tracking (Sprint 023).

Tracks per-tool reliability stats and produces availability reports. Tools are
never automatically disabled based solely on these metrics — the reports only
inform selection and surface the reason a capability is (or is not) usable.
"""

from __future__ import annotations

from dataclasses import replace

from hunterx.domain.tool_intelligence import (
    ToolAvailabilityReport,
    ToolAvailabilityStatus,
    ToolReliabilityStats,
)
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry


class ToolReliabilityTracker:
    """Update reliability stats and produce availability reports.

    Usage::

        tracker = ToolReliabilityTracker(registry)
        tracker.record_success("nmap", duration_ms=1200)
        tracker.report_availability("nmap", "missing", "binary not installed")
    """

    def __init__(self, registry: ToolIntelligenceRegistry) -> None:
        self._registry = registry

    def record_success(self, tool_id: str, *, duration_ms: int = 0) -> ToolReliabilityStats:
        """Record a successful execution."""
        stats = self._get(tool_id)
        stats = replace(
            stats,
            successful_executions=stats.successful_executions + 1,
            samples=stats.samples + 1,
            average_execution_time_ms=_rolling_average(stats, duration_ms),
        )
        self._registry.set_reliability(stats)
        return stats

    def record_failure(
        self,
        tool_id: str,
        *,
        parse_failure: bool = False,
        duration_ms: int = 0,
    ) -> ToolReliabilityStats:
        """Record a failed execution (optionally a parse failure)."""
        stats = self._get(tool_id)
        stats = replace(
            stats,
            failed_executions=stats.failed_executions + 1,
            parse_failures=stats.parse_failures + (1 if parse_failure else 0),
            samples=stats.samples + 1,
            average_execution_time_ms=_rolling_average(stats, duration_ms),
        )
        self._registry.set_reliability(stats)
        return stats

    def record_false_positive(self, tool_id: str) -> ToolReliabilityStats:
        """Record a reported false positive (lowers evidence quality)."""
        stats = self._get(tool_id)
        stats = replace(
            stats,
            false_positive_feedback=stats.false_positive_feedback + 1,
            evidence_quality=max(0.0, stats.evidence_quality - 0.1),
        )
        self._registry.set_reliability(stats)
        return stats

    def record_false_negative(self, tool_id: str) -> ToolReliabilityStats:
        """Record a reported false negative."""
        stats = self._get(tool_id)
        stats = replace(
            stats,
            false_negative_feedback=stats.false_negative_feedback + 1,
        )
        self._registry.set_reliability(stats)
        return stats

    def record_proof_outcome(self, tool_id: str, *, succeeded: bool) -> ToolReliabilityStats:
        """Record a proof execution outcome."""
        stats = self._get(tool_id)
        total_proofs = stats.proof_success_rate
        new_rate = _binary_ratio(total_proofs, succeeded)
        stats = replace(stats, proof_success_rate=new_rate)
        self._registry.set_reliability(stats)
        return stats

    def record_replay_outcome(self, tool_id: str, *, succeeded: bool) -> ToolReliabilityStats:
        """Record a proof replay outcome."""
        stats = self._get(tool_id)
        stats = replace(stats, replay_success_rate=_binary_ratio(stats.replay_success_rate, succeeded))
        self._registry.set_reliability(stats)
        return stats

    def get(self, tool_id: str) -> ToolReliabilityStats | None:
        """Return reliability stats for ``tool_id`` or ``None``."""
        return self._registry.get_reliability(tool_id)

    def report_availability(
        self,
        tool_id: str,
        status: ToolAvailabilityStatus,
        *,
        reason: str = "",
        checked_at: str = "",
    ) -> ToolAvailabilityReport:
        """Produce and store an availability report for a tool capability."""
        from hunterx.tools.intelligence.target import utc_now

        report = ToolAvailabilityReport(
            tool_id=tool_id,
            status=status,
            reason=reason,
            checked_at=checked_at or utc_now(),
        )
        self._registry.set_availability_report(report)
        return report

    def available(self, tool_id: str) -> bool:
        """Return ``True`` only when the latest report says the capability is installed."""
        report = self._registry.get_availability_report(tool_id)
        return report is None or report.available

    def _get(self, tool_id: str) -> ToolReliabilityStats:
        stats = self._registry.get_reliability(tool_id)
        return stats or ToolReliabilityStats(tool_id=tool_id)


def _rolling_average(stats: ToolReliabilityStats, duration_ms: int) -> float:
    if stats.samples == 0:
        return float(duration_ms)
    return (stats.average_execution_time_ms * stats.samples + duration_ms) / (stats.samples + 1)


def _binary_ratio(current: float, succeeded: bool) -> float:
    """Blend a binary outcome into a smooth ratio (exponential moving average)."""
    return round((current * 0.9) + (1.0 if succeeded else 0.0) * 0.1, 4)


__all__ = ["ToolReliabilityTracker"]
