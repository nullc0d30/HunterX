# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture reports.

Aggregates linter output into a structured report: violation counts by code and
layer, module statistics, the layer dependency graph, known issues (waivers)
and an architecture health score. Renderers produce JSON, Markdown and text.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from hunterx.architecture.violations import Severity, Violation

#: Base score of a perfectly healthy architecture.
_HEALTH_BASE = 100
#: Points deducted per error-severity violation.
_ERROR_PENALTY = 8
#: Points deducted per warning (capped so warning noise cannot zero the score).
_WARNING_PENALTY = 1
#: Maximum total points deducted for warnings.
_MAX_WARNING_PENALTY = 15
#: Points deducted per unresolved circular dependency.
_CYCLE_PENALTY = 12


@dataclass(slots=True)
class ArchitectureReport:
    """Complete output of an architecture lint run.

    Attributes:
        violations: all violations detected.
        module_count: number of scanned modules.
        source_line_count: total lines of scanned source.
        layer_graph: layer name to imported layer names mapping.
        cycles: detected cycles (module lists).
        known_cycles: documented known wiring cycles.
        known_issues: waived issues surfaced for visibility.
        started_at: ISO timestamp of the run.

    """

    violations: list[Violation] = field(default_factory=list)
    module_count: int = 0
    source_line_count: int = 0
    layer_graph: dict[str, list[str]] = field(default_factory=dict)
    cycles: list[list[str]] = field(default_factory=list)
    known_cycles: list[list[str]] = field(default_factory=list)
    known_issues: list[Violation] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def error_count(self) -> int:
        """Return the number of error-severity violations."""
        return sum(1 for violation in self.violations if violation.severity == Severity.ERROR)

    def warning_count(self) -> int:
        """Return the number of warning-severity violations."""
        return sum(1 for violation in self.violations if violation.severity == Severity.WARNING)

    def info_count(self) -> int:
        """Return the number of info-severity violations."""
        return sum(1 for violation in self.violations if violation.severity == Severity.INFO)

    def health_score(self) -> float:
        """Compute the architecture health score (0-100)."""
        score = float(_HEALTH_BASE)
        score -= _ERROR_PENALTY * self.error_count()
        score -= min(_WARNING_PENALTY * self.warning_count(), _MAX_WARNING_PENALTY)
        score -= _CYCLE_PENALTY * len(self.cycles)
        return max(0.0, round(score, 1))

    def grade(self) -> str:
        """Return a letter grade for the health score."""
        score = self.health_score()
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    def is_clean(self) -> bool:
        """Return ``True`` when there are no error-severity violations."""
        return self.error_count() == 0

    def violations_by_code(self) -> dict[str, int]:
        """Return violation counts grouped by code."""
        return dict(Counter(violation.code for violation in self.violations))

    def violations_by_layer(self) -> dict[str, int]:
        """Return violation counts grouped by owning layer (first module part)."""
        counts: Counter[str] = Counter()
        for violation in self.violations:
            module = violation.module
            if not module:
                continue
            parts = module.split(".")
            layer = parts[1] if len(parts) > 1 else parts[0]
            counts[layer] += 1
        return dict(counts)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "summary": {
                "clean": self.is_clean(),
                "health_score": self.health_score(),
                "grade": self.grade(),
                "module_count": self.module_count,
                "source_lines": self.source_line_count,
                "errors": self.error_count(),
                "warnings": self.warning_count(),
                "infos": self.info_count(),
                "cycles": len(self.cycles),
                "known_cycles": len(self.known_cycles),
            },
            "violations_by_code": self.violations_by_code(),
            "violations_by_layer": self.violations_by_layer(),
            "violations": [violation.to_dict() for violation in self.violations],
            "known_issues": [violation.to_dict() for violation in self.known_issues],
            "cycles": [sorted(cycle) for cycle in self.cycles],
            "layer_graph": self.layer_graph,
            "started_at": self.started_at,
        }

    def to_json(self) -> str:
        """Render the report as indented JSON."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_text(self) -> str:
        """Render a human-readable text summary."""
        lines: list[str] = [
            "HunterX Architecture Enforcement Report",
            "=" * 40,
            f"Health score: {self.health_score():.1f}/100 ({self.grade()})",
            f"Modules scanned: {self.module_count}",
            f"Source lines: {self.source_line_count}",
            f"Errors: {self.error_count()}",
            f"Warnings: {self.warning_count()}",
            f"Infos: {self.info_count()}",
            f"Cycles: {len(self.cycles)} (known: {len(self.known_cycles)})",
            "",
            "Violations by code:",
        ]
        for code, count in sorted(self.violations_by_code().items()):
            lines.append(f"  {code}: {count}")
        lines.append("")
        if self.violations:
            lines.append("Violations:")
            for violation in self.violations:
                location = f"{violation.module}:{violation.line}" if violation.module else "-"
                lines.append(f"  [{violation.severity}] {violation.code} {location}: {violation.message}")
        else:
            lines.append("No violations.")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Render the report as Markdown."""
        lines: list[str] = [
            "# HunterX Architecture Enforcement Report",
            "",
            f"- **Health score:** {self.health_score():.1f}/100 ({self.grade()})",
            f"- **Modules scanned:** {self.module_count}",
            f"- **Source lines:** {self.source_line_count}",
            f"- **Errors:** {self.error_count()}",
            f"- **Warnings:** {self.warning_count()}",
            f"- **Cycles:** {len(self.cycles)} (known: {len(self.known_cycles)})",
            "",
            "## Violations by code",
            "",
            "| Code | Count |",
            "| --- | --- |",
        ]
        for code, count in sorted(self.violations_by_code().items()):
            lines.append(f"| {code} | {count} |")
        lines.extend(["", "## Violations", ""])
        if self.violations:
            lines.append("| Severity | Code | Module:Line | Message |")
            lines.append("| --- | --- | --- | --- |")
            for violation in self.violations:
                location = f"{violation.module}:{violation.line}" if violation.module else "-"
                lines.append(f"| {violation.severity} | {violation.code} | {location} | {violation.message} |")
        else:
            lines.append("No violations.")
        lines.extend(["", "## Layer dependency graph", "", "```", self.render_mermaid(), "```"])
        return "\n".join(lines)

    def render_mermaid(self) -> str:
        """Render the layer dependency graph as a Mermaid flowchart."""
        lines = ["flowchart LR"]
        for layer in sorted(self.layer_graph):
            lines.append(f"    {layer}")
        for source, targets in sorted(self.layer_graph.items()):
            for target in targets:
                lines.append(f"    {source} --> {target}")
        return "\n".join(lines)


def summarize_changes(changes: list[Any]) -> dict[str, int]:
    """Summarize API stability changes by kind.

    Args:
        changes: list of API change objects.

    Returns:
        Counts by change kind.

    """
    return dict(Counter(getattr(change, "kind", "unknown") for change in changes))
