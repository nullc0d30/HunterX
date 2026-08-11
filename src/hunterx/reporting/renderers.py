# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report renderers.

Renderers convert a :class:`~hunterx.reporting.views.ReportView` into a
concrete output format. The engine layer passes view models to renderers, so
renderers stay small and format-focused.
"""

from __future__ import annotations

import abc
import json

from hunterx.reporting.views import ReportView


class Renderer(abc.ABC):
    """Contract every report renderer implements."""

    #: Format identifier (e.g. ``"json"``, ``"markdown"``, ``"sarif"``).
    format: str = ""

    @abc.abstractmethod
    def render(self, view: ReportView) -> str:
        """Render a report view into the target format."""


class JsonRenderer(Renderer):
    """Render a report as pretty-printed JSON."""

    format = "json"

    def render(self, view: ReportView) -> str:
        """Render a report view as pretty-printed JSON."""
        payload = {
            "report_id": view.report_id,
            "title": view.title,
            "summary": view.summary,
            "generated_at": view.generated_at,
            "mission": {
                "mission_id": view.mission.mission_id,
                "name": view.mission.name,
                "kind": view.mission.kind,
                "status": view.mission.status,
                "progress": view.mission.progress,
                "targets": list(view.mission.targets),
            },
            "findings": [self._finding(finding) for finding in view.findings],
            "correlation_groups": list(view.correlation_groups),
            "metadata": view.metadata,
        }
        return json.dumps(payload, indent=2, default=str)

    @staticmethod
    def _finding(finding: object) -> dict[str, object]:
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity,
            "target": finding.target,
            "tool": finding.tool,
            "description": finding.description,
            "risk_score": finding.risk_score,
            "references": list(finding.references),
        }


class MarkdownRenderer(Renderer):
    """Render a report as Markdown."""

    format = "markdown"

    def render(self, view: ReportView) -> str:
        """Render a report view as Markdown."""
        lines = [
            f"# {view.title}",
            "",
            f"**Mission:** {view.mission.name} ({view.mission.kind})",
            f"**Status:** {view.mission.status}",
            "",
        ]
        if view.summary:
            lines += [view.summary, ""]
        lines.append("## Findings")
        if not view.findings:
            lines.append("\n_No findings._")
        for finding in view.findings:
            lines += [
                "",
                f"### {finding.severity} - {finding.title}",
                f"**Target:** {finding.target} | **Tool:** {finding.tool}",
                "",
                finding.description,
            ]
        if view.correlation_groups:
            lines += ["", "## Correlation"]
            for group in view.correlation_groups:
                lines.append(f"- {group.get('narrative', '')}")
        return "\n".join(lines) + "\n"
