# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reporting engine.

Builds report documents from stored missions, findings and correlation
groups, then hands them to renderers. The engine is format-agnostic: concrete
renderers (JSON, Markdown, HTML, SARIF) implement
:class:`~hunterx.reporting.renderers.Renderer`.
"""

from __future__ import annotations

from hunterx.domain.entities import Report
from hunterx.domain.exceptions import ReportRenderError
from hunterx.domain.ports.repositories import FindingRepository, MissionRepository, ReportRepository
from hunterx.reporting.renderers import Renderer
from hunterx.reporting.views import build_report_view
from hunterx.shared.result import Failure, Result, Success


class ReportEngine:
    """Assemble and render report documents.

    ``render`` requires a renderer; the engine validates that the renderer
    supports the requested format before delegating.
    """

    def __init__(
        self,
        reports: ReportRepository,
        missions: MissionRepository,
        findings: FindingRepository,
        renderers: list[Renderer],
    ) -> None:
        self._reports = reports
        self._missions = missions
        self._findings = findings
        self._renderers = {renderer.format: renderer for renderer in renderers}

    def register_renderer(self, renderer: Renderer) -> None:
        """Register or replace a renderer by its format name."""
        self._renderers[renderer.format] = renderer

    def render(self, report: Report, *, fmt: str = "json") -> Result[str, Exception]:
        """Render ``report`` into ``fmt`` and return the document text."""
        renderer = self._renderers.get(fmt)
        if renderer is None:
            return Failure(ReportRenderError(f"No renderer registered for format '{fmt}'."))
        mission = self._missions.get(report.mission_id)
        findings = [
            finding
            for finding_id in report.finding_ids
            if (finding := self._findings.get(finding_id)) is not None
        ]
        view = build_report_view(report, mission=mission, findings=findings)
        try:
            return Success(renderer.render(view))
        except Exception as exc:
            return Failure(ReportRenderError(f"Rendering '{fmt}' failed: {exc}"))
