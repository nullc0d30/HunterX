# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report use-case service."""

from __future__ import annotations

from hunterx.application.dto import CreateReportRequest
from hunterx.domain.entities import Report, ReportKind
from hunterx.domain.exceptions import MissionNotFoundError
from hunterx.domain.ports.repositories import MissionRepository, ReportRepository
from hunterx.shared.result import Failure, Result, Success


class ReportService:
    """Application service for report creation and lifecycle."""

    def __init__(self, repository: ReportRepository, mission_repository: MissionRepository) -> None:
        self._repository = repository
        self._missions = mission_repository

    def create(self, request: CreateReportRequest) -> Result[Report, Exception]:
        """Create a report draft bound to an existing mission."""
        if self._missions.get(request.mission_id) is None:
            return Failure(MissionNotFoundError(request.mission_id))
        report = Report(
            mission_id=request.mission_id,
            kind=ReportKind(request.kind),
            title=request.title or f"Report for mission {request.mission_id}",
            summary=request.summary,
        )
        self._repository.save(report)
        return Success(report)

    def get(self, report_id: str) -> Report | None:
        """Fetch a report by identifier."""
        return self._repository.get(report_id)

    def attach_findings(self, report_id: str, finding_ids: list[str]) -> Result[Report, Exception]:
        """Replace the set of findings covered by a report."""
        report = self._repository.get(report_id)
        if report is None:
            return Failure(MissionNotFoundError(report_id))
        report.finding_ids = finding_ids
        self._repository.save(report)
        return Success(report)
