# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding use-case service."""

from __future__ import annotations

from hunterx.application.dto import CreateFindingRequest
from hunterx.domain.entities import Finding
from hunterx.domain.exceptions import DuplicateRegistrationError
from hunterx.domain.ports.repositories import FindingRepository
from hunterx.domain.value_objects import Severity
from hunterx.shared.result import Failure, Result, Success


class FindingService:
    """Application service for findings.

    Persists normalized findings and enforces the deduplication contract: a
    finding whose content hash already exists is rejected as a duplicate.
    """

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    def create(self, request: CreateFindingRequest) -> Result[Finding, Exception]:
        """Persist a new finding; reject duplicates by content hash."""
        try:
            finding = Finding(
                title=request.title,
                severity=Severity.from_str(request.severity),
                target=request.target,
                tool=request.tool,
                mission_id=request.mission_id,
                description=request.description,
                risk_score=request.risk_score,
                metadata=request.metadata,
            )
            finding.compute_content_hash()
        except Exception as exc:
            return Failure(exc)
        if self._repository.exists_by_content_hash(finding.content_hash):
            return Failure(
                DuplicateRegistrationError(f"Duplicate finding: {finding.content_hash}")
            )
        self._repository.save(finding)
        return Success(finding)

    def get(self, finding_id: str) -> Finding | None:
        """Fetch a finding by identifier."""
        return self._repository.get(finding_id)

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> list[Finding]:
        """List findings for a mission."""
        return list(self._repository.list_by_mission(mission_id, limit=limit))
