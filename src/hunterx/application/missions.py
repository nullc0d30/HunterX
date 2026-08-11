# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission use-case service."""

from __future__ import annotations

from hunterx.application.dto import CreateMissionRequest
from hunterx.domain.entities import Mission, MissionKind, MissionPriority
from hunterx.domain.exceptions import MissionNotFoundError
from hunterx.domain.ports.repositories import MissionRepository
from hunterx.shared.result import Failure, Result, Success


class MissionService:
    """Application service for mission lifecycle use cases.

    Owns the transactional rules around creating, starting, pausing and
    finalizing missions. State transitions are delegated to the entity; the
    service persists every change through the repository port.
    """

    def __init__(self, repository: MissionRepository) -> None:
        self._repository = repository

    def create(self, request: CreateMissionRequest) -> Result[Mission, Exception]:
        """Create and persist a new mission from a request."""
        try:
            mission = Mission(
                name=request.name,
                kind=MissionKind(request.kind),
                workflow=request.workflow,
                targets=request.targets,
                priority=MissionPriority(request.priority),
                config=request.config,
            )
        except (KeyError, ValueError) as exc:
            return Failure(exc)
        self._repository.save(mission)
        return Success(mission)

    def get(self, mission_id: str) -> Result[Mission, Exception]:
        """Fetch a mission by identifier."""
        mission = self._repository.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        return Success(mission)

    def start(self, mission_id: str) -> Result[Mission, Exception]:
        """Transition a mission to RUNNING and persist it."""
        mission = self._repository.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        try:
            mission.start()
        except Exception as exc:
            return Failure(exc)
        self._repository.save(mission)
        return Success(mission)

    def complete(self, mission_id: str) -> Result[Mission, Exception]:
        """Transition a mission to COMPLETED and persist it."""
        mission = self._repository.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        mission.complete()
        self._repository.save(mission)
        return Success(mission)

    def fail(self, mission_id: str) -> Result[Mission, Exception]:
        """Transition a mission to FAILED and persist it."""
        mission = self._repository.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        mission.fail()
        self._repository.save(mission)
        return Success(mission)

    def cancel(self, mission_id: str) -> Result[Mission, Exception]:
        """Transition a mission to CANCELLED and persist it."""
        mission = self._repository.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        mission.cancel()
        self._repository.save(mission)
        return Success(mission)

    def set_progress(self, mission_id: str, progress: float) -> Result[Mission, Exception]:
        """Update a mission's progress and persist it."""
        mission = self._repository.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        try:
            mission.set_progress(progress)
        except Exception as exc:
            return Failure(exc)
        self._repository.save(mission)
        return Success(mission)

    def list(self, *, limit: int = 100, offset: int = 0) -> list[Mission]:
        """List persisted missions."""
        return list(self._repository.list(limit=limit, offset=offset))
