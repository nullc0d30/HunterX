# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory repository implementations.

Test doubles implementing the domain repository ports without any database.
Used by unit tests and by the default wiring in development.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.entities import Asset, Finding, Mission, Report, Scan, Target
from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.ports.repositories import (
    AssetRepository,
    FindingRepository,
    MissionRepository,
    ReportRepository,
    ScanRepository,
    TargetRepository,
)


class InMemoryMissionRepository(MissionRepository):
    """In-memory :class:`MissionRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Mission] = {}

    def save(self, entity: Mission) -> None:
        self._store[entity.mission_id] = entity

    def get(self, identifier: str) -> Mission | None:
        return self._store.get(identifier)

    def delete(self, identifier: str) -> None:
        if identifier not in self._store:
            raise NotFoundError("Mission", identifier)
        del self._store[identifier]

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Mission]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def list_by_status(self, status: str, *, limit: int = 100) -> Sequence[Mission]:
        return [m for m in self._store.values() if m.status.value == status][:limit]


class InMemoryFindingRepository(FindingRepository):
    """In-memory :class:`FindingRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Finding] = {}
        self._hashes: set[str] = set()

    def save(self, entity: Finding) -> None:
        if not entity.content_hash:
            entity.compute_content_hash()
        self._store[entity.finding_id] = entity
        self._hashes.add(entity.content_hash)

    def get(self, identifier: str) -> Finding | None:
        return self._store.get(identifier)

    def delete(self, identifier: str) -> None:
        finding = self._store.pop(identifier, None)
        if finding is not None and finding.content_hash in self._hashes:
            self._hashes.discard(finding.content_hash)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Finding]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Finding]:
        return [f for f in self._store.values() if f.mission_id == mission_id][:limit]

    def exists_by_content_hash(self, content_hash: str) -> bool:
        return content_hash in self._hashes


class InMemoryTargetRepository(TargetRepository):
    """In-memory :class:`TargetRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Target] = {}

    def save(self, entity: Target) -> None:
        self._store[entity.target_id] = entity

    def get(self, identifier: str) -> Target | None:
        return self._store.get(identifier)

    def delete(self, identifier: str) -> None:
        if identifier not in self._store:
            raise NotFoundError("Target", identifier)
        del self._store[identifier]

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Target]:
        values = list(self._store.values())
        return values[offset : offset + limit]


class InMemoryScanRepository(ScanRepository):
    """In-memory :class:`ScanRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Scan] = {}

    def save(self, entity: Scan) -> None:
        self._store[entity.scan_id] = entity

    def get(self, identifier: str) -> Scan | None:
        return self._store.get(identifier)

    def delete(self, identifier: str) -> None:
        if identifier not in self._store:
            raise NotFoundError("Scan", identifier)
        del self._store[identifier]

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Scan]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Scan]:
        return [s for s in self._store.values() if s.mission_id == mission_id][:limit]


class InMemoryAssetRepository(AssetRepository):
    """In-memory :class:`AssetRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Asset] = {}

    def save(self, entity: Asset) -> None:
        self._store[entity.asset_id] = entity

    def get(self, identifier: str) -> Asset | None:
        return self._store.get(identifier)

    def delete(self, identifier: str) -> None:
        if identifier not in self._store:
            raise NotFoundError("Asset", identifier)
        del self._store[identifier]

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Asset]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Asset]:
        return [a for a in self._store.values() if a.mission_id == mission_id][:limit]


class InMemoryReportRepository(ReportRepository):
    """In-memory :class:`ReportRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Report] = {}

    def save(self, entity: Report) -> None:
        self._store[entity.report_id] = entity

    def get(self, identifier: str) -> Report | None:
        return self._store.get(identifier)

    def delete(self, identifier: str) -> None:
        if identifier not in self._store:
            raise NotFoundError("Report", identifier)
        del self._store[identifier]

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Report]:
        values = list(self._store.values())
        return values[offset : offset + limit]


def build_in_memory_repositories() -> dict[str, object]:
    """Build all in-memory repositories keyed by their role name."""
    return {
        "missions": InMemoryMissionRepository(),
        "findings": InMemoryFindingRepository(),
        "targets": InMemoryTargetRepository(),
        "scans": InMemoryScanRepository(),
        "assets": InMemoryAssetRepository(),
        "reports": InMemoryReportRepository(),
    }
