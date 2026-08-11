# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Repository ports.

Repositories encapsulate persistence of aggregates. Application and engine
layers call these interfaces; SQL/object-store/graph adapters implement them.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence

from hunterx.domain.entities import (
    Asset,
    Finding,
    Mission,
    Report,
    Scan,
    Target,
)


class Repository(abc.ABC):
    """Base class for all repositories."""

    @abc.abstractmethod
    def save(self, entity: object) -> None:
        """Persist (insert or update) an aggregate."""

    @abc.abstractmethod
    def delete(self, identifier: str) -> None:
        """Delete the aggregate identified by ``identifier``."""

    @abc.abstractmethod
    def get(self, identifier: str) -> object | None:
        """Return the aggregate by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[object]:
        """Return a page of aggregates ordered by creation time."""


class MissionRepository(Repository, abc.ABC):
    """Persistence contract for :class:`~hunterx.domain.entities.Mission`."""

    @abc.abstractmethod
    def save(self, entity: Mission) -> None:
        """Persist (insert or update) a mission."""

    @abc.abstractmethod
    def get(self, identifier: str) -> Mission | None:
        """Return a mission by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Mission]:
        """Return a page of missions ordered by creation time."""

    @abc.abstractmethod
    def list_by_status(self, status: str, *, limit: int = 100) -> Sequence[Mission]:
        """Return missions with the given status, most recent first."""


class FindingRepository(Repository, abc.ABC):
    """Persistence contract for :class:`~hunterx.domain.entities.Finding`."""

    @abc.abstractmethod
    def save(self, entity: Finding) -> None:
        """Persist (insert or update) a finding."""

    @abc.abstractmethod
    def get(self, identifier: str) -> Finding | None:
        """Return a finding by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Finding]:
        """Return a page of findings ordered by creation time."""

    @abc.abstractmethod
    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Finding]:
        """Return findings belonging to a mission, most severe first."""

    @abc.abstractmethod
    def exists_by_content_hash(self, content_hash: str) -> bool:
        """Return ``True`` when a finding with the content hash already exists."""


class TargetRepository(Repository, abc.ABC):
    """Persistence contract for :class:`~hunterx.domain.entities.Target`."""

    @abc.abstractmethod
    def save(self, entity: Target) -> None:
        """Persist (insert or update) a target."""

    @abc.abstractmethod
    def get(self, identifier: str) -> Target | None:
        """Return a target by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Target]:
        """Return a page of targets ordered by creation time."""


class ScanRepository(Repository, abc.ABC):
    """Persistence contract for :class:`~hunterx.domain.entities.Scan`."""

    @abc.abstractmethod
    def save(self, entity: Scan) -> None:
        """Persist (insert or update) a scan."""

    @abc.abstractmethod
    def get(self, identifier: str) -> Scan | None:
        """Return a scan by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Scan]:
        """Return a page of scans ordered by creation time."""

    @abc.abstractmethod
    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Scan]:
        """Return scans belonging to a mission, most recent first."""


class AssetRepository(Repository, abc.ABC):
    """Persistence contract for :class:`~hunterx.domain.entities.Asset`."""

    @abc.abstractmethod
    def save(self, entity: Asset) -> None:
        """Persist (insert or update) an asset."""

    @abc.abstractmethod
    def get(self, identifier: str) -> Asset | None:
        """Return an asset by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Asset]:
        """Return a page of assets ordered by creation time."""

    @abc.abstractmethod
    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Asset]:
        """Return assets discovered by a mission, most recent first."""


class ReportRepository(Repository, abc.ABC):
    """Persistence contract for :class:`~hunterx.domain.entities.Report`."""

    @abc.abstractmethod
    def save(self, entity: Report) -> None:
        """Persist (insert or update) a report."""

    @abc.abstractmethod
    def get(self, identifier: str) -> Report | None:
        """Return a report by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Report]:
        """Return a page of reports ordered by creation time."""
