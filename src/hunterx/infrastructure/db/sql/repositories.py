# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SQLAlchemy repository implementations of the domain repository ports."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from hunterx.domain.entities import (
    Asset,
    Finding,
    Mission,
    MissionPriority,
    MissionStatus,
    Report,
    ReportKind,
    ReportStatus,
    Scan,
    ScanStatus,
    Target,
    TargetKind,
)
from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.ports.repositories import (
    AssetRepository,
    FindingRepository,
    MissionRepository,
    ReportRepository,
    ScanRepository,
    TargetRepository,
)
from hunterx.domain.value_objects import Severity
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.infrastructure.db.sql.models import (
    AssetModel,
    FindingModel,
    MissionModel,
    ReportModel,
    ScanModel,
    TargetModel,
)


def _json_dumps(value: object) -> str:
    """Serialize a value to JSON, coercing non-JSON types to strings."""
    return json.dumps(value, default=str)


class _SqlRepositoryMixin:
    """Shared CRUD plumbing over a :class:`SessionFactory`."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def _session(self) -> Any:
        return self._session_factory.session()

    def _delete(self, model_cls: type, identifier: str) -> None:
        with self._session() as session:
            row = session.get(model_cls, identifier)
            if row is None:
                raise NotFoundError(model_cls.__name__, identifier)
            session.delete(row)
            session.commit()

    def _get(self, model_cls: type, identifier: str) -> Any | None:
        with self._session() as session:
            return session.get(model_cls, identifier)

    def _list(self, model_cls: type, *, limit: int, offset: int) -> Sequence[Any]:
        with self._session() as session:
            return list(session.query(model_cls).offset(offset).limit(limit).all())


class SqlMissionRepository(_SqlRepositoryMixin, MissionRepository):
    """SQL-backed :class:`MissionRepository`."""

    def save(self, entity: Mission) -> None:
        """Persist (insert or update) a mission."""
        with self._session() as session:
            row = session.get(MissionModel, entity.mission_id)
            if row is None:
                row = MissionModel(id=entity.mission_id)
                session.add(row)
            row.name = entity.name
            row.kind = entity.kind.value
            row.workflow = entity.workflow
            row.priority = entity.priority.value
            row.status = entity.status.value
            row.progress = entity.progress
            row.targets = _json_dumps(entity.targets)
            row.config = _json_dumps(entity.config)
            row.created_at = entity.created_at
            row.started_at = entity.started_at
            row.finished_at = entity.finished_at
            session.commit()

    def get(self, identifier: str) -> Mission | None:
        """Return a mission by identifier, or ``None`` if absent."""
        row = self._get(MissionModel, identifier)
        if row is None:
            return None
        data = row.to_dict()
        return Mission(
            mission_id=data["id"],
            name=data["name"],
            kind=_mission_kind_from_string(data["kind"]),
            workflow=data["workflow"],
            priority=MissionPriority(data["priority"]),
            status=MissionStatus(data["status"]),
            progress=data["progress"],
            targets=data["targets"],
            config=data["config"],
            created_at=data["created_at"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
        )

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Mission]:
        """Return a page of missions ordered by creation time."""
        return [self.get(row.id) for row in self._list(MissionModel, limit=limit, offset=offset) if row.id]

    def list_by_status(self, status: str, *, limit: int = 100) -> Sequence[Mission]:
        """Return missions with the given status, most recent first."""
        with self._session() as session:
            rows = list(session.query(MissionModel).filter_by(status=status).limit(limit).all())
        return [self.get(row.id) for row in rows if row.id]

    def delete(self, identifier: str) -> None:
        """Delete a mission, raising when absent."""
        self._delete(MissionModel, identifier)


def _mission_kind_from_string(value: str) -> Any:
    """Convert a stored mission kind string into its enum member."""
    from hunterx.domain.entities import MissionKind

    return MissionKind(value)


class SqlFindingRepository(_SqlRepositoryMixin, FindingRepository):
    """SQL-backed :class:`FindingRepository`."""

    def save(self, entity: Finding) -> None:
        """Persist (insert or update) a finding."""
        with self._session() as session:
            row = session.get(FindingModel, entity.finding_id)
            if row is None:
                row = FindingModel(id=entity.finding_id)
                session.add(row)
            row.content_hash = entity.content_hash or entity.compute_content_hash()
            row.title = entity.title
            row.severity = entity.severity.name
            row.target = entity.target
            row.tool = entity.tool
            row.mission_id = entity.mission_id
            row.description = entity.description
            row.evidence_ids = _json_dumps(entity.evidence_ids)
            row.references = _json_dumps(entity.references)
            row.risk_score = entity.risk_score
            row.metadata_json = _json_dumps(entity.metadata)
            row.created_at = entity.created_at
            session.commit()

    def get(self, identifier: str) -> Finding | None:
        """Return a finding by identifier, or ``None`` if absent."""
        row = self._get(FindingModel, identifier)
        if row is None:
            return None
        data = row.to_dict()
        return Finding(
            finding_id=data["id"],
            content_hash=data["content_hash"],
            title=data["title"],
            severity=Severity[data["severity"]],
            target=data["target"],
            tool=data["tool"],
            mission_id=data["mission_id"],
            description=data["description"],
            evidence_ids=data["evidence_ids"],
            references=data["references"],
            risk_score=data["risk_score"],
            metadata=data["metadata"],
            created_at=data["created_at"],
        )

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Finding]:
        """Return a page of findings ordered by creation time."""
        rows = self._list(FindingModel, limit=limit, offset=offset)
        return [finding for row in rows if (finding := self.get(row.id)) is not None]  # type: ignore[misc]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Finding]:
        """Return findings belonging to a mission, most severe first."""
        with self._session() as session:
            rows = list(session.query(FindingModel).filter_by(mission_id=mission_id).limit(limit).all())
        return [finding for row in rows if (finding := self.get(row.id)) is not None]  # type: ignore[misc]

    def exists_by_content_hash(self, content_hash: str) -> bool:
        """Return ``True`` when a finding with the content hash already exists."""
        with self._session() as session:
            return session.query(FindingModel).filter_by(content_hash=content_hash).first() is not None

    def delete(self, identifier: str) -> None:
        """Delete a finding, raising when absent."""
        self._delete(FindingModel, identifier)


class SqlTargetRepository(_SqlRepositoryMixin, TargetRepository):
    """SQL-backed :class:`TargetRepository`."""

    def save(self, entity: Target) -> None:
        """Persist (insert or update) a target."""
        with self._session() as session:
            row = session.get(TargetModel, entity.target_id)
            if row is None:
                row = TargetModel(id=entity.target_id)
                session.add(row)
            row.kind = entity.kind.value
            row.value = entity.value
            row.label = entity.label
            row.metadata_json = _json_dumps(entity.metadata)
            row.created_at = entity.created_at
            session.commit()

    def get(self, identifier: str) -> Target | None:
        """Return a target by identifier, or ``None`` if absent."""
        row = self._get(TargetModel, identifier)
        if row is None:
            return None
        data = row.to_dict()
        return Target(
            target_id=data["id"],
            kind=TargetKind(data["kind"]),
            value=data["value"],
            label=data["label"],
            metadata=data["metadata"],
            created_at=data["created_at"],
        )

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Target]:
        """Return a page of targets ordered by creation time."""
        rows = self._list(TargetModel, limit=limit, offset=offset)
        return [target for row in rows if (target := self.get(row.id)) is not None]  # type: ignore[misc]

    def delete(self, identifier: str) -> None:
        """Delete a target, raising when absent."""
        self._delete(TargetModel, identifier)


class SqlScanRepository(_SqlRepositoryMixin, ScanRepository):
    """SQL-backed :class:`ScanRepository`."""

    def save(self, entity: Scan) -> None:
        """Persist (insert or update) a scan."""
        with self._session() as session:
            row = session.get(ScanModel, entity.scan_id)
            if row is None:
                row = ScanModel(id=entity.scan_id)
                session.add(row)
            row.mission_id = entity.mission_id
            row.tool = entity.tool
            row.target = entity.target
            row.status = entity.status.value
            row.parameters = _json_dumps(entity.parameters)
            row.created_at = entity.created_at
            session.commit()

    def get(self, identifier: str) -> Scan | None:
        """Return a scan by identifier, or ``None`` if absent."""
        row = self._get(ScanModel, identifier)
        if row is None:
            return None
        data = row.to_dict()
        return Scan(
            scan_id=data["id"],
            mission_id=data["mission_id"],
            tool=data["tool"],
            target=data["target"],
            status=ScanStatus(data["status"]),
            parameters=data["parameters"],
            created_at=data["created_at"],
        )

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Scan]:
        """Return a page of scans ordered by creation time."""
        rows = self._list(ScanModel, limit=limit, offset=offset)
        return [scan for row in rows if (scan := self.get(row.id)) is not None]  # type: ignore[misc]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Scan]:
        """Return scans belonging to a mission, most recent first."""
        with self._session() as session:
            rows = list(session.query(ScanModel).filter_by(mission_id=mission_id).limit(limit).all())
        return [scan for row in rows if (scan := self.get(row.id)) is not None]  # type: ignore[misc]

    def delete(self, identifier: str) -> None:
        """Delete a scan, raising when absent."""
        self._delete(ScanModel, identifier)


class SqlAssetRepository(_SqlRepositoryMixin, AssetRepository):
    """SQL-backed :class:`AssetRepository`."""

    def save(self, entity: Asset) -> None:
        """Persist (insert or update) an asset."""
        with self._session() as session:
            row = session.get(AssetModel, entity.asset_id)
            if row is None:
                row = AssetModel(id=entity.asset_id)
                session.add(row)
            row.name = entity.name
            row.asset_type = entity.asset_type
            row.mission_id = entity.mission_id
            row.properties = _json_dumps(entity.properties)
            row.created_at = entity.created_at
            session.commit()

    def get(self, identifier: str) -> Asset | None:
        """Return an asset by identifier, or ``None`` if absent."""
        row = self._get(AssetModel, identifier)
        if row is None:
            return None
        data = row.to_dict()
        return Asset(
            asset_id=data["id"],
            name=data["name"],
            asset_type=data["asset_type"],
            mission_id=data["mission_id"],
            properties=data["properties"],
            created_at=data["created_at"],
        )

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Asset]:
        """Return a page of assets ordered by creation time."""
        rows = self._list(AssetModel, limit=limit, offset=offset)
        return [asset for row in rows if (asset := self.get(row.id)) is not None]  # type: ignore[misc]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[Asset]:
        """Return assets discovered by a mission, most recent first."""
        with self._session() as session:
            rows = list(session.query(AssetModel).filter_by(mission_id=mission_id).limit(limit).all())
        return [asset for row in rows if (asset := self.get(row.id)) is not None]  # type: ignore[misc]

    def delete(self, identifier: str) -> None:
        """Delete an asset, raising when absent."""
        self._delete(AssetModel, identifier)


class SqlReportRepository(_SqlRepositoryMixin, ReportRepository):
    """SQL-backed :class:`ReportRepository`."""

    def save(self, entity: Report) -> None:
        """Persist (insert or update) a report."""
        with self._session() as session:
            row = session.get(ReportModel, entity.report_id)
            if row is None:
                row = ReportModel(id=entity.report_id)
                session.add(row)
            row.mission_id = entity.mission_id
            row.kind = entity.kind.value
            row.title = entity.title
            row.summary = entity.summary
            row.status = entity.status.value
            row.finding_ids = _json_dumps(entity.finding_ids)
            row.created_at = entity.created_at
            session.commit()

    def get(self, identifier: str) -> Report | None:
        """Return a report by identifier, or ``None`` if absent."""
        row = self._get(ReportModel, identifier)
        if row is None:
            return None
        data = row.to_dict()
        return Report(
            report_id=data["id"],
            mission_id=data["mission_id"],
            kind=ReportKind(data["kind"]),
            title=data["title"],
            summary=data["summary"],
            status=ReportStatus(data["status"]),
            finding_ids=data["finding_ids"],
            created_at=data["created_at"],
        )

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Report]:
        """Return a page of reports ordered by creation time."""
        rows = self._list(ReportModel, limit=limit, offset=offset)
        return [report for row in rows if (report := self.get(row.id)) is not None]  # type: ignore[misc]

    def delete(self, identifier: str) -> None:
        """Delete a report, raising when absent."""
        self._delete(ReportModel, identifier)
