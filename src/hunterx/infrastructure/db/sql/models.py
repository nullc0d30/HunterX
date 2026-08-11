# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SQLAlchemy ORM models.

Models mirror the domain entities 1:1 but are storage views, not domain
objects. Complex values (metadata, lists, dicts) are stored as JSON text to
keep the foundation schema portable across SQLite/Postgres.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.factory import get_base

Base = get_base()


class MissionModel(Base):
    """ORM view of :class:`~hunterx.domain.entities.Mission`."""

    __tablename__ = "hunterx_missions"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    workflow: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    targets: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    config: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    finished_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a JSON-safe mapping."""
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "workflow": self.workflow,
            "priority": self.priority,
            "status": self.status,
            "progress": self.progress,
            "targets": json.loads(self.targets),
            "config": json.loads(self.config),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class FindingModel(Base):
    """ORM view of :class:`~hunterx.domain.entities.Finding`."""

    __tablename__ = "hunterx_findings"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True, unique=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    tool: Mapped[str] = mapped_column(String(255), nullable=False)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    references: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    metadata_json: Mapped[str] = mapped_column("metadata", Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a JSON-safe mapping."""
        return {
            "id": self.id,
            "content_hash": self.content_hash,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "tool": self.tool,
            "mission_id": self.mission_id,
            "description": self.description,
            "evidence_ids": json.loads(self.evidence_ids),
            "references": json.loads(self.references),
            "risk_score": self.risk_score,
            "metadata": json.loads(self.metadata_json),
            "created_at": self.created_at,
        }


class TargetModel(Base):
    """ORM view of :class:`~hunterx.domain.entities.Target`."""

    __tablename__ = "hunterx_targets"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[str] = mapped_column("metadata", Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a JSON-safe mapping."""
        return {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "label": self.label,
            "metadata": json.loads(self.metadata_json),
            "created_at": self.created_at,
        }


class ScanModel(Base):
    """ORM view of :class:`~hunterx.domain.entities.Scan`."""

    __tablename__ = "hunterx_scans"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    tool: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    parameters: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a JSON-safe mapping."""
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "tool": self.tool,
            "target": self.target,
            "status": self.status,
            "parameters": json.loads(self.parameters),
            "created_at": self.created_at,
        }


class AssetModel(Base):
    """ORM view of :class:`~hunterx.domain.entities.Asset`."""

    __tablename__ = "hunterx_assets"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    properties: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a JSON-safe mapping."""
        return {
            "id": self.id,
            "name": self.name,
            "asset_type": self.asset_type,
            "mission_id": self.mission_id,
            "properties": json.loads(self.properties),
            "created_at": self.created_at,
        }


class ReportModel(Base):
    """ORM view of :class:`~hunterx.domain.entities.Report`."""

    __tablename__ = "hunterx_reports"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    finding_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the row to a JSON-safe mapping."""
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "kind": self.kind,
            "title": self.title,
            "summary": self.summary,
            "status": self.status,
            "finding_ids": json.loads(self.finding_ids),
            "created_at": self.created_at,
        }
