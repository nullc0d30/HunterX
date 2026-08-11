# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB technology entities.

System-of-record tables for the technology fingerprinting capability: the
canonical catalogue (categories, families, definitions), per-asset technology
observations with versions and evidence, and the derived intelligence records
(conflicts, changes and fingerprint run summaries).
"""

from __future__ import annotations

from sqlalchemy import JSON, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class TechnologyCategoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyCategory`."""

    __tablename__ = "tidb_technology_categories"

    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    family: Mapped[str] = mapped_column(String(64), nullable=False, default="other")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class TechnologyFamilyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyFamily`."""

    __tablename__ = "tidb_technology_families"

    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class TechnologyDefinitionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyDefinition`."""

    __tablename__ = "tidb_technology_definitions"

    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="other", index=True)
    family: Mapped[str] = mapped_column(String(64), nullable=False, default="other", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    base_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.9)


class TechnologyObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyObservation`."""

    __tablename__ = "tidb_technology_observations"

    asset: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(16), nullable=False, default="hostname")
    raw_name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    software_version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    version_confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="other", index=True)
    family: Mapped[str] = mapped_column(String(64), nullable=False, default="other", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    validation_status: Mapped[str] = mapped_column(String(16), nullable=False, default="valid")
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_technology_obs_asset_name", "asset", "canonical_name"),
    )


class TechnologyVersionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyVersion`."""

    __tablename__ = "tidb_technology_versions"

    observation_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    asset: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    lower: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    upper: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")


class TechnologyEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyEvidence`."""

    __tablename__ = "tidb_technology_evidence"

    observation_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    asset: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    strength: Mapped[str] = mapped_column(String(16), nullable=False, default="moderate")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")


class TechnologyConflictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyConflict`."""

    __tablename__ = "tidb_technology_conflicts"

    asset: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    technology: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    conflict_type: Mapped[str] = mapped_column(String(32), nullable=False, default="version")
    selected_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    selected_source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_technology_conflicts_asset_tech", "asset", "technology"),
    )


class TechnologyChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyChange`."""

    __tablename__ = "tidb_technology_changes"

    asset: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    technology: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, default="added", index=True)
    old_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    new_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class TechnologyRunModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.technology.TechnologyRun`."""

    __tablename__ = "tidb_technology_runs"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", index=True)
    observations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    technologies: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    versions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
