# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB knowledge-base entities (CVE/CWE/CAPEC/EPSS/MITRE)."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class CVEModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.CVE`."""

    __tablename__ = "tidb_cves"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cvss_v2: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v4: Mapped[float | None] = mapped_column(Float, nullable=True)
    published: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String(32), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    known_exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    poc_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class CWEModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.CWE`."""

    __tablename__ = "tidb_cwes"

    cwe_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mitigations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    related_cwes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    taxonomy: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class CAPECModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.CAPEC`."""

    __tablename__ = "tidb_capecs"

    capec_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    prerequisites: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    steps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    related_weaknesses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    severity_hint: Mapped[str | None] = mapped_column(String(16), nullable=True)


class EPSSModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.EPSS`."""

    __tablename__ = "tidb_epss"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    percentile: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    score_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="first.org")

    __table_args__ = (
        Index("ix_tidb_epss_cve_date", "cve_id", "score_date"),
    )


class MITRETechniqueModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.MITRETechnique`."""

    __tablename__ = "tidb_mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tactics: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    subtechniques: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    detection: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mitigations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    platforms: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class MITRETacticModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.MITRETactic`."""

    __tablename__ = "tidb_mitre_tactics"

    tactic_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    techniques: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class MITREGroupModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.MITREGroup`."""

    __tablename__ = "tidb_mitre_groups"

    group_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    aliases: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    techniques: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    software: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class ExploitReferenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.knowledge.ExploitReference`."""

    __tablename__ = "tidb_exploit_references"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="poc")
    published: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
