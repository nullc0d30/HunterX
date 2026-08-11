# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB finding-layer entities (history, evidence, risk)."""

from __future__ import annotations

from sqlalchemy import JSON, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class FindingHistoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.FindingHistory`."""

    __tablename__ = "tidb_finding_history"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    finding_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="new")
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    delta: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    changed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_tidb_finding_history_finding_version", "finding_id", "finding_version"),
    )


class EvidenceAttachmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.EvidenceAttachment`."""

    __tablename__ = "tidb_evidence_attachments"

    evidence_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)


class RiskRatingModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.RiskRating`."""

    __tablename__ = "tidb_risk_ratings"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    vector: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    formula_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    overrides: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    calculated_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class SeverityBandModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.SeverityBand`."""

    __tablename__ = "tidb_severity_bands"

    name: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    score_min: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    score_max: Mapped[float] = mapped_column(Float, nullable=False, default=10.0)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ConfidenceLevelModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.ConfidenceLevel`."""

    __tablename__ = "tidb_confidence_levels"

    name: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    min_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_value: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class RecommendationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.Recommendation`."""

    __tablename__ = "tidb_recommendations"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="fix")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ReferenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.Reference`."""

    __tablename__ = "tidb_references"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="url")
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ValidationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.Validation`."""

    __tablename__ = "tidb_validations"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    result: Mapped[str] = mapped_column(String(32), nullable=False, default="inconclusive")
    validator: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    detail: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    validated_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class VerificationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.findings.Verification`."""

    __tablename__ = "tidb_verifications"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="inconclusive")
    verifier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    verified_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
