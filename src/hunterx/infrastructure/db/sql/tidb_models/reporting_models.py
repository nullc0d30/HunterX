# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB reporting entities (sections, attachments, exports)."""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class ReportSectionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting.ReportSection`."""

    __tablename__ = "tidb_report_sections"

    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    section_key: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="markdown")


class ReportAttachmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting.ReportAttachment`."""

    __tablename__ = "tidb_report_attachments"

    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    caption: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class ReportExportModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting.ReportExport`."""

    __tablename__ = "tidb_report_exports"

    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(16), nullable=False, default="pdf")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rendered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    exported_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        Index("ix_tidb_report_exports_report_status", "report_id", "status"),
    )


class ReportConsumptionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting.ReportConsumption`."""

    __tablename__ = "tidb_report_consumptions"

    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(16), nullable=False, default="pdf")
    consumer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    consumer_type: Mapped[str] = mapped_column(String(16), nullable=False, default="human")
    consumed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
