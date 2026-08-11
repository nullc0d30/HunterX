# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB audit and history entities.

These tables are append-only: written by the persistence layer (via the
versioning listener) and never edited by capability logic.
"""

from __future__ import annotations

from sqlalchemy import JSON, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class AuditLogModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.audit.AuditLog`."""

    __tablename__ = "tidb_audit_logs"

    actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False, default="update", index=True)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    object_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    object_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    before: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    occurred_at: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    __table_args__ = (
        Index("ix_tidb_audit_logs_object", "object_type", "object_id", "occurred_at"),
        Index("ix_tidb_audit_logs_actor_time", "actor", "occurred_at"),
    )


class AuditEventModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.audit.AuditEvent`."""

    __tablename__ = "tidb_audit_events"

    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    aggregate_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    aggregate_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    occurred_at: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)


class ChangeHistoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.audit.ChangeHistory`."""

    __tablename__ = "tidb_change_history"

    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    entity_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    field_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    old_value: Mapped[object] = mapped_column(JSON, nullable=True)
    new_value: Mapped[object] = mapped_column(JSON, nullable=True)
    changed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    changed_at: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    __table_args__ = (
        Index("ix_tidb_change_history_entity", "entity_type", "entity_id", "changed_at"),
    )


class VersionHistoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.audit.VersionHistory`."""

    __tablename__ = "tidb_version_history"

    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    entity_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    recorded_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    recorded_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="current")
    reason: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_tidb_version_history_entity", "entity_type", "entity_id", "recorded_version"),
    )


class TimelineEventModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.audit.TimelineEvent`."""

    __tablename__ = "tidb_timeline_events"

    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    entity_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    occurred_at: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
