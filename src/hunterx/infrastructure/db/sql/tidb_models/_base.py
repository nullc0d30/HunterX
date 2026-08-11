# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base for TIDB SQLAlchemy ORM models.

Mirrors the ``TidbEntity`` envelope from ``hunterx.domain.entities.tidb``.
All TIDB tables share the USS system-of-record columns: identity, assertion
and state timestamps, optimistic-lock versioning, soft delete and free-form
``meta``. Complex values are stored as JSON (``JSONB`` on PostgreSQL, ``JSON``
on SQLite) so the schema is portable across the test and production stores.
"""

from __future__ import annotations

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.factory import get_base

Base = get_base()


class TidbModelMixin:
    """Shared TIDB envelope columns for every TIDB table."""

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(32), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    deleted_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    meta: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    def envelope_dict(self) -> dict[str, object]:
        """Serialize the TIDB envelope to a JSON-safe mapping."""
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "version": self.version,
            "revision": self.revision,
            "schema_version": self.schema_version,
            "deleted_at": self.deleted_at,
            "meta": self.meta,
        }
