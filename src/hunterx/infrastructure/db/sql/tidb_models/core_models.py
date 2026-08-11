# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB core entities (organizations, programs, scope, tags)."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class OrganizationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.core.Organization`."""

    __tablename__ = "tidb_organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    website: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    industry: Mapped[str | None] = mapped_column(String(128), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)


class ProgramModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.core.Program`."""

    __tablename__ = "tidb_programs"

    organization_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_organizations.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    starts_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ends_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ScopePolicyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.core.ScopePolicy`."""

    __tablename__ = "tidb_scope_policies"

    program_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_programs.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="default")
    rules: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    destructive_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approval_required_for: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    windows: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)


class AssetGroupModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.core.AssetGroup`."""

    __tablename__ = "tidb_asset_groups"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    program_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_programs.id"), nullable=True, index=True
    )
    parent_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_asset_groups.id"), nullable=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class TagModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.core.Tag`."""

    __tablename__ = "tidb_tags"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    color: Mapped[str | None] = mapped_column(String(16), nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
