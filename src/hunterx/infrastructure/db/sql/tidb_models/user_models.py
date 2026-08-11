# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB user and access entities."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class UserModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.users.User`."""

    __tablename__ = "tidb_users"

    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", index=True)
    is_service_account: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_login_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    preferences: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class RoleModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.users.Role`."""

    __tablename__ = "tidb_roles"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    permissions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class PermissionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.users.Permission`."""

    __tablename__ = "tidb_permissions"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    resource: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(32), nullable=False, default="read")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class TeamModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.users.Team`."""

    __tablename__ = "tidb_teams"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    user_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    role_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class APIClientModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.users.APIClient`."""

    __tablename__ = "tidb_api_clients"

    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    client_type: Mapped[str] = mapped_column(String(32), nullable=False, default="automation")
    user_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", index=True)
    last_used_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
