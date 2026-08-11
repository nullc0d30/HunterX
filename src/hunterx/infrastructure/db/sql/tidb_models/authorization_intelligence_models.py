# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB authorization-intelligence entities.

Mirrors ``hunterx.domain.entities.tidb.authorization_intelligence`` one-to-one.
Every model carries the shared TIDB envelope via :class:`TidbModelMixin` plus
the canonical authorization-inventory columns. No model stores raw credentials,
token values, authorization-header values or JWT claims — only metadata and
masked indicators.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class AuthorizationRunModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationRun`."""

    __tablename__ = "tidb_authorization_runs"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="hybrid")
    subjects: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    roles: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    permissions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resources: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    admin_surfaces: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    function_level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    object_level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    field_level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationSubjectModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationSubject`."""

    __tablename__ = "tidb_authorization_subjects"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    subject_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationRoleModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationRole`."""

    __tablename__ = "tidb_authorization_roles"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    custom: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationGroupModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationGroup`."""

    __tablename__ = "tidb_authorization_groups"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationPermissionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationPermission`."""

    __tablename__ = "tidb_authorization_permissions"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationScopeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationScope`."""

    __tablename__ = "tidb_authorization_scopes"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationClaimModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationClaim`."""

    __tablename__ = "tidb_authorization_claims"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationPolicyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationPolicy`."""

    __tablename__ = "tidb_authorization_policies"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    model_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    mechanism: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationResource`."""

    __tablename__ = "tidb_authorization_resources"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    resource_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    parent: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationActionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationAction`."""

    __tablename__ = "tidb_authorization_actions"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    original: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationIdentifierModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationIdentifier`."""

    __tablename__ = "tidb_authorization_identifiers"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    identifier_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    location: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationOwnershipModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationOwnership`."""

    __tablename__ = "tidb_authorization_ownership"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    ownership_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationTenantModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationTenant`."""

    __tablename__ = "tidb_authorization_tenants"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    tenant_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    location: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationAdminSurfaceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationAdminSurface`."""

    __tablename__ = "tidb_authorization_admin_surfaces"

    url: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    surface_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationFunctionLevelModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationFunctionLevel`."""

    __tablename__ = "tidb_authorization_function_level"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    function: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    required_role: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationObjectLevelModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationObjectLevel`."""

    __tablename__ = "tidb_authorization_object_level"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    parent_resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationFieldLevelModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationFieldLevel`."""

    __tablename__ = "tidb_authorization_field_level"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    field: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationFrontendModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationFrontend`."""

    __tablename__ = "tidb_authorization_frontend"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    check_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown", index=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    js_asset: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationBackendModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationBackend`."""

    __tablename__ = "tidb_authorization_backend"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    mechanism: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationApiCorrelationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationApiCorrelation`."""

    __tablename__ = "tidb_authorization_api_correlations"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    authentication: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    scope: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    permission: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    tenant: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    policy: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationGraphQLModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationGraphQL`."""

    __tablename__ = "tidb_authorization_graphql"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    subject: Mapped[str] = mapped_column(String(32), nullable=False, default="field", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    directive: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationWebSocketModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationWebSocket`."""

    __tablename__ = "tidb_authorization_websockets"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    channel: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    mechanism: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown", index=True)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationServiceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationService`."""

    __tablename__ = "tidb_authorization_services"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    service_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    mechanism: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationDecisionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationDecision`."""

    __tablename__ = "tidb_authorization_decisions"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationMassAssignmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationMassAssignment`."""

    __tablename__ = "tidb_authorization_mass_assignment"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    model: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    fields: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationAccessControlModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationAccessControl`."""

    __tablename__ = "tidb_authorization_access_control"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    relationship_type: Mapped[str] = mapped_column(String(32), nullable=False, default="role", index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationObservation`."""

    __tablename__ = "tidb_authorization_observations"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="authorization")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationEvidence`."""

    __tablename__ = "tidb_authorization_evidence"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="resource", index=True)
    subject_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="authorization")
    strength: Mapped[str] = mapped_column(String(16), nullable=False, default="moderate")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthorizationChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.authorization_intelligence.AuthorizationChange`."""

    __tablename__ = "tidb_authorization_changes"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="resource")
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, default="changed")
    previous: Mapped[str] = mapped_column(Text, nullable=False, default="")
    current: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
