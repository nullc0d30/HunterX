# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB API-intelligence entities.

Mirrors ``hunterx.domain.entities.tidb.api_intelligence`` one-to-one. Every
model carries the shared TIDB envelope via :class:`TidbModelMixin` plus the
canonical API-inventory columns.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class APIRunModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIRun`."""

    __tablename__ = "tidb_api_runs"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="hybrid")
    hosts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    apis: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    operations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    parameters: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    schemas: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    auth_schemes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIHostModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIHost`."""

    __tablename__ = "tidb_api_hosts"

    target_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    scheme: Mapped[str] = mapped_column(String(8), nullable=False, default="https")
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    origin_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    api_kinds: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    api_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoint_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APISpecModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APISpec`."""

    __tablename__ = "tidb_api_specs"

    host_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    source_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    spec_type: Mapped[str] = mapped_column(String(16), nullable=False, default="openapi3")
    format: Mapped[str] = mapped_column(String(8), nullable=False, default="yaml")
    spec_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    operation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    schema_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    integrity: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIVersionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIVersion`."""

    __tablename__ = "tidb_api_versions"

    host_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    api_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    api_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    spec_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    path_prefix: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    operation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoint_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_api_versions_host_name", "host_id", "api_name"),
    )


class APIOperationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIOperation`."""

    __tablename__ = "tidb_api_operations"

    api_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    host_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET", index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    normalized_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    path_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    response_content_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    auth_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pagination: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    has_filters: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rate_limit_hint: Mapped[str] = mapped_column(String(16), nullable=False, default="none")
    parameter_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    security_schemes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    sources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_api_operations_hash_method", "path_hash", "method"),
    )


class APIParameterModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIParameter`."""

    __tablename__ = "tidb_api_parameters"

    operation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    location: Mapped[str] = mapped_column(String(16), nullable=False, default="query")
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    param_type: Mapped[str] = mapped_column(String(64), nullable=False, default="string")
    schema_digest: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    nullable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    default_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    enum_values: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    pattern: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="spec")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_api_parameters_op_name", "operation_id", "name"),
    )


class APISchemaModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APISchema`."""

    __tablename__ = "tidb_api_schemas"

    operation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    direction: Mapped[str] = mapped_column(String(8), nullable=False, default="response")
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="object")
    content_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    digest: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fields: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="spec")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIAuthenticationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIAuthentication`."""

    __tablename__ = "tidb_api_authentications"

    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    host_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    scheme_type: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    token_location: Mapped[str] = mapped_column(String(64), nullable=False, default="header")
    flows: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="spec")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIAuthorizationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIAuthorization`."""

    __tablename__ = "tidb_api_authorizations"

    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    model_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    roles: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="spec")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIRateLimitModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIRateLimit`."""

    __tablename__ = "tidb_api_rate_limits"

    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    host_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    style: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    headers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    declared: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="web")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIPaginationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIPagination`."""

    __tablename__ = "tidb_api_paginations"

    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    operation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    style: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    limit_param: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    offset_param: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cursor_param: Mapped[str | None] = mapped_column(String(64), nullable=True)
    total_source: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIFilterModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIFilter`."""

    __tablename__ = "tidb_api_filters"

    operation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    filter_param: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    style: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    operators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIEvidence`."""

    __tablename__ = "tidb_api_evidence"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="operation")
    subject_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="tidb-intelligence")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="api")
    strength: Mapped[str] = mapped_column(String(16), nullable=False, default="moderate")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    integrity: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_api_evidence_subject", "subject_type", "subject_id"),
    )


class APIConflictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIConflict`."""

    __tablename__ = "tidb_api_conflicts"

    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="operation")
    conflict_type: Mapped[str] = mapped_column(String(32), nullable=False, default="identity")
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    selected: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    selected_source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class APIChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api_intelligence.APIChange`."""

    __tablename__ = "tidb_api_changes"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="operation")
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, default="changed")
    previous: Mapped[str] = mapped_column(Text, nullable=False, default="")
    current: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_api_changes_subject_type", "subject_type", "subject"),
    )
