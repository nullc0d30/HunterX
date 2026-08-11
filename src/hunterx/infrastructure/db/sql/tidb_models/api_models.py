# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB API-surface entities."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class APIModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api.API`."""

    __tablename__ = "tidb_apis"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    base_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    api_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    auth_scheme: Mapped[str | None] = mapped_column(String(64), nullable=True)
    spec_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    discovered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class RESTEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api.RESTEndpoint`."""

    __tablename__ = "tidb_rest_endpoints"

    api_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_apis.id"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    auth_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_meta: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_rest_endpoints_api_method_path", "api_id", "method", "path"),
    )


class GraphQLEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api.GraphQLEndpoint`."""

    __tablename__ = "tidb_graphql_endpoints"

    api_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_apis.id"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(Text, nullable=False, default="/graphql")
    introspection_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    query_limits: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class SOAPEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api.SOAPEndpoint`."""

    __tablename__ = "tidb_soap_endpoints"

    api_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_apis.id"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    wsdl_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    operations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class RPCServiceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api.RPCService`."""

    __tablename__ = "tidb_rpc_services"

    api_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_apis.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False, default="json-rpc")
    endpoints: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class AuthenticationSchemeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api.AuthenticationScheme`."""

    __tablename__ = "tidb_authentication_schemes"

    api_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_apis.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="default")
    scheme_type: Mapped[str] = mapped_column(String(32), nullable=False, default="bearer")
    config: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class AuthorizationModelModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.api.AuthorizationModel`."""

    __tablename__ = "tidb_authorization_models"

    api_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_apis.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="default")
    model_type: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    roles: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
