# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB web crawling entities.

Mirrors ``hunterx.domain.entities.tidb.web_crawl`` one-to-one. The tables
extend the baseline web-layer tables with the crawl-specific projections the
web crawling & web attack-surface discovery capability persists.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class WebOriginModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.WebOrigin`."""

    __tablename__ = "tidb_web_origins"

    scheme: Mapped[str] = mapped_column(String(16), nullable=False, default="https")
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    is_upgrade_candidate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)


class URLObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.URLObservation`."""

    __tablename__ = "tidb_url_observations"

    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    origin_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_web_origins.id"), nullable=True, index=True
    )
    path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    query: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="crawl")
    tool_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    execution_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    times_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    key: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)


class WebRedirectModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.WebRedirect`."""

    __tablename__ = "tidb_web_redirects"

    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    destination_url: Mapped[str] = mapped_column(Text, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, default=301)
    redirect_type: Mapped[str] = mapped_column(String(32), nullable=False, default="permanent")
    chain: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="crawl")
    tool_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)


class WebAPIEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.WebAPIEndpoint`."""

    __tablename__ = "tidb_web_api_endpoints"

    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parameters: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="crawl")
    tool_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)


class WebSocketEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.WebSocketEndpoint`."""

    __tablename__ = "tidb_web_websocket_endpoints"

    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="wss")
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="crawl")
    tool_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)


class WebGraphQLEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.WebGraphQLEndpoint`."""

    __tablename__ = "tidb_web_graphql_endpoints"

    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    methods: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    introspection: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="crawl")
    tool_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)


class WebAuthenticationBoundaryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.AuthenticationBoundary`."""

    __tablename__ = "tidb_web_auth_boundaries"

    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    scheme: Mapped[str] = mapped_column(String(32), nullable=False, default="session")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="crawl")
    tool_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)


class CrawlExecutionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.CrawlExecution`."""

    __tablename__ = "tidb_crawl_executions"

    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    target_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed", index=True)
    urls_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    urls_distinct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoints: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redirects: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    websockets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    graphqls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    auth_boundaries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    policy: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)


class CrawlEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web_crawl.CrawlEvidence`."""

    __tablename__ = "tidb_crawl_evidence"

    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="html", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="crawl")
    tool_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    integrity: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
