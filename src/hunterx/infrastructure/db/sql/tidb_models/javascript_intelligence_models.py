# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB JavaScript intelligence entities.

System-of-record tables for the JavaScript Intelligence & Client-Side
Attack-Surface Discovery capability: per-asset acquisitions, correlated
findings (endpoints, routes, auth, domains, services, storage, secrets,
technology, dependencies, configuration, workers, wasm, security, dynamic
imports) and the derived intelligence records (conflicts, changes and run
summaries).
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class JSIntelligenceAssetModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceAsset`."""

    __tablename__ = "tidb_js_intelligence_assets"

    url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    parent_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    asset_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="external", index=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    etag: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_modified: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="crawl")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_js_assets_hash_url", "content_hash", "url"),
    )


class JSIntelligenceEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceEndpoint`."""

    __tablename__ = "tidb_js_intelligence_endpoints"

    url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="fetch", index=True)
    api_type: Mapped[str] = mapped_column(String(16), nullable=False, default="rest", index=True)
    base_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    parameters: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    headers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_js_endpoints_url_method", "url", "method"),
    )


class JSIntelligenceRouteModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceRoute`."""

    __tablename__ = "tidb_js_intelligence_routes"

    route: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pattern: Mapped[str] = mapped_column(Text, nullable=False, default="")
    parameters: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    framework: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceAuthModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceAuth`."""

    __tablename__ = "tidb_js_intelligence_auth"

    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mechanism: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceDomainModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceDomain`."""

    __tablename__ = "tidb_js_intelligence_domains"

    domain: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    relation: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    hostname: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceServiceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceService`."""

    __tablename__ = "tidb_js_intelligence_services"

    provider: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    service: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    domain: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceStorageModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceStorage`."""

    __tablename__ = "tidb_js_intelligence_storage"

    storage_type: Mapped[str] = mapped_column(String(32), nullable=False, default="local-storage", index=True)
    key_pattern: Mapped[str] = mapped_column(Text, nullable=False, default="")
    usage_context: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceSecretModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceSecret`.

    Never stores a raw value: only the masked preview and the value hash.
    """

    __tablename__ = "tidb_js_intelligence_secrets"

    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="generic-secret", index=True)
    masked_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    location: Mapped[str] = mapped_column(Text, nullable=False, default="")
    file: Mapped[str] = mapped_column(Text, nullable=False, default="")
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    offset: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    detection_rule: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    tier: Mapped[str] = mapped_column(String(32), nullable=False, default="low", index=True)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_js_secrets_hash_class", "value_hash", "classification"),
    )


class JSIntelligenceTechnologyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceTechnology`."""

    __tablename__ = "tidb_js_intelligence_technology"

    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="library", index=True)
    version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    version_confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceDependencyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceDependency`."""

    __tablename__ = "tidb_js_intelligence_dependencies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="import")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceConfigurationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceConfiguration`."""

    __tablename__ = "tidb_js_intelligence_configuration"

    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    key: Mapped[str] = mapped_column(Text, nullable=False, default="")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceWorkerModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceWorker`."""

    __tablename__ = "tidb_js_intelligence_workers"

    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="worker", index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    registration_context: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceWasmModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceWasm`."""

    __tablename__ = "tidb_js_intelligence_wasm"

    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="resource", index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceSecurityModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceSecurity`."""

    __tablename__ = "tidb_js_intelligence_security"

    api: Mapped[str] = mapped_column(String(32), nullable=False, default="", index=True)
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceImportModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceImport`."""

    __tablename__ = "tidb_js_intelligence_imports"

    specifier: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    chunk: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    asset_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceConflictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceConflict`."""

    __tablename__ = "tidb_js_intelligence_conflicts"

    subject: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    selected: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_js_conflicts_subject_type", "subject", "artifact_type"),
    )


class JSIntelligenceChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceChange`."""

    __tablename__ = "tidb_js_intelligence_changes"

    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    subject: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, default="changed", index=True)
    previous: Mapped[str] = mapped_column(Text, nullable=False, default="")
    current: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class JSIntelligenceRunModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.javascript_intelligence.JSIntelligenceRun`."""

    __tablename__ = "tidb_js_intelligence_runs"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", index=True)
    assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoints: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    routes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    secrets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    services: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dependencies: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    technologies: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
