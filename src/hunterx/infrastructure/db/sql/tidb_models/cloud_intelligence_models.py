# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS intelligence TIDB ORM models.

Mirrors ``hunterx.domain.entities.tidb.cloud_intelligence`` one-to-one. Every
table stores metadata and masked indicators only — never cloud credentials,
access keys, secret values, tokens or private keys.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class CloudRunModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudRun`."""

    __tablename__ = "tidb_cloud_runs"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="hybrid")
    providers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    accounts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    regions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resources: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    services: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoints: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    environments: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    identities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    saas_providers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    saas_integrations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    webhooks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    storage: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    compute: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    containers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kubernetes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    databases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    gateways: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cdns: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    load_balancers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cicd: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    secrets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudProviderModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudProvider`."""

    __tablename__ = "tidb_cloud_providers"

    name: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    evidence_indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudAccountModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudAccount`."""

    __tablename__ = "tidb_cloud_accounts"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="account", index=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (Index("ix_tidb_cloud_accounts_provider_kind", "provider", "kind"),)


class CloudRegionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudRegion`."""

    __tablename__ = "tidb_cloud_regions"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (Index("ix_tidb_cloud_regions_provider_region", "provider", "region"),)


class CloudResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudResource`."""

    __tablename__ = "tidb_cloud_resources"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    resource_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    service: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    public: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (Index("ix_tidb_cloud_resources_provider_identifier", "provider", "identifier"),)


class CloudServiceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudService`."""

    __tablename__ = "tidb_cloud_services"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    service: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (Index("ix_tidb_cloud_services_provider_service", "provider", "service"),)


class CloudEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudEndpoint`."""

    __tablename__ = "tidb_cloud_endpoints"

    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    service: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    plane: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    exposure: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (Index("ix_tidb_cloud_endpoints_provider_service", "provider", "service"),)


class CloudEnvironmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudEnvironment`."""

    __tablename__ = "tidb_cloud_environments"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudIdentityModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudIdentity`."""

    __tablename__ = "tidb_cloud_identities"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    identity_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    account: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    permissions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudRoleModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudRole`."""

    __tablename__ = "tidb_cloud_roles"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    account: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    assume_role: Mapped[bool] = mapped_column(JSON, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudPermissionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudPermission`."""

    __tablename__ = "tidb_cloud_permissions"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    resource: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudIntegrationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudIntegration`."""

    __tablename__ = "tidb_cloud_integrations"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    integration_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    scope: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class SaaSProviderModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.SaaSProvider`."""

    __tablename__ = "tidb_cloud_saas_providers"

    name: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    provider_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="saas")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class SaaSApplicationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.SaaSApplication`."""

    __tablename__ = "tidb_cloud_saas_applications"

    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    saas_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class SaaSIntegrationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.SaaSIntegration`."""

    __tablename__ = "tidb_cloud_saas_integrations"

    saas_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    integration_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    auth_mechanism: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    scope: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class WebhookModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.Webhook`."""

    __tablename__ = "tidb_cloud_webhooks"

    direction: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    event_type: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    signing: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudDependencyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudDependency`."""

    __tablename__ = "tidb_cloud_dependencies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    application: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class StorageResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.StorageResource`."""

    __tablename__ = "tidb_cloud_storage_resources"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    storage_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="object")
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    public: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class ComputeResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.ComputeResource`."""

    __tablename__ = "tidb_cloud_compute_resources"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    compute_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="instance")
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class ContainerResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.ContainerResource`."""

    __tablename__ = "tidb_cloud_container_resources"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    container_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="registry")
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    registry: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    image: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class KubernetesResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.KubernetesResource`."""

    __tablename__ = "tidb_cloud_kubernetes_resources"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    cluster: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class DatabaseResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.DatabaseResource`."""

    __tablename__ = "tidb_cloud_database_resources"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    database_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="managed")
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    technology: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    public: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class MessageInfrastructureModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.MessageInfrastructure`."""

    __tablename__ = "tidb_cloud_message_infrastructure"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="queue", index=True)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    service: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class ApiGatewayResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.ApiGatewayResource`."""

    __tablename__ = "tidb_cloud_api_gateways"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    gateway_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="gateway")
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    backend: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CdnResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CdnResource`."""

    __tablename__ = "tidb_cloud_cdns"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class LoadBalancerResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.LoadBalancerResource`."""

    __tablename__ = "tidb_cloud_load_balancers"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    backend: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CiCdResourceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CiCdResource`."""

    __tablename__ = "tidb_cloud_cicd_resources"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="pipeline")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    repository: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class SecretManagementIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.SecretManagementIndicator`."""

    __tablename__ = "tidb_cloud_secret_management"

    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="secrets-manager")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reference: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudExposureIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudExposureIndicator`."""

    __tablename__ = "tidb_cloud_exposure_indicators"

    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudObservation`."""

    __tablename__ = "tidb_cloud_observations"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="cloud")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CloudEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudEvidence`."""

    __tablename__ = "tidb_cloud_evidence"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="observation", index=True)
    subject_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="cloud")
    strength: Mapped[str] = mapped_column(String(16), nullable=False, default="moderate")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (Index("ix_tidb_cloud_evidence_subject", "subject_type", "subject_id"),)


class CloudChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.cloud_intelligence.CloudChange`."""

    __tablename__ = "tidb_cloud_changes"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="provider")
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, default="changed")
    previous: Mapped[str] = mapped_column(Text, nullable=False, default="")
    current: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
