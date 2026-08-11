# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS attack-surface intelligence TIDB entities.

System-of-record entities for the Wave 11 cloud & SaaS attack-surface
intelligence capability (Sprint 017). They carry the canonical, evidence-backed
cloud inventory of an authorized target: cloud providers, accounts/subscriptions/
projects/organizations/tenants, regions, resources, services, endpoints (with
control/data/identity/management plane classification), environments, identity
& IAM indicators, SaaS platforms, SaaS integrations, webhooks, third-party
dependencies, storage/compute/container/Kubernetes/database/message/gateway/CDN/
load-balancer/CI/CD resource indicators, secret-management indicators (never
values), exposure indicators (intelligence, never vulnerabilities) and the
derived intelligence (observations, evidence, changes and run records).

Security boundary: intelligence & discovery only. These entities store metadata,
masked/derived values and secret fingerprints — never cloud credentials, access
keys, secret keys, session tokens, OAuth secrets, private keys, secret values or
database credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class CloudRun(TidbEntity):
    """Observability record for a cloud intelligence run.

    Attributes:
        mission_id: owning mission id.
        target_key: canonical target the run covered.
        target_id: owning target record id.
        status: terminal run status.
        mode: execution posture (passive/active/hybrid).
        providers / accounts / regions / resources / services / endpoints /
            environments / identities / saas_providers / saas_integrations /
            webhooks / storage / compute / containers / kubernetes /
            databases / gateways / cdns / load_balancers / cicd / secrets /
            changes / conflicts: artifact counts.
        started_at / completed_at / duration_ms: timing.
        summary: free-form run summary (tools, stats).
        correlation_id: correlation id of the run.

    """

    mission_id: str = ""
    target_key: str = ""
    target_id: str | None = None
    status: str = "running"
    mode: str = "hybrid"
    providers: int = 0
    accounts: int = 0
    regions: int = 0
    resources: int = 0
    services: int = 0
    endpoints: int = 0
    environments: int = 0
    identities: int = 0
    saas_providers: int = 0
    saas_integrations: int = 0
    webhooks: int = 0
    storage: int = 0
    compute: int = 0
    containers: int = 0
    kubernetes: int = 0
    databases: int = 0
    gateways: int = 0
    cdns: int = 0
    load_balancers: int = 0
    cicd: int = 0
    secrets: int = 0
    changes: int = 0
    conflicts: int = 0
    started_at: str = ""
    completed_at: str | None = None
    duration_ms: int = 0
    summary: dict[str, object] = field(default_factory=dict)
    correlation_id: str = ""


@dataclass(slots=True)
class CloudProvider(TidbEntity):
    """A detected cloud/platform provider.

    Attributes:
        name: canonical provider name (``aws``/``azure``/``gcp``/``cloudflare``/
            ``digitalocean``/``vercel``/``netlify``/``kubernetes``/...).
        display_name: human provider label.
        evidence_indicators: evidence strings that triggered the detection.
        confidence: detection confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id.

    """

    name: str = ""
    display_name: str = ""
    evidence_indicators: list[str] = field(default_factory=list)
    confidence: float = 0.5
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudAccount(TidbEntity):
    """A cloud account/subscription/project/organization/tenant indicator.

    Attributes:
        provider: owning provider name.
        kind: ``account``/``subscription``/``project``/``organization``/
            ``tenant``/``workspace``/``resource-group``/``unknown``.
        value: the observed identifier (metadata only; never validated).
        name: optional human label.
        region: optional associated region.
        environment: optional environment classification.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    kind: str = "account"
    value: str = ""
    name: str = ""
    region: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudRegion(TidbEntity):
    """A cloud region/location indicator.

    Attributes:
        provider: owning provider name.
        region: canonical region code (``us-east-1``/``eastus``/
            ``us-central1``/...).
        resource: optional associated resource indicator.
        environment: optional environment classification.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    region: str = ""
    resource: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudResource(TidbEntity):
    """A cloud resource indicator (identifier only, never contents).

    Attributes:
        provider: owning provider name.
        resource_kind: ``bucket``/``instance``/``function``/``cluster``/
            ``database``/``queue``/``topic``/``api``/``gateway``/
            ``load-balancer``/``cdn``/``registry``/``identity``/``secret``/
            ``unknown``.
        identifier: the observable resource identifier.
        service: associated cloud service name.
        region: associated region.
        endpoint: associated endpoint hostname.
        environment: environment classification.
        public: exposure classification (``public``/``private``/``internal``/
            ``unknown``).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    resource_kind: str = "unknown"
    identifier: str = ""
    service: str = ""
    region: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    public: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudService(TidbEntity):
    """A classified cloud service indicator.

    Attributes:
        provider: owning provider name.
        service: canonical service name (``s3``/``ec2``/``lambda``/``cloudfront``/
            ``app-service``/``cloud-run``/...).
        category: service family (``compute``/``storage``/``database``/
            ``networking``/``serverless``/``container``/``identity``/
            ``monitoring``/``ci-cd``/``messaging``/``unknown``).
        resource: optional associated resource indicator.
        region: optional region.
        endpoint: optional endpoint hostname.
        environment: environment classification.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    service: str = ""
    category: str = "unknown"
    resource: str = ""
    region: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudEndpoint(TidbEntity):
    """A cloud-related endpoint with plane & exposure classification.

    Attributes:
        endpoint: canonical endpoint hostname/URL.
        provider: owning provider name.
        service: associated service name.
        plane: ``control``/``data``/``identity``/``management``/``developer``/
            ``unknown``.
        exposure: ``public``/``public-indicator``/``private-indicator``/
            ``internal-indicator``/``unknown``.
        region: optional region.
        environment: environment classification.
        domain: optional owning domain.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    endpoint: str = ""
    provider: str = ""
    service: str = ""
    plane: str = "unknown"
    exposure: str = "unknown"
    region: str = ""
    environment: str = "unknown"
    domain: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudEnvironment(TidbEntity):
    """An environment classification for a cloud subject.

    Attributes:
        provider: owning provider name.
        environment: ``production``/``staging``/``development``/``testing``/
            ``qa``/``sandbox``/``preview``/``dr``/``unknown``.
        subject: optional associated subject (domain/resource/endpoint).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    environment: str = "unknown"
    subject: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudIdentity(TidbEntity):
    """A cloud identity / IAM indicator (metadata only, never validated).

    Attributes:
        provider: owning provider name.
        identity_kind: ``service-account``/``managed-identity``/``user``/
            ``role``/``group``/``client``/``oidc``/``cognito-pool``/
            ``entra-tenant``/``assume-role``/``federated``/``unknown``.
        name: canonical identity label.
        identifier: observable identifier (non-secret metadata).
        account: optional associated account indicator.
        role: optional associated role.
        permissions: optional permission indicators.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    identity_kind: str = "unknown"
    name: str = ""
    identifier: str = ""
    account: str = ""
    role: str = ""
    permissions: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudRole(TidbEntity):
    """A cloud IAM role indicator (metadata only)."""

    provider: str = ""
    name: str = ""
    account: str = ""
    assume_role: bool = False
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudPermission(TidbEntity):
    """A cloud permission indicator (from documented/observed material only)."""

    provider: str = ""
    name: str = ""
    action: str = ""
    resource: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudIntegration(TidbEntity):
    """A cloud/SaaS integration indicator.

    Attributes:
        provider: owning provider name.
        integration_type: ``oauth``/``api``/``webhook``/``sdk``/
            ``single-sign-on``/``identity-federation``/``unknown``.
        name: canonical integration label.
        endpoint: associated endpoint.
        scope: declared scope (metadata only).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    integration_type: str = "unknown"
    name: str = ""
    endpoint: str = ""
    scope: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class SaaSProvider(TidbEntity):
    """A detected SaaS platform (evidence-based)."""

    name: str = ""
    display_name: str = ""
    provider_kind: str = "saas"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class SaaSApplication(TidbEntity):
    """A SaaS application reference observed on the target.

    Attributes:
        name: canonical SaaS application label.
        saas_provider: owning SaaS provider name.
        url: observed application URL.
        environment: environment classification.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    name: str = ""
    saas_provider: str = ""
    url: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class SaaSIntegration(TidbEntity):
    """A SaaS integration (OAuth/API/webhook) indicator.

    Attributes:
        saas_provider: owning SaaS provider name.
        integration_type: ``oauth``/``api``/``webhook``/``js-script``/
            ``analytics``/``payment``/``email``/``monitoring``/
            ``error-tracking``/``crm``/``support``/``identity``/``ci-cd``/
            ``cloud-storage``/``communication``/``unknown``.
        name: canonical integration label.
        endpoint: associated endpoint/domain.
        auth_mechanism: ``oauth``/``api-key``/``webhook-signature``/
            ``none``/``unknown``.
        scope: declared scope (metadata only).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    saas_provider: str = ""
    integration_type: str = "unknown"
    name: str = ""
    endpoint: str = ""
    auth_mechanism: str = "unknown"
    scope: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class Webhook(TidbEntity):
    """A webhook indicator (inbound/outbound endpoint, never signatures).

    Attributes:
        direction: ``inbound``/``outbound``/``unknown``.
        provider: owning provider/SaaS name.
        endpoint: webhook endpoint URL/pattern.
        event_type: event-type indicators when observed.
        signing: signing-mechanism indicator (``hmac-sha256``/``secret-ref``/
            ``unknown``).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    direction: str = "unknown"
    provider: str = ""
    endpoint: str = ""
    event_type: str = ""
    signing: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudDependency(TidbEntity):
    """A third-party/cloud dependency relationship.

    Attributes:
        name: canonical dependency label.
        provider: owning provider/SaaS name.
        kind: ``cdn``/``api``/``sdk``/``saas``/``cloud-service``/
            ``registry``/``unknown``.
        endpoint: associated endpoint.
        application: owning application label when known.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    name: str = ""
    provider: str = ""
    kind: str = "unknown"
    endpoint: str = ""
    application: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class StorageResource(TidbEntity):
    """A cloud storage resource indicator (never contents)."""

    provider: str = ""
    storage_kind: str = "object"
    identifier: str = ""
    endpoint: str = ""
    public: str = "unknown"
    region: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class ComputeResource(TidbEntity):
    """A cloud compute/serverless resource indicator (metadata only)."""

    provider: str = ""
    compute_kind: str = "instance"
    identifier: str = ""
    endpoint: str = ""
    region: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class ContainerResource(TidbEntity):
    """A container/registry resource indicator."""

    provider: str = ""
    container_kind: str = "registry"
    identifier: str = ""
    registry: str = ""
    image: str = ""
    region: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class KubernetesResource(TidbEntity):
    """A Kubernetes resource indicator (never a control-plane interaction).

    Attributes:
        provider: owning provider name.
        cluster: cluster indicator (``eks``/``aks``/``gke``/``k8s``).
        kind: ``ingress``/``service``/``namespace``/``deployment``/
            ``dashboard``/``apiserver``/``helm``/``unknown``.
        name: resource name indicator.
        endpoint: observable endpoint.
        environment: environment classification.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    provider: str = ""
    cluster: str = ""
    kind: str = "unknown"
    name: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class DatabaseResource(TidbEntity):
    """A managed database resource indicator (never connected)."""

    provider: str = ""
    database_kind: str = "managed"
    identifier: str = ""
    endpoint: str = ""
    technology: str = ""
    region: str = ""
    public: str = "unknown"
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class MessageInfrastructure(TidbEntity):
    """A message/event infrastructure indicator (never published to)."""

    provider: str = ""
    kind: str = "queue"
    identifier: str = ""
    service: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class ApiGatewayResource(TidbEntity):
    """An API gateway / edge resource indicator."""

    provider: str = ""
    gateway_kind: str = "gateway"
    identifier: str = ""
    endpoint: str = ""
    backend: str = ""
    region: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CdnResource(TidbEntity):
    """A CDN resource indicator."""

    provider: str = ""
    identifier: str = ""
    endpoint: str = ""
    origin: str = ""
    region: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class LoadBalancerResource(TidbEntity):
    """A load-balancer resource indicator."""

    provider: str = ""
    identifier: str = ""
    endpoint: str = ""
    backend: str = ""
    region: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CiCdResource(TidbEntity):
    """A CI/CD infrastructure indicator (never credentials)."""

    provider: str = ""
    kind: str = "pipeline"
    name: str = ""
    repository: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class SecretManagementIndicator(TidbEntity):
    """A secret-management indicator (references/fingerprints only)."""

    provider: str = ""
    kind: str = "secrets-manager"
    name: str = ""
    reference: str = ""
    fingerprint: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudExposureIndicator(TidbEntity):
    """A cloud exposure intelligence indicator (never a vulnerability).

    Attributes:
        kind: ``public-storage``/``public-admin-interface``/
            ``exposed-management-endpoint``/``missing-auth-indicator``/
            ``documented-resource``/``debug-endpoint``/``unusual-exposure``/
            ``dangling-resource``/``unknown``.
        subject: affected subject (domain/resource/endpoint).
        detail: masked/truncated detail.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    kind: str = "unknown"
    subject: str = ""
    detail: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudObservation(TidbEntity):
    """A generic cloud-adjacent observation (normalized, masked values)."""

    origin: str = ""
    kind: str = "unknown"
    name: str = ""
    value: str = ""
    detail: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudEvidence(TidbEntity):
    """One piece of evidence backing cloud intelligence.

    Attributes:
        subject_type: owning record class (``provider``/``account``/``region``/
            ``resource``/``service``/``endpoint``/``environment``/``identity``/
            ``role``/``permission``/``integration``/``saas``/
            ``saas-integration``/``webhook``/``dependency``/``storage``/
            ``compute``/``container``/``kubernetes``/``database``/``message``/
            ``gateway``/``cdn``/``load-balancer``/``ci-cd``/``secret``/
            ``exposure``/``observation``).
        subject_id: owning record id.
        evidence_type: ``dns-cname``/``dns-record``/``http-header``/``tls``/
            ``technology``/``javascript``/``openapi``/``documentation``/
            ``url-pattern``/``metadata``/``tidb-intelligence``/``tool-output``/
            ``known-signature``/``other``.
        value: evidence value (masked/truncated when long).
        source: provenance.
        strength: ``strong``/``moderate``/``weak``.
        tool_id: producing tool.
        detail: detail text.

    """

    subject_type: str = "observation"
    subject_id: str = ""
    evidence_type: str = "other"
    value: str = ""
    source: str = "cloud"
    strength: str = "moderate"
    tool_id: str = ""
    detail: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CloudChange(TidbEntity):
    """A detected temporal change in the cloud attack surface.

    Attributes:
        subject_type: affected record class.
        subject: canonical subject key.
        change_type: ``added``/``removed``/``changed``.
        previous / current: values.
        tool_id: producing tool.
        confidence: change confidence.
        mission_id / correlation_id: provenance.

    """

    subject_type: str = "provider"
    subject: str = ""
    change_type: str = "changed"
    previous: str = ""
    current: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""
