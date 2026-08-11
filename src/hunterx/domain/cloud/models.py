# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS attack-surface intelligence canonical domain models.

Pure data contracts for the Cloud & SaaS Attack-Surface Intelligence capability
(Sprint 017 / Wave 11): cloud providers, accounts/subscriptions/projects/
organizations/tenants, regions, resources, services, endpoints (with plane and
exposure classification), environments, identity & IAM indicators, SaaS
platforms, SaaS applications, SaaS integrations, webhooks, third-party
dependencies, storage/compute/container/Kubernetes/database/message/gateway/CDN/
load-balancer/CI/CD resource indicators, secret-management indicators (never
values), exposure indicators (intelligence, never vulnerabilities), generic
observations, evidence, conflicts, historical changes, execution summaries, the
collection strategy and the batch that carries everything back to the
application layer. No I/O and no execution here.

The TIDB ``cloud_intelligence`` entities
(:mod:`hunterx.domain.entities.tidb.cloud_intelligence`) are the persistence
projection of these models; this module is the runtime surface the cloud
intelligence pipeline is built on.

Security boundary: intelligence & discovery only. Sensitive values are masked or
fingerprinted before they reach these records.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, get_type_hints

from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class CloudProviderKind(StrEnum):
    """Canonical cloud/platform provider families."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ORACLE = "oracle"
    CLOUDFLARE = "cloudflare"
    DIGITALOCEAN = "digitalocean"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    VERCEL = "vercel"
    NETLIFY = "netlify"
    HEROKU = "heroku"
    RENDER = "render"
    FLY_IO = "fly.io"
    SUPABASE = "supabase"
    FIREBASE = "firebase"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    OTHER = "other"
    UNKNOWN = "unknown"


class CloudPlane(StrEnum):
    """Canonical cloud endpoint plane classification."""

    CONTROL = "control"
    DATA = "data"
    IDENTITY = "identity"
    MANAGEMENT = "management"
    DEVELOPER = "developer"
    UNKNOWN = "unknown"


class CloudExposure(StrEnum):
    """Canonical cloud resource/endpoint exposure classification."""

    PUBLIC = "public"
    PUBLIC_INDICATOR = "public-indicator"
    PRIVATE_INDICATOR = "private-indicator"
    INTERNAL_INDICATOR = "internal-indicator"
    UNKNOWN = "unknown"


class EnvironmentKind(StrEnum):
    """Canonical environment classification."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    QA = "qa"
    SANDBOX = "sandbox"
    PREVIEW = "preview"
    DR = "dr"
    UNKNOWN = "unknown"


class ServiceCategory(StrEnum):
    """Canonical cloud service family categories."""

    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORKING = "networking"
    SERVERLESS = "serverless"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    IDENTITY = "identity"
    MONITORING = "monitoring"
    LOGGING = "logging"
    MESSAGING = "messaging"
    CI_CD = "ci-cd"
    SECRET = "secret"
    SECURITY = "security"
    COMMUNICATION = "communication"
    EMAIL = "email"
    PAYMENT = "payment"
    CRM = "crm"
    SUPPORT = "support"
    ANALYTICS = "analytics"
    UNKNOWN = "unknown"


class AccountKind(StrEnum):
    """Canonical cloud account/subscription/project families."""

    ACCOUNT = "account"
    SUBSCRIPTION = "subscription"
    PROJECT = "project"
    ORGANIZATION = "organization"
    TENANT = "tenant"
    WORKSPACE = "workspace"
    RESOURCE_GROUP = "resource-group"
    UNKNOWN = "unknown"


class IdentityKind(StrEnum):
    """Canonical cloud identity indicator families."""

    SERVICE_ACCOUNT = "service-account"
    MANAGED_IDENTITY = "managed-identity"
    USER = "user"
    ROLE = "role"
    GROUP = "group"
    CLIENT = "client"
    OIDC = "oidc"
    COGNITO_POOL = "cognito-pool"
    ENTRA_TENANT = "entra-tenant"
    ASSUME_ROLE = "assume-role"
    FEDERATED = "federated"
    UNKNOWN = "unknown"


class IntegrationType(StrEnum):
    """Canonical SaaS/cloud integration families."""

    OAUTH = "oauth"
    API = "api"
    WEBHOOK = "webhook"
    SDK = "sdk"
    SINGLE_SIGN_ON = "single-sign-on"
    IDENTITY_FEDERATION = "identity-federation"
    ANALYTICS = "analytics"
    PAYMENT = "payment"
    EMAIL = "email"
    MONITORING = "monitoring"
    ERROR_TRACKING = "error-tracking"
    CRM = "crm"
    SUPPORT = "support"
    COMMUNICATION = "communication"
    CLOUD_STORAGE = "cloud-storage"
    CI_CD = "ci-cd"
    UNKNOWN = "unknown"


class ExposureIndicatorKind(StrEnum):
    """Canonical cloud exposure intelligence indicator kinds."""

    PUBLIC_STORAGE = "public-storage"
    PUBLIC_ADMIN_INTERFACE = "public-admin-interface"
    EXPOSED_MANAGEMENT_ENDPOINT = "exposed-management-endpoint"
    MISSING_AUTH_INDICATOR = "missing-auth-indicator"
    DOCUMENTED_RESOURCE = "documented-resource"
    DEBUG_ENDPOINT = "debug-endpoint"
    UNUSUAL_EXPOSURE = "unusual-exposure"
    DANGLING_RESOURCE = "dangling-resource"
    UNKNOWN = "unknown"


class EvidenceStrength(StrEnum):
    """Relative strength of a single cloud intelligence indicator."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class EvidenceType(StrEnum):
    """The kind of source an evidence fragment came from."""

    DNS_CNAME = "dns-cname"
    DNS_RECORD = "dns-record"
    HTTP_HEADER = "http-header"
    TLS = "tls"
    TECHNOLOGY = "technology"
    JAVASCRIPT = "javascript"
    OPENAPI = "openapi"
    DOCUMENTATION = "documentation"
    URL_PATTERN = "url-pattern"
    METADATA = "metadata"
    TIDB_INTELLIGENCE = "tidb-intelligence"
    TOOL_OUTPUT = "tool-output"
    KNOWN_SIGNATURE = "known-signature"
    OTHER = "other"


class ChangeType(StrEnum):
    """Historical change categories for cloud intelligence subjects."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


#: Pipeline payload discriminator for typed cloud findings.
FINDINGS_KEY = "cloud"

ASSET_URL = "url"
ASSET_HOSTNAME = "hostname"
ASSET_DOMAIN = "domain"
ASSET_IP = "ip"


@dataclass(frozen=True, slots=True)
class CloudTarget:
    """A single cloud intelligence target.

    Attributes:
        value: canonical target identifier (a hostname, domain, IP or URL).
        target_type: canonical target kind (``url``, ``hostname``, ``domain``,
            ``ip``).
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "hostname"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class CloudEvidence:
    """One evidence fragment backing a cloud intelligence record.

    Attributes:
        evidence_type: kind of evidence.
        value: evidence value (masked/truncated when long).
        source: upstream source.
        strength: relative indicator strength.
        tool_id: producing tool.
        detail: contextual detail.
        integrity: optional content hash.

    """

    evidence_type: EvidenceType | str = EvidenceType.OTHER
    value: str = ""
    source: str = "cloud"
    strength: EvidenceStrength | str = EvidenceStrength.MODERATE
    tool_id: str = ""
    detail: str = ""
    integrity: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_type", _parse_evidence_type(self.evidence_type))
        object.__setattr__(self, "strength", _parse_evidence_strength(self.strength))
        object.__setattr__(self, "value", str(self.value).strip())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "evidence_type": str(self.evidence_type),
            "value": self.value,
            "source": self.source,
            "strength": str(self.strength),
            "tool_id": self.tool_id,
            "detail": self.detail,
            "integrity": self.integrity,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CloudEvidence:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            evidence_type=_parse_evidence_type(payload.get("evidence_type")),
            value=str(payload.get("value") or ""),
            source=str(payload.get("source") or "cloud"),
            strength=_parse_evidence_strength(payload.get("strength")),
            tool_id=str(payload.get("tool_id") or ""),
            detail=str(payload.get("detail") or ""),
            integrity=str(payload.get("integrity") or ""),
        )


def make_evidence(
    evidence_type: EvidenceType | str,
    value: str,
    *,
    source: str = "cloud",
    strength: EvidenceStrength | str = EvidenceStrength.MODERATE,
    tool_id: str = "",
    detail: str = "",
) -> CloudEvidence:
    """Build an :class:`CloudEvidence` fragment."""
    return CloudEvidence(
        evidence_type=evidence_type,
        value=value,
        source=source,
        strength=strength,
        tool_id=tool_id,
        detail=detail,
    )


# -- observation records ------------------------------------------------------

# The trailing "provenance block" shared by every observation:
#   source, tool_id, target_key, correlation_id, mission_id, execution_id,
#   observed_at, record_id


@dataclass(frozen=True, slots=True)
class CloudProviderObservation:
    """A detected cloud/platform provider.

    Attributes:
        name: canonical provider name.
        display_name: human provider label.
        evidence_indicators: evidence strings that triggered the detection.
        confidence: detection confidence in ``[0, 1]``.
        evidence: evidence fragments.
        provenance: source / tool_id / target_key / correlation_id /
            mission_id / execution_id / observed_at / record_id.

    """

    name: str
    display_name: str = ""
    evidence_indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"provider:{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudServiceObservation:
    """A classified cloud service indicator."""

    provider: str
    service: str
    category: str = "unknown"
    resource: str = ""
    region: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())
        object.__setattr__(self, "service", str(self.service).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"service:{self.provider}|{self.service}|{self.endpoint}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudResourceObservation:
    """A cloud resource indicator (identifier only, never contents)."""

    provider: str
    resource_kind: str = "unknown"
    identifier: str = ""
    service: str = ""
    region: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    public: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"resource:{self.provider}|{self.resource_kind}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudEndpointObservation:
    """A cloud-related endpoint with plane & exposure classification."""

    endpoint: str
    provider: str
    service: str = ""
    plane: str = "unknown"
    exposure: str = "unknown"
    region: str = ""
    environment: str = "unknown"
    domain: str = ""
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())
        object.__setattr__(self, "endpoint", str(self.endpoint).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"endpoint:{self.provider}|{self.endpoint}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudAccountObservation:
    """A cloud account/subscription/project/organization/tenant indicator."""

    provider: str
    kind: str = "account"
    value: str = ""
    name: str = ""
    region: str = ""
    environment: str = "unknown"
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"account:{self.provider}|{self.kind}|{self.value}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudRegionObservation:
    """A cloud region/location indicator."""

    provider: str
    region: str
    resource: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())
        object.__setattr__(self, "region", str(self.region).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"region:{self.provider}|{self.region}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudEnvironmentObservation:
    """An environment classification for a cloud subject."""

    provider: str
    environment: str = "unknown"
    subject: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"environment:{self.provider}|{self.environment}|{self.subject}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudIdentityObservation:
    """A cloud identity / IAM indicator (metadata only, never validated)."""

    provider: str
    identity_kind: str = "unknown"
    name: str = ""
    identifier: str = ""
    account: str = ""
    role: str = ""
    permissions: tuple[str, ...] = ()
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"identity:{self.provider}|{self.identity_kind}|{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudRoleObservation:
    """A cloud IAM role indicator (metadata only)."""

    provider: str
    name: str
    account: str = ""
    assume_role: bool = False
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"role:{self.provider}|{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudPermissionObservation:
    """A cloud permission indicator (from documented/observed material only)."""

    provider: str
    name: str = ""
    action: str = ""
    resource: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"permission:{self.provider}|{self.action}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudIntegrationObservation:
    """A cloud/SaaS integration indicator."""

    provider: str
    integration_type: str = "unknown"
    name: str = ""
    endpoint: str = ""
    scope: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"integration:{self.provider}|{self.integration_type}|{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class SaaSProviderObservation:
    """A detected SaaS platform (evidence-based)."""

    name: str
    display_name: str = ""
    provider_kind: str = "saas"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"saas:{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class SaaSApplicationObservation:
    """A SaaS application reference observed on the target."""

    name: str
    saas_provider: str = ""
    url: str = ""
    environment: str = "unknown"
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"saas-app:{self.saas_provider}|{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class SaaSIntegrationObservation:
    """A SaaS integration (OAuth/API/webhook) indicator."""

    saas_provider: str
    integration_type: str = "unknown"
    name: str = ""
    endpoint: str = ""
    auth_mechanism: str = "unknown"
    scope: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "saas_provider", str(self.saas_provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"saas-int:{self.saas_provider}|{self.integration_type}|{self.name}|{self.endpoint}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class WebhookObservation:
    """A webhook indicator (inbound/outbound endpoint, never signatures)."""

    direction: str = "unknown"
    provider: str = ""
    endpoint: str = ""
    event_type: str = ""
    signing: str = "unknown"
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"webhook:{self.provider}|{self.endpoint}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudDependencyObservation:
    """A third-party/cloud dependency relationship."""

    name: str
    provider: str = ""
    kind: str = "unknown"
    endpoint: str = ""
    application: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"dependency:{self.name}|{self.provider}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class StorageResourceObservation:
    """A cloud storage resource indicator (never contents)."""

    provider: str
    storage_kind: str = "object"
    identifier: str = ""
    endpoint: str = ""
    public: str = "unknown"
    region: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"storage:{self.provider}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class ComputeResourceObservation:
    """A cloud compute/serverless resource indicator (metadata only)."""

    provider: str
    compute_kind: str = "instance"
    identifier: str = ""
    endpoint: str = ""
    region: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"compute:{self.provider}|{self.compute_kind}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class ContainerResourceObservation:
    """A container/registry resource indicator."""

    provider: str
    container_kind: str = "registry"
    identifier: str = ""
    registry: str = ""
    image: str = ""
    region: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"container:{self.provider}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class KubernetesResourceObservation:
    """A Kubernetes resource indicator (never a control-plane interaction)."""

    provider: str
    cluster: str = ""
    kind: str = "unknown"
    name: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"k8s:{self.provider}|{self.kind}|{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class DatabaseResourceObservation:
    """A managed database resource indicator (never connected)."""

    provider: str
    database_kind: str = "managed"
    identifier: str = ""
    endpoint: str = ""
    technology: str = ""
    region: str = ""
    public: str = "unknown"
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"database:{self.provider}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class MessageInfrastructureObservation:
    """A message/event infrastructure indicator (never published to)."""

    provider: str
    kind: str = "queue"
    identifier: str = ""
    service: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"message:{self.provider}|{self.kind}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class ApiGatewayResourceObservation:
    """An API gateway / edge resource indicator."""

    provider: str
    gateway_kind: str = "gateway"
    identifier: str = ""
    endpoint: str = ""
    backend: str = ""
    region: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"gateway:{self.provider}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CdnResourceObservation:
    """A CDN resource indicator."""

    provider: str
    identifier: str = ""
    endpoint: str = ""
    origin: str = ""
    region: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"cdn:{self.provider}|{self.identifier}"


@dataclass(frozen=True, slots=True)
class LoadBalancerResourceObservation:
    """A load-balancer resource indicator."""

    provider: str
    identifier: str = ""
    endpoint: str = ""
    backend: str = ""
    region: str = ""
    environment: str = "unknown"
    confidence: float = 0.4
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"lb:{self.provider}|{self.identifier}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CiCdResourceObservation:
    """A CI/CD infrastructure indicator (never credentials)."""

    provider: str
    kind: str = "pipeline"
    name: str = ""
    repository: str = ""
    endpoint: str = ""
    environment: str = "unknown"
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"cicd:{self.provider}|{self.kind}|{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class SecretManagementObservation:
    """A secret-management indicator (references/fingerprints only)."""

    provider: str
    kind: str = "secrets-manager"
    name: str = ""
    reference: str = ""
    fingerprint: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", str(self.provider).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"secret:{self.provider}|{self.kind}|{self.name}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudExposureObservation:
    """A cloud exposure intelligence indicator (never a vulnerability)."""

    kind: str = "unknown"
    subject: str = ""
    detail: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"exposure:{self.kind}|{self.subject}"

    @property
    def origin(self) -> str:
        """Return the provenance origin used for scope checks."""
        return self.target_key


@dataclass(frozen=True, slots=True)
class CloudObservation:
    """A generic cloud-adjacent observation (normalized, masked values)."""

    origin: str
    kind: str = "unknown"
    name: str = ""
    value: str = ""
    detail: str = ""
    confidence: float = 0.3
    indicators: tuple[str, ...] = ()
    evidence: tuple[CloudEvidence, ...] = ()
    source: str = "cloud"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"observation:{self.origin}|{self.kind}|{self.name}"


# -- aggregation records ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CloudConflict:
    """A disagreement between sources about one cloud subject."""

    subject: str
    subject_type: str = "provider"
    conflict_type: str = "identity"
    observations: tuple[dict[str, Any], ...] = ()
    selected: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    detected_at: str = field(default_factory=utcnow_iso)

    def key(self) -> str:
        """Return the canonical key of this conflict."""
        return f"cloud:{self.subject_type}|{self.subject}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "subject": self.subject,
            "subject_type": self.subject_type,
            "conflict_type": self.conflict_type,
            "observations": [dict(item) for item in self.observations],
            "selected": self.selected,
            "selected_source": self.selected_source,
            "reason": self.reason,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
        }


@dataclass(frozen=True, slots=True)
class CloudChange:
    """A detected difference between historical and current cloud state."""

    subject_type: str
    subject: str
    change_type: str
    previous: str = ""
    current: str = ""
    detected_at: str = field(default_factory=utcnow_iso)
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        """Return the canonical key of the changed subject."""
        return f"cloud:{self.subject_type}|{self.subject}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "subject_type": self.subject_type,
            "subject": self.subject,
            "change_type": self.change_type,
            "previous": self.previous,
            "current": self.current,
            "detected_at": self.detected_at,
            "source": self.source,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class CloudExecutionSummary:
    """Outcome of running one cloud intelligence tool through the engine."""

    tool_id: str
    status: str
    observations: int = 0
    resources: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class CloudBatch:
    """The result of one cloud intelligence run.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target analysed.
        mode: the execution posture used.
        raw: raw observations collected from every source.
        records: correlated canonical records.
        conflicts: conflicting observations recorded.
        changes: historical changes detected.
        executions: per-tool execution summaries.
        created_at / batch_id: run metadata.

    """

    mission_id: str
    correlation_id: str
    target: CloudTarget
    mode: ReconMode = ReconMode.HYBRID
    raw: list[Any] = field(default_factory=list)
    records: list[Any] = field(default_factory=list)
    conflicts: list[CloudConflict] = field(default_factory=list)
    changes: list[CloudChange] = field(default_factory=list)
    executions: list[CloudExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_observation(self, observation: Any) -> None:
        """Append a raw observation to the batch."""
        self.raw.append(observation)

    def add_record(self, record: Any) -> None:
        """Append a correlated canonical record."""
        self.records.append(record)

    def add_conflict(self, conflict: CloudConflict) -> None:
        """Append a conflict."""
        self.conflicts.append(conflict)

    def add_change(self, change: CloudChange) -> None:
        """Append a historical change."""
        self.changes.append(change)

    def add_execution(self, summary: CloudExecutionSummary) -> None:
        """Append an execution summary."""
        self.executions.append(summary)

    def provider_count(self) -> int:
        """Return the number of correlated cloud providers."""
        return sum(1 for record in self.records if isinstance(record, CloudProviderObservation))

    def resource_count(self) -> int:
        """Return the number of correlated cloud resources."""
        return sum(1 for record in self.records if isinstance(record, CloudResourceObservation))

    def service_count(self) -> int:
        """Return the number of correlated cloud services."""
        return sum(1 for record in self.records if isinstance(record, CloudServiceObservation))

    def endpoint_count(self) -> int:
        """Return the number of correlated cloud endpoints."""
        return sum(1 for record in self.records if isinstance(record, CloudEndpointObservation))

    def record_count(self) -> int:
        """Return the number of correlated canonical records."""
        return len(self.records)

    def total_observations(self) -> int:
        """Return the number of raw observations collected."""
        return len(self.raw)

    def change_count(self) -> int:
        """Return the number of recorded changes."""
        return len(self.changes)

    def conflict_count(self) -> int:
        """Return the number of recorded conflicts."""
        return len(self.conflicts)


# -- analyzer input / output --------------------------------------------------


@dataclass(frozen=True, slots=True)
class CloudInput:
    """The static, already-acquired material a cloud analysis consumes.

    Security boundary: the bundle never contains cloud credentials, access keys
    or secret values. It carries observable indicators (hostnames, headers,
    TLS metadata, technology names, script content, documentation text and
    previously persisted TIDB hints) only.

    Attributes:
        target: canonical target value.
        domain: owning domain when known.
        records: DNS records (``name``/``type``/``value``/``cname_target``).
        certificates: TLS certificate metadata (``subject_org``/``issuer_org``/
            ``san``/``wildcard``).
        headers: HTTP response headers as ``(name, value)`` pairs.
        html: response body text (truncated at the analyzer layer).
        scripts: ``(url, content)`` script asset pairs.
        api_schemes: OpenAPI/API security + server hints.
        documents: infrastructure documentation fragments.
        technologies: technology observations (``name``/``category``/``version``).
        observed_urls: URLs observed on the target.
        tidb_hints: previously persisted cloud intelligence hints.
        source / tool_id: provenance.

    """

    target: str
    domain: str = ""
    records: tuple[dict[str, Any], ...] = ()
    certificates: tuple[dict[str, Any], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    html: str = ""
    scripts: tuple[tuple[str, str], ...] = ()
    api_schemes: tuple[dict[str, Any], ...] = ()
    documents: tuple[dict[str, Any], ...] = ()
    technologies: tuple[dict[str, Any], ...] = ()
    observed_urls: tuple[str, ...] = ()
    tidb_hints: tuple[dict[str, Any], ...] = ()
    source: str = "cloud"
    tool_id: str = ""


@dataclass(slots=True)
class CloudAnalysis:
    """The aggregate result of one cloud analysis pass.

    Holds the ordered typed collections produced by the analyzer; observers
    consume them through ``all_observations()``.
    """

    providers: list[CloudProviderObservation] = field(default_factory=list)
    services: list[CloudServiceObservation] = field(default_factory=list)
    resources: list[CloudResourceObservation] = field(default_factory=list)
    endpoints: list[CloudEndpointObservation] = field(default_factory=list)
    accounts: list[CloudAccountObservation] = field(default_factory=list)
    regions: list[CloudRegionObservation] = field(default_factory=list)
    environments: list[CloudEnvironmentObservation] = field(default_factory=list)
    identities: list[CloudIdentityObservation] = field(default_factory=list)
    roles: list[CloudRoleObservation] = field(default_factory=list)
    permissions: list[CloudPermissionObservation] = field(default_factory=list)
    integrations: list[CloudIntegrationObservation] = field(default_factory=list)
    saas_providers: list[SaaSProviderObservation] = field(default_factory=list)
    saas_applications: list[SaaSApplicationObservation] = field(default_factory=list)
    saas_integrations: list[SaaSIntegrationObservation] = field(default_factory=list)
    webhooks: list[WebhookObservation] = field(default_factory=list)
    dependencies: list[CloudDependencyObservation] = field(default_factory=list)
    storage: list[StorageResourceObservation] = field(default_factory=list)
    compute: list[ComputeResourceObservation] = field(default_factory=list)
    containers: list[ContainerResourceObservation] = field(default_factory=list)
    kubernetes: list[KubernetesResourceObservation] = field(default_factory=list)
    databases: list[DatabaseResourceObservation] = field(default_factory=list)
    message_infrastructure: list[MessageInfrastructureObservation] = field(default_factory=list)
    gateways: list[ApiGatewayResourceObservation] = field(default_factory=list)
    cdns: list[CdnResourceObservation] = field(default_factory=list)
    load_balancers: list[LoadBalancerResourceObservation] = field(default_factory=list)
    cicd: list[CiCdResourceObservation] = field(default_factory=list)
    secrets: list[SecretManagementObservation] = field(default_factory=list)
    exposures: list[CloudExposureObservation] = field(default_factory=list)
    observations: list[CloudObservation] = field(default_factory=list)

    def all_observations(self) -> list[Any]:
        """Return every observation in stable detector order."""
        return [
            *self.providers,
            *self.services,
            *self.resources,
            *self.endpoints,
            *self.accounts,
            *self.regions,
            *self.environments,
            *self.identities,
            *self.roles,
            *self.permissions,
            *self.integrations,
            *self.saas_providers,
            *self.saas_applications,
            *self.saas_integrations,
            *self.webhooks,
            *self.dependencies,
            *self.storage,
            *self.compute,
            *self.containers,
            *self.kubernetes,
            *self.databases,
            *self.message_infrastructure,
            *self.gateways,
            *self.cdns,
            *self.load_balancers,
            *self.cicd,
            *self.secrets,
            *self.exposures,
            *self.observations,
        ]


# -- serialization bridge ------------------------------------------------------


_BUILDERS: dict[str, type[Any]] = {
    "cloud-provider": CloudProviderObservation,
    "cloud-service": CloudServiceObservation,
    "cloud-resource": CloudResourceObservation,
    "cloud-endpoint": CloudEndpointObservation,
    "cloud-account": CloudAccountObservation,
    "cloud-region": CloudRegionObservation,
    "cloud-environment": CloudEnvironmentObservation,
    "cloud-identity": CloudIdentityObservation,
    "cloud-role": CloudRoleObservation,
    "cloud-permission": CloudPermissionObservation,
    "cloud-integration": CloudIntegrationObservation,
    "saas-provider": SaaSProviderObservation,
    "saas-application": SaaSApplicationObservation,
    "saas-integration": SaaSIntegrationObservation,
    "webhook": WebhookObservation,
    "cloud-dependency": CloudDependencyObservation,
    "storage-resource": StorageResourceObservation,
    "compute-resource": ComputeResourceObservation,
    "container-resource": ContainerResourceObservation,
    "kubernetes-resource": KubernetesResourceObservation,
    "database-resource": DatabaseResourceObservation,
    "message-infrastructure": MessageInfrastructureObservation,
    "api-gateway-resource": ApiGatewayResourceObservation,
    "cdn-resource": CdnResourceObservation,
    "load-balancer-resource": LoadBalancerResourceObservation,
    "ci-cd-resource": CiCdResourceObservation,
    "secret-management": SecretManagementObservation,
    "cloud-exposure": CloudExposureObservation,
    "cloud-observation": CloudObservation,
}

_TYPE_BY_BUILDER: dict[type[Any], str] = {cls: key for key, cls in _BUILDERS.items()}


def record_type_of(record: Any) -> str:
    """Return the type discriminator of a cloud observation (``"unknown"`` when unrecognized)."""
    return _TYPE_BY_BUILDER.get(type(record), "unknown")


def record_to_dict(record: Any) -> dict[str, Any]:
    """Serialize a canonical observation to a JSON-safe dictionary."""
    payload = dataclasses.asdict(record)
    payload["type"] = record_type_of(record)
    return payload


def record_from_dict(cls: type[Any], payload: Mapping[str, Any]) -> Any:
    """Rebuild a canonical observation from a serialized dictionary."""
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for name, value in dict(payload).items():
        if name == "type" or name not in hints:
            continue
        kwargs[name] = _coerce_value(hints[name], value)
    return cls(**kwargs)


def observations_from_payload(payload: Mapping[str, Any] | None) -> list[Any]:
    """Extract canonical observations from a pipeline JSON payload.

    Cloud adapters serialise their findings under the ``cloud`` key of the JSON
    payload they attach to the execution output. Each entry carries a ``type``
    discriminator; this helper rebuilds the typed records so downstream
    services never touch raw dictionaries.
    """
    if not payload:
        return []
    entries = payload.get(FINDINGS_KEY)
    if not isinstance(entries, list):
        return []
    observations: list[Any] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        builder = _BUILDERS.get(entry.get("type", ""))
        if builder is None:
            continue
        observations.append(record_from_dict(builder, entry))
    return observations


def _coerce_value(hint: Any, value: Any) -> Any:
    """Coerce a raw payload value into the declared type hint."""
    if value is None:
        return value
    origin = getattr(hint, "__origin__", None)
    if origin in (tuple, list):
        args = getattr(hint, "__args__", ())
        element = args[0] if args else Any
        converted = [_coerce_value(element, item) for item in value]
        return tuple(converted) if origin is tuple else converted
    if origin is dict:
        return dict(value)
    if isinstance(hint, type) and issubclass(hint, StrEnum):
        return _coerce_enum(hint, value)
    if isinstance(hint, type) and issubclass(hint, CloudEvidence):
        return CloudEvidence.from_dict(value)
    if isinstance(value, dict):
        try:
            return hint(**value)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return value
    return value


def _coerce_enum(enum_cls: type[Any], value: Any) -> Any:
    """Coerce a value into a StrEnum member with a safe fallback."""
    try:
        return enum_cls(str(value))
    except ValueError:
        return value


# -- classification helpers ----------------------------------------------------


def infer_asset_type(value: str) -> str:
    """Infer the canonical asset kind of ``value``."""
    import ipaddress

    candidate = str(value).strip()
    if "://" in candidate:
        return ASSET_URL
    if candidate.endswith("/"):
        candidate = candidate.rstrip("/")
    try:
        ipaddress.ip_address(candidate)
        return ASSET_IP
    except ValueError:
        pass
    if "." in candidate:
        return ASSET_DOMAIN
    return ASSET_HOSTNAME


def origin_of(url: str) -> str:
    """Return the canonical origin for a URL (``scheme://host[:port]``)."""
    from urllib.parse import urlsplit

    candidate = str(url).strip()
    try:
        parts = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    except ValueError:  # pragma: no cover - defensive
        return ""
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    scheme = (parts.scheme or "https").lower()
    port = parts.port
    if port is not None and port not in _DEFAULT_PORTS.get(scheme, ()):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


_DEFAULT_PORTS: dict[str, tuple[int, ...]] = {"https": (443,), "http": (80,)}


# -- parsing helpers -----------------------------------------------------------


def _parse_evidence_type(value: object) -> EvidenceType:
    if isinstance(value, EvidenceType):
        return value
    try:
        return EvidenceType(str(value).lower())
    except ValueError:
        return EvidenceType.OTHER


def _parse_evidence_strength(value: object) -> EvidenceStrength:
    if isinstance(value, EvidenceStrength):
        return value
    try:
        return EvidenceStrength(str(value).lower())
    except ValueError:
        return EvidenceStrength.MODERATE
