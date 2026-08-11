# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization & access-control intelligence canonical domain models.

Pure data contracts for the Wave 10 authorization intelligence capability
(Sprint 016): authorization subjects, roles, groups, permissions, scopes,
claims, policies, resources, actions, ownership relationships, tenant
boundaries, administrative surfaces, function/object/field-level access-control
indicators, frontend/backend authorization logic, API authorization
correlation, GraphQL/WebSocket/service authorization, decision indicators,
mass-assignment fields, resource-identifier metadata, generic observations,
evidence, conflicts, historical changes, execution summaries, the collection
strategy and the batch that carries everything back to the application layer.
No I/O and no execution here.

Security boundary: intelligence only. The models carry metadata and
masked/derived values only — never raw passwords, access/refresh tokens,
session-cookie values, API secrets, authorization-header values, JWT claims or
PII. No field ever holds a value that would enable authorization exploitation.

The TIDB ``authorization_intelligence`` entities
(:mod:`hunterx.domain.entities.tidb.authorization_intelligence`) are the
persistence projection of these models; this module is the runtime surface the
authorization intelligence pipeline is built on.
"""

from __future__ import annotations

import dataclasses
import types
import typing
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from enum import Enum, StrEnum
from typing import Any, get_args, get_origin

from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class SubjectKind(StrEnum):
    """Canonical kinds of an authorization subject.

    Subjects are evidence-backed only: HunterX never fabricates an identity.
    """

    USER = "user"
    ROLE = "role"
    GROUP = "group"
    SERVICE_ACCOUNT = "service-account"
    API_CLIENT = "api-client"
    APPLICATION = "application"
    TENANT = "tenant"
    ORGANIZATION = "organization"
    WORKSPACE = "workspace"
    PROJECT = "project"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"
    UNKNOWN = "unknown"


class ResourceKind(StrEnum):
    """Canonical kinds of an authorization resource."""

    USER = "user"
    ACCOUNT = "account"
    ORGANIZATION = "organization"
    TENANT = "tenant"
    WORKSPACE = "workspace"
    PROJECT = "project"
    REPOSITORY = "repository"
    DOCUMENT = "document"
    FILE = "file"
    REPORT = "report"
    FINDING = "finding"
    ASSET = "asset"
    API_KEY = "api-key"
    TOKEN = "token"
    INTEGRATION = "integration"
    WEBHOOK = "webhook"
    DEPLOYMENT = "deployment"
    CONFIGURATION = "configuration"
    BILLING_OBJECT = "billing-object"
    SECURITY_POLICY = "security-policy"
    ROLE = "role"
    PERMISSION = "permission"
    OTHER = "other"
    UNKNOWN = "unknown"


class ActionKind(StrEnum):
    """Canonical normalized authorization actions (original names preserved)."""

    READ = "read"
    LIST = "list"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    PUBLISH = "publish"
    MANAGE = "manage"
    CONFIGURE = "configure"
    INVITE = "invite"
    ASSIGN = "assign"
    REVOKE = "revoke"
    EXPORT = "export"
    IMPORT = "import"
    ROTATE = "rotate"
    DEPLOY = "deploy"
    ADMINISTER = "administer"
    DISABLE = "disable"
    ENABLE = "enable"
    OTHER = "other"
    UNKNOWN = "unknown"


class IdentifierKind(StrEnum):
    """Canonical resource-identifier families."""

    NUMERIC = "numeric"
    UUID = "uuid"
    ULID = "ulid"
    SLUG = "slug"
    HASH = "hash"
    COMPOSITE = "composite"
    OPAQUE = "opaque"
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    GRAPHQL = "graphql"
    ENCODED = "encoded"
    UNKNOWN = "unknown"


class PolicyModelKind(StrEnum):
    """Canonical authorization policy models."""

    RBAC = "rbac"
    ABAC = "abac"
    ACL = "acl"
    PBAC = "pbac"
    REBAC = "rebac"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class OwnershipKind(StrEnum):
    """Canonical ownership indicator families."""

    OWNER_ID = "owner-id"
    USER_ID = "user-id"
    ACCOUNT_ID = "account-id"
    TENANT_ID = "tenant-id"
    ORGANIZATION_ID = "organization-id"
    CREATED_BY = "created-by"
    UPDATED_BY = "updated-by"
    AUTHOR = "author"
    CREATOR = "creator"
    PRINCIPAL = "principal"
    SUBJECT = "subject"
    OWNER = "owner"
    MEMBER = "member"
    MANAGER = "manager"
    ADMINISTRATOR = "administrator"
    UNKNOWN = "unknown"


class TenantKind(StrEnum):
    """Canonical tenant-boundary indicator families."""

    ID = "id"
    HEADER = "header"
    CLAIM = "claim"
    PATH = "path"
    QUERY = "query"
    SUBDOMAIN = "subdomain"
    UNKNOWN = "unknown"


class AdminSurfaceKind(StrEnum):
    """Canonical administrative surface families."""

    ADMIN_LOGIN = "admin-login"
    ADMIN_API = "admin-api"
    ADMIN_ROUTE = "admin-route"
    ADMIN_UI = "admin-ui"
    MANAGEMENT_API = "management-api"
    ROLE_MANAGEMENT = "role-management"
    PERMISSION_MANAGEMENT = "permission-management"
    USER_MANAGEMENT = "user-management"
    CONFIGURATION_MANAGEMENT = "configuration-management"
    SECURITY_CONTROLS = "security-controls"
    AUDIT_ACCESS = "audit-access"
    INTEGRATION_MANAGEMENT = "integration-management"
    CREDENTIAL_MANAGEMENT = "credential-management"
    API_MANAGEMENT = "api-management"
    TOKEN_MANAGEMENT = "token-management"
    BILLING_MANAGEMENT = "billing-management"
    UNKNOWN = "unknown"


class AccessLevel(StrEnum):
    """Canonical access-control level indicators."""

    FUNCTION = "function"
    OBJECT = "object"
    FIELD = "field"
    UNKNOWN = "unknown"


class EnforcementScope(StrEnum):
    """Where authorization enforcement is observed."""

    FRONTEND_ONLY = "frontend-only"
    BACKEND = "backend"
    BOTH = "both"
    UNKNOWN = "unknown"


class DecisionKind(StrEnum):
    """Observed/documented authorization decision indicators."""

    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"


class AuthzObservationKind(StrEnum):
    """Kinds of generic authorization-adjacent observations."""

    HEADER = "header"
    STATUS = "status"
    POLICY = "policy"
    ROUTE_GUARD = "route-guard"
    FEATURE_FLAG = "feature-flag"
    ROLE_CHECK = "role-check"
    PERMISSION_CHECK = "permission-check"
    SCOPE_CHECK = "scope-check"
    CLAIM = "claim"
    OWNERSHIP = "ownership"
    TENANT = "tenant"
    ADMIN_SURFACE = "admin-surface"
    PRIVILEGED_FUNCTION = "privileged-function"
    OBJECT_LEVEL = "object-level"
    FIELD_LEVEL = "field-level"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    SERVICE = "service"
    MASS_ASSIGNMENT = "mass-assignment"
    UNKNOWN = "unknown"


class EvidenceStrength(StrEnum):
    """Relative strength of a single authorization indicator."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class AuthzEvidenceType(StrEnum):
    """The kind of source an authorization evidence fragment came from."""

    HTTP_HEADER = "http-header"
    HTTP_STATUS = "http-status"
    HTML = "html"
    URL_PATTERN = "url-pattern"
    JAVASCRIPT = "javascript"
    OPENAPI_SECURITY = "openapi-security"
    API_OPERATION = "api-operation"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    POLICY_CONFIG = "policy-config"
    JS_INDICATOR = "js-indicator"
    DOCUMENTATION = "documentation"
    RESPONSE = "response"
    TIDB_INTELLIGENCE = "tidb-intelligence"
    TOOL_OUTPUT = "tool-output"
    KNOWN_SIGNATURE = "known-signature"
    OTHER = "other"


class ChangeType(StrEnum):
    """Historical change categories for authorization intelligence subjects."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


#: Pipeline payload discriminator key for typed authorization findings.
FINDINGS_KEY = "authorization"

#: Canonical asset kinds an authorization observation can be attached to.
ASSET_URL = "url"
ASSET_HOSTNAME = "hostname"
ASSET_DOMAIN = "domain"
ASSET_IP = "ip"


# ---------------------------------------------------------------------------
# generic serialization helpers
# ---------------------------------------------------------------------------


def record_to_dict(instance: object) -> dict[str, Any]:
    """Serialize any authorization record into a JSON-safe dictionary.

    Nested dataclasses are rendered recursively, every :class:`Enum` is reduced
    to its value, and the record's ``type`` discriminator is included so
    :func:`observations_from_payload` can rebuild the typed record.
    """
    payload: dict[str, Any] = _encode(dataclasses.asdict(instance))  # type: ignore[call-overload]  # instance is always a dataclass
    payload["type"] = _record_type(instance)
    return payload


def record_from_dict(cls: type, payload: Mapping[str, Any]) -> Any:
    """Rebuild an authorization record from a :func:`record_to_dict` payload."""
    kwargs: dict[str, Any] = {}
    for name, field_type in _type_hints(cls).items():
        if name not in payload:
            continue
        kwargs[name] = _decode(field_type, payload[name])
    return cls(**kwargs)


_TYPE_HINTS_CACHE: dict[type, dict[str, Any]] = {}


def _type_hints(cls: type) -> dict[str, Any]:
    """Return the resolved field type hints for ``cls`` (cached)."""
    cached = _TYPE_HINTS_CACHE.get(cls)
    if cached is not None:
        return cached
    try:
        hints = typing.get_type_hints(cls)
    except Exception:  # pragma: no cover - defensive fallback
        hints = {field.name: field.type for field in dataclasses.fields(cls)}
    _TYPE_HINTS_CACHE[cls] = hints
    return hints


def _encode(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_encode(item) for item in value]
    if isinstance(value, list):
        return [_encode(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _encode(item) for key, item in value.items()}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _encode(dataclasses.asdict(value))
    return value


def _decode(typ: Any, value: Any) -> Any:
    if value is None:
        return None
    origin = get_origin(typ)
    if origin in (tuple, list):
        args = get_args(typ)
        item_type = args[0] if args else object
        items = [_decode(item_type, item) for item in value]
        return tuple(items) if origin is tuple else items
    if origin in (types.UnionType, getattr(__import__("typing"), "Union", types.UnionType)):
        for arg in get_args(typ):
            if arg is type(None):
                continue
            try:
                return _decode(arg, value)
            except (TypeError, ValueError):
                continue
        return value
    if isinstance(typ, type):
        if issubclass(typ, Enum):
            return typ(value)
        if dataclasses.is_dataclass(typ) and hasattr(typ, "from_dict"):
            return typ.from_dict(value)
    return value


# ---------------------------------------------------------------------------
# target + evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorizationTarget:
    """A single authorization intelligence target.

    Attributes:
        value: canonical target identifier (a hostname, domain, IP or URL).
        target_type: canonical target kind (``url``/``hostname``/``domain``/
            ``ip``).
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "hostname"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class AuthzEvidence:
    """One evidence fragment backing an authorization intelligence record.

    Attributes:
        evidence_type: kind of evidence.
        value: evidence value (masked/truncated when long).
        source: upstream source.
        strength: relative indicator strength.
        tool_id: producing tool.
        detail: contextual detail.
        integrity: optional content hash.

    """

    evidence_type: AuthzEvidenceType | str = AuthzEvidenceType.OTHER
    value: str = ""
    source: str = "authorization"
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
    def from_dict(cls, payload: Mapping[str, Any]) -> AuthzEvidence:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            evidence_type=_parse_evidence_type(payload.get("evidence_type")),
            value=str(payload.get("value") or ""),
            source=str(payload.get("source") or "authorization"),
            strength=_parse_evidence_strength(payload.get("strength")),
            tool_id=str(payload.get("tool_id") or ""),
            detail=str(payload.get("detail") or ""),
            integrity=str(payload.get("integrity") or ""),
        )


def make_evidence(
    evidence_type: AuthzEvidenceType | str,
    value: str,
    *,
    source: str = "authorization",
    strength: EvidenceStrength | str = EvidenceStrength.MODERATE,
    tool_id: str = "",
    detail: str = "",
) -> AuthzEvidence:
    """Build an :class:`AuthzEvidence` fragment with the given type and value."""
    return AuthzEvidence(
        evidence_type=evidence_type,
        value=value,
        source=source,
        strength=strength,
        tool_id=tool_id,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthzSubjectObservation:
    """An evidence-backed authorization subject.

    Attributes:
        origin: canonical ``scheme://host[:port]``.
        name: canonical subject identifier.
        subject_kind: :class:`SubjectKind` value.
        context: surrounding context (masked/truncated).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        execution_id / observed_at / record_id.

    """

    origin: str
    name: str
    subject_kind: SubjectKind | str = SubjectKind.UNKNOWN
    context: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject_kind", _parse_subject_kind(self.subject_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"subject:{self.origin}|{str(self.subject_kind)}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzRoleObservation:
    """An evidence-backed role identifier (never inferred semantically)."""

    origin: str
    name: str
    context: str = ""
    default: bool = False
    custom: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"role:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzGroupObservation:
    """An evidence-backed authorization group."""

    origin: str
    name: str
    context: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"group:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzPermissionObservation:
    """An evidence-backed permission identifier.

    Attributes:
        origin: canonical origin.
        name: permission name (e.g. ``users.read``).
        action: normalized action when derivable.
        resource: normalized resource when derivable.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str
    action: str = ""
    resource: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"permission:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzScopeObservation:
    """An evidence-backed OAuth/OIDC/API scope identifier."""

    origin: str
    name: str
    description: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"scope:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzClaimObservation:
    """An evidence-backed authorization claim reference (never the value)."""

    origin: str
    name: str
    value: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"claim:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzPolicyObservation:
    """An evidence-backed authorization policy model/mechanism.

    Attributes:
        origin: canonical origin.
        name: policy name/identifier when observed.
        model_kind: :class:`PolicyModelKind` value.
        mechanism: observed mechanism (middleware, decorator, guard, engine).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str = ""
    model_kind: PolicyModelKind | str = PolicyModelKind.UNKNOWN
    mechanism: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "model_kind", _parse_policy_model_kind(self.model_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"policy:{self.origin}|{str(self.model_kind)}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzResourceObservation:
    """An evidence-backed authorization resource.

    Attributes:
        origin: canonical origin.
        name: resource name (e.g. ``users``).
        resource_kind: :class:`ResourceKind` value.
        identifier: observed resource identifier (metadata only).
        parent: parent resource name when observed.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str
    resource_kind: ResourceKind | str = ResourceKind.UNKNOWN
    identifier: str = ""
    parent: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "resource_kind", _parse_resource_kind(self.resource_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"resource:{self.origin}|{str(self.resource_kind)}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzActionObservation:
    """An evidence-backed authorization action.

    Attributes:
        origin: canonical origin.
        name: canonical normalized action name.
        original: original terminology preserved from the evidence.
        resource: associated resource when derivable.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str
    original: str = ""
    resource: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"action:{self.origin}|{self.name}|{self.resource}"


@dataclass(frozen=True, slots=True)
class AuthzResourceIdentifierObservation:
    """Resource-identifier metadata observed on an endpoint.

    Attributes:
        origin: canonical origin.
        identifier: the identifier value/pattern (metadata only).
        identifier_kind: :class:`IdentifierKind` value.
        location: ``path``/``query``/``body``/``header``/``graphql``.
        endpoint: endpoint where the identifier was observed.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    identifier: str
    identifier_kind: IdentifierKind | str = IdentifierKind.UNKNOWN
    location: str = ""
    endpoint: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "identifier_kind", _parse_identifier_kind(self.identifier_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"identifier:{self.origin}|{str(self.identifier_kind)}|{self.location}|{self.endpoint}"


@dataclass(frozen=True, slots=True)
class AuthzOwnershipObservation:
    """An evidence-backed ownership indicator.

    Attributes:
        origin: canonical origin.
        name: ownership field/claim name (e.g. ``owner_id``).
        ownership_kind: :class:`OwnershipKind` value.
        resource: resource the indicator applies to.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str
    ownership_kind: OwnershipKind | str = OwnershipKind.UNKNOWN
    resource: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ownership_kind", _parse_ownership_kind(self.ownership_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"ownership:{self.origin}|{str(self.ownership_kind)}|{self.name}|{self.resource}"


@dataclass(frozen=True, slots=True)
class AuthzTenantObservation:
    """An evidence-backed tenant boundary indicator.

    Attributes:
        origin: canonical origin.
        name: tenant/organization/workspace/account identifier observed.
        tenant_kind: :class:`TenantKind` value.
        location: where the indicator was observed (header name, claim, path).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str
    tenant_kind: TenantKind | str = TenantKind.UNKNOWN
    location: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_kind", _parse_tenant_kind(self.tenant_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"tenant:{self.origin}|{str(self.tenant_kind)}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthzAdminSurfaceObservation:
    """A discovered administrative surface.

    Attributes:
        url: canonical URL of the admin surface.
        origin: canonical origin.
        surface_kind: :class:`AdminSurfaceKind` value.
        method: HTTP method when API-scoped.
        api_id: owning API host when API-scoped.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    url: str
    origin: str
    surface_kind: AdminSurfaceKind | str = AdminSurfaceKind.UNKNOWN
    method: str = "GET"
    api_id: str | None = None
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "surface_kind", _parse_admin_surface_kind(self.surface_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"admin-surface:{self.origin}|{self.method}|{self.url}|{str(self.surface_kind)}"


@dataclass(frozen=True, slots=True)
class AuthzFunctionLevelObservation:
    """A function-level access-control indicator (privileged function).

    Attributes:
        origin: canonical origin.
        function: function label.
        endpoint: endpoint URL.
        method: HTTP method.
        required_role: observed role/scope requirement (metadata only).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    function: str
    endpoint: str = ""
    method: str = "GET"
    required_role: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"function-level:{self.origin}|{self.method}|{self.endpoint}|{self.function}"


@dataclass(frozen=True, slots=True)
class AuthzObjectLevelObservation:
    """An object-level access-control indicator (endpoint on a specific object).

    Attributes:
        origin: canonical origin.
        resource: resource type (e.g. ``users``).
        identifier: object identifier (metadata only).
        action: associated action when derivable.
        endpoint: endpoint URL.
        method: HTTP method.
        parent_resource: parent resource when observed.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    resource: str
    identifier: str = ""
    action: str = ""
    endpoint: str = ""
    method: str = "GET"
    parent_resource: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"object-level:{self.origin}|{self.method}|{self.endpoint}|{self.resource}"


@dataclass(frozen=True, slots=True)
class AuthzFieldLevelObservation:
    """A field-level access-control indicator (potentially restricted field).

    Attributes:
        origin: canonical origin.
        field: field name (e.g. ``is_admin``).
        resource: owning resource when observed.
        endpoint: endpoint where the field appears.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    field: str
    resource: str = ""
    endpoint: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"field-level:{self.origin}|{self.field}|{self.resource}"


@dataclass(frozen=True, slots=True)
class AuthzFrontendObservation:
    """A frontend authorization-logic indicator.

    Attributes:
        origin: canonical origin.
        check_type: ``isAdmin``/``hasPermission``/``hasRole``/``can``/
            ``authorize``/``checkAccess``/``route-guard``/``feature-flag``.
        target: what the check protects (endpoint/resource/route).
        js_asset: owning script asset URL.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    check_type: str = "unknown"
    target: str = ""
    js_asset: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"frontend:{self.origin}|{self.check_type}|{self.target}|{self.js_asset}"


@dataclass(frozen=True, slots=True)
class AuthzBackendObservation:
    """A backend authorization-logic indicator.

    Attributes:
        origin: canonical origin.
        mechanism: ``middleware``/``decorator``/``guard``/``policy``/
            ``service``/``engine``.
        name: mechanism/endpoint name when observed.
        target: what the mechanism protects (endpoint/resource).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    mechanism: str = "unknown"
    name: str = ""
    target: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"backend:{self.origin}|{self.mechanism}|{self.name}|{self.target}"


@dataclass(frozen=True, slots=True)
class AuthzApiCorrelationObservation:
    """API authorization correlation for one operation.

    Attributes:
        origin: canonical origin.
        endpoint: operation endpoint.
        method: HTTP method.
        authentication: observed authentication requirement (scheme name).
        role: observed role requirement (metadata only).
        scope: observed scope requirement (metadata only).
        permission: observed permission requirement.
        resource: associated resource.
        action: associated action.
        tenant: observed tenant indicator.
        policy: observed policy model.
        documented: whether a spec declared the operation.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    endpoint: str
    method: str = "GET"
    authentication: str = ""
    role: str = ""
    scope: str = ""
    permission: str = ""
    resource: str = ""
    action: str = ""
    tenant: str = ""
    policy: str = ""
    documented: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"api-correlation:{self.origin}|{self.method}|{self.endpoint}"


@dataclass(frozen=True, slots=True)
class AuthzGraphQLObservation:
    """A GraphQL authorization indicator.

    Attributes:
        origin: canonical origin.
        subject: ``query``/``mutation``/``subscription``/``type``/``field``.
        name: subject name (type/field/operation).
        directive: observed authorization directive.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    subject: str = "field"
    name: str = ""
    directive: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"graphql:{self.origin}|{self.subject}|{self.name}|{self.directive}"


@dataclass(frozen=True, slots=True)
class AuthzWebSocketObservation:
    """A WebSocket authorization indicator.

    Attributes:
        origin: canonical origin.
        endpoint: WebSocket endpoint URL.
        channel: observed channel/topic when documented.
        mechanism: ``connection-auth``/``channel-auth``/``topic-auth``/
            ``subscription-auth``.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    endpoint: str = ""
    channel: str = ""
    mechanism: str = "unknown"
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"websocket:{self.origin}|{self.endpoint}|{self.channel}|{self.mechanism}"


@dataclass(frozen=True, slots=True)
class AuthzServiceObservation:
    """A service-to-service authorization indicator.

    Attributes:
        origin: canonical origin.
        name: service account/API client/machine identity name.
        service_kind: ``service-account``/``api-client``/``machine-identity``.
        mechanism: ``client-credentials``/``mtls``/``internal-header``.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str
    service_kind: str = "unknown"
    mechanism: str = "unknown"
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"service:{self.origin}|{self.service_kind}|{self.name}|{self.mechanism}"


@dataclass(frozen=True, slots=True)
class AuthzDecisionObservation:
    """An observed/documented authorization decision indicator.

    Attributes:
        origin: canonical origin.
        decision: :class:`DecisionKind` value.
        endpoint: endpoint the decision concerns.
        method: HTTP method.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    decision: DecisionKind | str = DecisionKind.UNKNOWN
    endpoint: str = ""
    method: str = "GET"
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", _parse_decision_kind(self.decision))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"decision:{self.origin}|{str(self.decision)}|{self.method}|{self.endpoint}"


@dataclass(frozen=True, slots=True)
class AuthzMassAssignmentObservation:
    """A model containing authorization-sensitive fields (structural only).

    Attributes:
        origin: canonical origin.
        model: model name when observed.
        fields: authorization-sensitive fields (``role``, ``is_admin``, ...).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    model: str = ""
    fields: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"mass-assignment:{self.origin}|{self.model}"


@dataclass(frozen=True, slots=True)
class AuthzAccessControlObservation:
    """An access-control relationship (subject -> role/permission/scope).

    Attributes:
        origin: canonical origin.
        subject: subject name.
        relationship_type: ``role``/``permission``/``scope``/``group``/
            ``tenant``/``membership``.
        target: the target of the relationship.
        resource: optional resource the relationship concerns.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    subject: str
    relationship_type: str = "role"
    target: str = ""
    resource: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"access-control:{self.origin}|{self.relationship_type}|{self.subject}|{self.target}"


@dataclass(frozen=True, slots=True)
class AuthzObservation:
    """A generic authorization-adjacent observation.

    Attributes:
        origin: canonical origin.
        kind: :class:`AuthzObservationKind` value.
        name: canonical observation name.
        value: normalized, masked value (never a raw secret).
        detail: contextual detail.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    kind: AuthzObservationKind | str = AuthzObservationKind.UNKNOWN
    name: str = ""
    value: str = ""
    detail: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthzEvidence, ...] = ()
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = dc_field(default_factory=utcnow_iso)
    record_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_observation_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"observation:{self.origin}|{str(self.kind)}|{self.name}"


# ---------------------------------------------------------------------------
# conflicts, changes, summaries, batch
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorizationConflict:
    """A preserved contradiction between authorization intelligence sources.

    Attributes:
        subject: affected key.
        subject_type: affected record class.
        conflict_type: ``identity``/``model``/``presence``/``enforcement``.
        observations: disagreeing observations with provenance.
        selected: canonical value selected.
        selected_source: provenance of the selected value.
        reason: selection rationale.
        confidence: selection confidence in ``[0, 1]``.
        detected_at: UTC ISO-8601 detection timestamp.

    """

    subject: str
    subject_type: str = "resource"
    conflict_type: str = "identity"
    observations: tuple[dict[str, Any], ...] = ()
    selected: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    detected_at: str = dc_field(default_factory=utcnow_iso)

    def key(self) -> str:
        """Return the canonical key of this conflict."""
        return f"authorization:{self.subject_type}|{self.subject}"


@dataclass(frozen=True, slots=True)
class AuthorizationChange:
    """A detected difference between historical and current authorization state.

    Attributes:
        subject_type: affected record class.
        subject: canonical subject key.
        change_type: ``added``/``removed``/``changed``.
        previous / current: values.
        detected_at: UTC ISO-8601 detection timestamp.
        source: tool that produced the current observation.
        details: extra change context.

    """

    subject_type: str
    subject: str
    change_type: str
    previous: str = ""
    current: str = ""
    detected_at: str = dc_field(default_factory=utcnow_iso)
    source: str = ""
    details: Mapping[str, Any] = dc_field(default_factory=dict)

    def key(self) -> str:
        """Return the canonical key of the changed subject."""
        return f"authorization:{self.subject_type}|{self.subject}"


@dataclass(frozen=True, slots=True)
class AuthorizationExecutionSummary:
    """Outcome of running one authorization-analysis tool through the engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        observations: number of observations produced.
        resources: number of distinct authorization resources produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    observations: int = 0
    resources: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class AuthorizationBatch:
    """The result of one authorization intelligence run.

    Aggregates the raw observations, the correlated canonical records,
    evidence, conflicts, changes and the run's identity.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target analysed.
        mode: the execution posture used.
        raw: raw observations collected from every source.
        records: correlated canonical observations (all record types).
        conflicts: conflicting observations recorded.
        changes: historical changes detected.
        executions: per-tool execution summaries.
        created_at: UTC ISO-8601 run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: AuthorizationTarget
    mode: ReconMode = ReconMode.HYBRID
    raw: list[Any] = dc_field(default_factory=list)
    records: list[Any] = dc_field(default_factory=list)
    conflicts: list[AuthorizationConflict] = dc_field(default_factory=list)
    changes: list[AuthorizationChange] = dc_field(default_factory=list)
    executions: list[AuthorizationExecutionSummary] = dc_field(default_factory=list)
    created_at: str = dc_field(default_factory=utcnow_iso)
    batch_id: str = dc_field(default_factory=generate_id, kw_only=True)

    def add_observation(self, observation: Any) -> None:
        """Append a raw observation to the batch."""
        self.raw.append(observation)

    def add_record(self, record: Any) -> None:
        """Append a correlated canonical record to the batch."""
        self.records.append(record)

    def add_conflict(self, conflict: AuthorizationConflict) -> None:
        """Append a conflict to the batch."""
        self.conflicts.append(conflict)

    def add_change(self, change: AuthorizationChange) -> None:
        """Append a historical change to the batch."""
        self.changes.append(change)

    def add_execution(self, summary: AuthorizationExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)

    def resource_count(self) -> int:
        """Return the number of correlated authorization resources."""
        return sum(1 for record in self.records if _record_type(record) == "resource")

    def role_count(self) -> int:
        """Return the number of correlated roles."""
        return sum(1 for record in self.records if _record_type(record) == "role")

    def conflict_count(self) -> int:
        """Return the number of recorded conflicts."""
        return len(self.conflicts)

    def change_count(self) -> int:
        """Return the number of recorded changes."""
        return len(self.changes)

    def record_count(self) -> int:
        """Return the total number of correlated records."""
        return len(self.records)

    def total_observations(self) -> int:
        """Return the total number of raw observations in the batch."""
        return len(self.raw)


# ---------------------------------------------------------------------------
# analyzer input
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorizationInput:
    """The normalized input bundle fed to the authorization analyzer.

    Carries one HTTP response snapshot, associated script content, API security
    schemes and operations, GraphQL metadata, WebSocket endpoints, observed
    URLs, policy documents and pre-existing TIDB intelligence so the analyzer
    stays pure (no I/O) and deterministic.

    Attributes:
        target: canonical target identifier.
        url: the URL the snapshot was observed on.
        status_code: HTTP status observed.
        headers: lowercased header name/value pairs.
        html: HTML body text (bounded).
        content_type: response content type.
        final_url: redirect target when a redirect was observed.
        scripts: ``(url, content)`` script assets.
        api_schemes: API security-scheme records.
        api_operations: API operation records (endpoint, method, security).
        graphql: parsed GraphQL metadata records.
        websockets: observed WebSocket endpoint records.
        documents: parsed policy/document records.
        observed_urls: other observed URLs on the target.
        tidb_hints: pre-existing TIDB intelligence records.
        source / tool_id: provenance.

    """

    target: str
    url: str = ""
    status_code: int = 0
    headers: tuple[tuple[str, str], ...] = ()
    html: str = ""
    content_type: str = ""
    final_url: str = ""
    scripts: tuple[tuple[str, str], ...] = ()
    api_schemes: tuple[dict[str, object], ...] = ()
    api_operations: tuple[dict[str, object], ...] = ()
    graphql: tuple[dict[str, object], ...] = ()
    websockets: tuple[dict[str, object], ...] = ()
    documents: tuple[dict[str, object], ...] = ()
    observed_urls: tuple[str, ...] = ()
    tidb_hints: tuple[dict[str, object], ...] = ()
    source: str = "authorization"
    tool_id: str = ""


# ---------------------------------------------------------------------------
# payload bridge
# ---------------------------------------------------------------------------


#: Record type discriminators -> builder class.
_BUILDERS: dict[str, type] = {
    "subject": AuthzSubjectObservation,
    "role": AuthzRoleObservation,
    "group": AuthzGroupObservation,
    "permission": AuthzPermissionObservation,
    "scope": AuthzScopeObservation,
    "claim": AuthzClaimObservation,
    "policy": AuthzPolicyObservation,
    "resource": AuthzResourceObservation,
    "action": AuthzActionObservation,
    "identifier": AuthzResourceIdentifierObservation,
    "ownership": AuthzOwnershipObservation,
    "tenant": AuthzTenantObservation,
    "admin-surface": AuthzAdminSurfaceObservation,
    "function-level": AuthzFunctionLevelObservation,
    "object-level": AuthzObjectLevelObservation,
    "field-level": AuthzFieldLevelObservation,
    "frontend": AuthzFrontendObservation,
    "backend": AuthzBackendObservation,
    "api-correlation": AuthzApiCorrelationObservation,
    "graphql": AuthzGraphQLObservation,
    "websocket": AuthzWebSocketObservation,
    "service": AuthzServiceObservation,
    "decision": AuthzDecisionObservation,
    "mass-assignment": AuthzMassAssignmentObservation,
    "access-control": AuthzAccessControlObservation,
    "authorization-observation": AuthzObservation,
}


def observations_from_payload(payload: Mapping[str, Any] | None) -> list[Any]:
    """Extract canonical observations from a pipeline JSON payload.

    Authorization adapters serialise their detections under the
    ``authorization`` key of the JSON payload they attach to the execution
    output. Each entry carries a ``type`` discriminator. This helper rebuilds
    the typed records so downstream services never touch raw dictionaries.
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
        record_type = entry.get("type")
        builder = _BUILDERS.get(str(record_type)) if record_type is not None else None
        if builder is None:
            continue
        try:
            observations.append(record_from_dict(builder, entry))
        except (TypeError, ValueError, KeyError):
            continue
    return observations


def record_type_of(record: Any) -> str:
    """Return the payload discriminator for an authorization record."""
    return _record_type(record)


def _record_type(record: Any) -> str:
    for discriminator, builder in _BUILDERS.items():
        if isinstance(record, builder):
            return discriminator
    return "unknown"


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------


def infer_asset_type(value: str) -> str:
    """Infer a canonical asset kind from a target value."""
    candidate = str(value).strip()
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return ASSET_URL
    try:
        import ipaddress

        ipaddress.ip_address(candidate)
        return ASSET_IP
    except ValueError:
        pass
    if "." in candidate:
        return ASSET_DOMAIN if candidate.count(".") == 1 else ASSET_HOSTNAME
    return ASSET_HOSTNAME


def origin_of(url: str) -> str:
    """Return ``scheme://host[:port]`` of ``url`` (empty when unparseable)."""
    import urllib.parse

    candidate = str(url).strip()
    if "://" not in candidate:
        return ""
    try:
        parsed = urllib.parse.urlsplit(candidate)
        return f"{parsed.scheme}://{parsed.netloc}"
    except ValueError:
        return ""


def _parse_subject_kind(value: object) -> SubjectKind:
    try:
        return SubjectKind(str(value).lower())
    except ValueError:
        return SubjectKind.UNKNOWN


def _parse_resource_kind(value: object) -> ResourceKind:
    try:
        return ResourceKind(str(value).lower())
    except ValueError:
        return ResourceKind.UNKNOWN


def _parse_identifier_kind(value: object) -> IdentifierKind:
    try:
        return IdentifierKind(str(value).lower())
    except ValueError:
        return IdentifierKind.UNKNOWN


def _parse_policy_model_kind(value: object) -> PolicyModelKind:
    try:
        return PolicyModelKind(str(value).lower())
    except ValueError:
        return PolicyModelKind.UNKNOWN


def _parse_ownership_kind(value: object) -> OwnershipKind:
    try:
        return OwnershipKind(str(value).lower())
    except ValueError:
        return OwnershipKind.UNKNOWN


def _parse_tenant_kind(value: object) -> TenantKind:
    try:
        return TenantKind(str(value).lower())
    except ValueError:
        return TenantKind.UNKNOWN


def _parse_admin_surface_kind(value: object) -> AdminSurfaceKind:
    try:
        return AdminSurfaceKind(str(value).lower())
    except ValueError:
        return AdminSurfaceKind.UNKNOWN


def _parse_decision_kind(value: object) -> DecisionKind:
    try:
        return DecisionKind(str(value).lower())
    except ValueError:
        return DecisionKind.UNKNOWN


def _parse_observation_kind(value: object) -> AuthzObservationKind:
    try:
        return AuthzObservationKind(str(value).lower())
    except ValueError:
        return AuthzObservationKind.UNKNOWN


def _parse_evidence_type(value: object) -> AuthzEvidenceType:
    try:
        return AuthzEvidenceType(str(value).lower())
    except ValueError:
        return AuthzEvidenceType.OTHER


def _parse_evidence_strength(value: object) -> EvidenceStrength:
    try:
        return EvidenceStrength(str(value).lower())
    except ValueError:
        return EvidenceStrength.MODERATE
