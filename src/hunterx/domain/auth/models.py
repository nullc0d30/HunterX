# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication, session & identity intelligence canonical domain models.

Pure data contracts for the Wave 9 authentication intelligence capability
(Sprint 015): authentication surfaces, endpoints, modeled flows, identity
providers, OAuth/OIDC/SAML configurations, authentication schemes, cookie
security metadata, token-storage indicators, CSRF mechanisms, CORS policies,
MFA/WebAuthn mechanisms, role/scope/permission/tenant indicators, generic
observations, evidence, conflicts, historical changes, execution summaries,
the collection strategy and the batch that carries everything back to the
application layer. No I/O and no execution here.

Security boundary: the models carry metadata and masked/derived values only.
No model field ever holds a raw password, access/refresh token, session-cookie
value, OTP, recovery code or authorization-header value.

The TIDB ``auth_intelligence`` entities
(:mod:`hunterx.domain.entities.tidb.auth_intelligence`) are the persistence
projection of these models; this module is the runtime surface the
authentication intelligence pipeline is built on.
"""

from __future__ import annotations

import dataclasses
import types
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Any, get_args, get_origin

from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class AuthSurfaceKind(StrEnum):
    """Canonical kinds of an authentication surface."""

    LOGIN = "login"
    REGISTRATION = "registration"
    PASSWORD_RESET = "password-reset"
    PASSWORD_CHANGE = "password-change"
    PASSWORD_RECOVERY = "password-recovery"
    EMAIL_VERIFICATION = "email-verification"
    MFA_ENROLLMENT = "mfa-enrollment"
    MFA_CHALLENGE = "mfa-challenge"
    MFA_RECOVERY = "mfa-recovery"
    ACCOUNT_VERIFICATION = "account-verification"
    ACCOUNT_RECOVERY = "account-recovery"
    SESSION_REFRESH = "session-refresh"
    TOKEN_REFRESH = "token-refresh"
    AUTH_CALLBACK = "auth-callback"
    AUTHORIZATION_CALLBACK = "authorization-callback"
    SSO_ENTRYPOINT = "sso-entrypoint"
    IDENTITY_PROVIDER = "identity-provider"
    LOGOUT = "logout"
    UNKNOWN = "unknown"


class AuthEndpointKind(StrEnum):
    """Canonical kinds of an authentication-related endpoint."""

    LOGIN = "login"
    LOGOUT = "logout"
    REGISTRATION = "registration"
    PASSWORD_RESET = "password-reset"
    PASSWORD_CHANGE = "password-change"
    PASSWORD_RECOVERY = "password-recovery"
    EMAIL_VERIFICATION = "email-verification"
    MFA_ENROLLMENT = "mfa-enrollment"
    MFA_CHALLENGE = "mfa-challenge"
    MFA_RECOVERY = "mfa-recovery"
    ACCOUNT_VERIFICATION = "account-verification"
    ACCOUNT_RECOVERY = "account-recovery"
    SESSION_REFRESH = "session-refresh"
    TOKEN_REFRESH = "token-refresh"
    TOKEN_ENDPOINT = "token-endpoint"
    AUTHORIZATION_ENDPOINT = "authorization-endpoint"
    REVOCATION_ENDPOINT = "revocation-endpoint"
    INTROSPECTION_ENDPOINT = "introspection-endpoint"
    USERINFO_ENDPOINT = "userinfo-endpoint"
    JWKS_URI = "jwks-uri"
    DISCOVERY_DOCUMENT = "discovery-document"
    AUTH_CALLBACK = "auth-callback"
    AUTHORIZATION_CALLBACK = "authorization-callback"
    SSO_ENTRYPOINT = "sso-entrypoint"
    ACS = "acs"
    SLO = "slo"
    UNKNOWN = "unknown"


class AuthAccessState(StrEnum):
    """Evidence-backed classification of a resource's access requirement."""

    PUBLIC = "public"
    AUTH_REQUIRED = "auth-required"
    AUTHENTICATED_ONLY = "authenticated-only"
    UNKNOWN = "unknown"


class AuthSchemeType(StrEnum):
    """Canonical authentication scheme types."""

    BASIC = "basic"
    BEARER = "bearer"
    APIKEY = "apikey"
    DIGEST = "digest"
    DPOF = "dpop"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    SESSION = "session"
    COOKIE = "cookie"
    CUSTOM = "custom"
    NONE = "none"
    UNKNOWN = "unknown"


class IdPKind(StrEnum):
    """Canonical identity-provider families (evidence-backed only)."""

    AUTH0 = "auth0"
    OKTA = "okta"
    KEYCLOAK = "keycloak"
    AZURE_AD = "azure-ad"
    GOOGLE = "google"
    AWS_COGNITO = "aws-cognito"
    FIREBASE = "firebase"
    SUPABASE = "supabase"
    GITHUB = "github"
    GITLAB = "gitlab"
    PING = "ping"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class TokenStorageType(StrEnum):
    """Canonical client-side token storage locations."""

    LOCAL_STORAGE = "local-storage"
    SESSION_STORAGE = "session-storage"
    COOKIE = "cookie"
    INDEXED_DB = "indexed-db"
    MEMORY = "memory"
    WRAPPER = "wrapper"
    UNKNOWN = "unknown"


class CSRFKind(StrEnum):
    """Canonical CSRF protection mechanisms."""

    SYNCHRONIZER_TOKEN = "synchronizer-token"
    DOUBLE_SUBMIT_COOKIE = "double-submit-cookie"
    SAME_SITE = "same-site"
    CUSTOM_HEADER = "custom-header"
    ORIGIN_CHECK = "origin-check"
    REFERER_CHECK = "referer-check"
    FRAMEWORK = "framework"
    NONE = "none"
    UNKNOWN = "unknown"


class MFAKind(StrEnum):
    """Canonical MFA mechanism families."""

    TOTP = "totp"
    SMS_OTP = "sms-otp"
    EMAIL_OTP = "email-otp"
    PUSH = "push"
    WEBAUTHN = "webauthn"
    FIDO2 = "fido2"
    PASSKEY = "passkey"
    RECOVERY_CODES = "recovery-codes"
    UNKNOWN = "unknown"


class SessionState(StrEnum):
    """Observable session lifecycle states (never fabricated)."""

    ANONYMOUS = "anonymous"
    AUTH_INITIATED = "auth-initiated"
    AUTHENTICATED = "authenticated"
    SESSION_ESTABLISHED = "session-established"
    SESSION_REFRESH = "session-refresh"
    LOGOUT = "logout"
    SESSION_EXPIRED = "session-expired"
    RECOVERY = "recovery"
    MFA_CHALLENGE = "mfa-challenge"
    MFA_VERIFIED = "mfa-verified"
    UNKNOWN = "unknown"


class FlowKind(StrEnum):
    """Canonical authentication flow families."""

    TRADITIONAL_LOGIN = "traditional-login"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    PASSWORD_RESET = "password-reset"
    REGISTRATION = "registration"
    LOGOUT = "logout"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class AccessClassification(StrEnum):
    """Evidence-backed public vs authenticated surface classification."""

    PUBLIC = "public"
    AUTH_REQUIRED = "auth-required"
    AUTHENTICATED_ONLY = "authenticated-only"
    UNKNOWN = "unknown"


class AuthObservationKind(StrEnum):
    """Kinds of generic authentication-adjacent observations."""

    HEADER = "header"
    JWT = "jwt"
    SESSION_STATE = "session-state"
    PASSWORD_POLICY = "password-policy"
    ACCOUNT_LIFECYCLE = "account-lifecycle"
    CLAIM = "claim"
    PREFLIGHT = "preflight"
    CUSTOM_HEADER = "custom-header"
    UNKNOWN = "unknown"


class EvidenceStrength(StrEnum):
    """Relative strength of a single authentication indicator."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class EvidenceType(StrEnum):
    """The kind of source an evidence fragment came from."""

    HTTP_HEADER = "http-header"
    COOKIE = "cookie"
    HTML = "html"
    HTTP_STATUS = "http-status"
    URL_PATTERN = "url-pattern"
    LOCATION = "location"
    JAVASCRIPT = "javascript"
    OPENID_DISCOVERY = "openid-discovery"
    SAML_METADATA = "saml-metadata"
    OPENAPI_SECURITY = "openapi-security"
    JS_INDICATOR = "js-indicator"
    TIDB_INTELLIGENCE = "tidb-intelligence"
    TOOL_OUTPUT = "tool-output"
    KNOWN_SIGNATURE = "known-signature"
    OTHER = "other"


class ChangeType(StrEnum):
    """Historical change categories for authentication intelligence subjects."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


#: Pipeline payload discriminator key for typed auth findings.
FINDINGS_KEY = "auth"

#: Canonical asset kinds an auth observation can be attached to.
ASSET_URL = "url"
ASSET_HOSTNAME = "hostname"
ASSET_DOMAIN = "domain"
ASSET_IP = "ip"


# ---------------------------------------------------------------------------
# generic serialization helpers
# ---------------------------------------------------------------------------


def record_to_dict(instance: object) -> dict[str, Any]:
    """Serialize any auth record into a JSON-safe dictionary.

    Nested dataclasses are rendered recursively, every :class:`Enum` is
    reduced to its value, and the record's ``type`` discriminator is included
    so :func:`observations_from_payload` can rebuild the typed record.
    """
    payload: dict[str, Any] = _encode(dataclasses.asdict(instance))  # type: ignore[call-overload]  # instance is always a dataclass
    payload["type"] = _record_type(instance)
    return payload


def record_from_dict(cls: type, payload: Mapping[str, Any]) -> Any:
    """Rebuild an auth record from a :func:`record_to_dict` payload."""
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
class AuthTarget:
    """A single authentication intelligence target.

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
class AuthEvidence:
    """One evidence fragment backing an authentication intelligence record.

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
    source: str = "auth"
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
    def from_dict(cls, payload: Mapping[str, Any]) -> AuthEvidence:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            evidence_type=_parse_evidence_type(payload.get("evidence_type")),
            value=str(payload.get("value") or ""),
            source=str(payload.get("source") or "auth"),
            strength=_parse_evidence_strength(payload.get("strength")),
            tool_id=str(payload.get("tool_id") or ""),
            detail=str(payload.get("detail") or ""),
            integrity=str(payload.get("integrity") or ""),
        )


def make_evidence(
    evidence_type: EvidenceType | str,
    value: str,
    *,
    source: str = "auth",
    strength: EvidenceStrength | str = EvidenceStrength.MODERATE,
    tool_id: str = "",
    detail: str = "",
) -> AuthEvidence:
    """Build an :class:`AuthEvidence` fragment with the given type and value."""
    return AuthEvidence(
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
class AuthSurfaceObservation:
    """A discovered authentication surface on an origin.

    Attributes:
        url: canonical URL of the surface.
        origin: canonical ``scheme://host[:port]``.
        surface_kind: surface classification.
        access_state: public vs auth-required classification.
        indicators: evidence strings that triggered the discovery.
        confidence: intelligence confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        execution_id / observed_at / record_id.

    """

    url: str
    origin: str
    surface_kind: AuthSurfaceKind | str = AuthSurfaceKind.UNKNOWN
    access_state: AuthAccessState | str = AuthAccessState.UNKNOWN
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "surface_kind", _parse_surface_kind(self.surface_kind))
        object.__setattr__(self, "access_state", _parse_access_state(self.access_state))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"surface:{self.origin}|{self.url}|{str(self.surface_kind)}"


@dataclass(frozen=True, slots=True)
class AuthEndpointObservation:
    """An authentication-related endpoint.

    Attributes:
        url: endpoint URL.
        method: HTTP method.
        origin: canonical origin.
        kind: endpoint classification.
        documented: whether a spec/documentation declared the endpoint.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    url: str
    method: str = "GET"
    origin: str = ""
    kind: AuthEndpointKind | str = AuthEndpointKind.UNKNOWN
    documented: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_endpoint_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"endpoint:{self.origin}|{self.method}|{self.url}|{str(self.kind)}"


@dataclass(frozen=True, slots=True)
class AuthFlowObservation:
    """A modeled stateful authentication flow.

    Attributes:
        name: flow label.
        flow_kind: flow family.
        origin: canonical origin.
        start_state / end_state: observable session states bounding the flow.
        steps: ordered endpoint kinds/URLs composing the flow.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    name: str
    flow_kind: FlowKind | str = FlowKind.UNKNOWN
    origin: str = ""
    start_state: SessionState | str = SessionState.ANONYMOUS
    end_state: SessionState | str = SessionState.UNKNOWN
    steps: tuple[dict[str, str], ...] = ()
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "flow_kind", _parse_flow_kind(self.flow_kind))
        object.__setattr__(self, "start_state", _parse_session_state(self.start_state))
        object.__setattr__(self, "end_state", _parse_session_state(self.end_state))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"flow:{self.origin}|{self.name}|{str(self.flow_kind)}"


@dataclass(frozen=True, slots=True)
class IdPObservation:
    """A detected identity provider.

    Attributes:
        name: canonical provider name.
        provider_kind: :class:`IdPKind` value.
        origin: canonical origin where the provider was observed.
        issuer: detected issuer identifier when available.
        discovery_url: OIDC discovery document URL when found.
        endpoints: provider endpoint table.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    name: str
    provider_kind: IdPKind | str = IdPKind.UNKNOWN
    origin: str = ""
    issuer: str = ""
    discovery_url: str = ""
    endpoints: tuple[dict[str, str], ...] = ()
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_kind", _parse_idp_kind(self.provider_kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"idp:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class OAuthObservation:
    """Detected OAuth 2.x configuration metadata (never secrets).

    Attributes:
        origin: canonical origin.
        authorization_endpoint / token_endpoint / revocation_endpoint /
            introspection_endpoint / userinfo_endpoint: discovered URLs.
        issuer: detected issuer.
        jwks_uri: JWKS URI when observed.
        client_ids: observed client identifiers (non-secret identifiers only).
        redirect_uris: observed registered redirect URI patterns.
        scopes / response_types / grant_types: declared values.
        pkce / state_parameter: whether PKCE/state are indicated.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    revocation_endpoint: str = ""
    introspection_endpoint: str = ""
    userinfo_endpoint: str = ""
    issuer: str = ""
    jwks_uri: str = ""
    client_ids: tuple[str, ...] = ()
    redirect_uris: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    response_types: tuple[str, ...] = ()
    grant_types: tuple[str, ...] = ()
    pkce: bool = False
    state_parameter: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"oauth:{self.origin}"


@dataclass(frozen=True, slots=True)
class OIDCObservation:
    """Detected OIDC metadata (discovery document values, non-secret).

    Attributes:
        origin: canonical origin.
        issuer: OIDC issuer.
        discovery_url: location of the discovery document.
        authorization_endpoint / token_endpoint / userinfo_endpoint /
            jwks_uri: discovered endpoints.
        scopes / claims: declared scopes and supported claims.
        response_types / subject_types / id_token_signing_alg_values:
            supported metadata.
        code_challenge_methods_supported: PKCE methods.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    issuer: str = ""
    discovery_url: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    scopes: tuple[str, ...] = ()
    claims: tuple[str, ...] = ()
    response_types: tuple[str, ...] = ()
    subject_types: tuple[str, ...] = ()
    id_token_signing_alg_values: tuple[str, ...] = ()
    code_challenge_methods_supported: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"oidc:{self.origin}"


@dataclass(frozen=True, slots=True)
class SAMLIndicatorObservation:
    """Detected SAML indicators (safe metadata only, never messages).

    Attributes:
        origin: canonical origin.
        entity_id: SAML entity id when exposed.
        sso_url: SSO endpoint when exposed.
        acs_url: assertion consumer service URL when exposed.
        metadata_url: metadata document URL when exposed.
        idp_name / sp_name: identity/service provider labels.
        relay_state: whether ``RelayState`` indicators were observed.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    entity_id: str = ""
    sso_url: str = ""
    acs_url: str = ""
    metadata_url: str = ""
    idp_name: str = ""
    sp_name: str = ""
    relay_state: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"saml:{self.origin}"


@dataclass(frozen=True, slots=True)
class JWTIndicatorObservation:
    """A safely detected JWT-like indicator.

    Attributes:
        origin: canonical origin.
        transport: ``authorization-header``/``cookie``/``local-storage``/
            ``session-storage``/``body``/``url``/``static``/``unknown``.
        location: where the indicator was observed.
        issuer / audience / algorithm: claims observed in static material.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    transport: str = "unknown"
    location: str = ""
    issuer: str = ""
    audience: str = ""
    algorithm: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"jwt:{self.origin}|{self.transport}|{self.location}"


@dataclass(frozen=True, slots=True)
class AuthSchemeObservation:
    """An authentication scheme observed on an origin/API.

    Attributes:
        origin: canonical origin.
        scheme_type: scheme classification.
        name: scheme name from a spec.
        token_location: ``header``/``query``/``cookie``.
        header_name: authentication header name when identified.
        documented: whether a spec declared the scheme.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    scheme_type: AuthSchemeType | str = AuthSchemeType.UNKNOWN
    name: str = ""
    token_location: str = "header"
    header_name: str = ""
    documented: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "scheme_type", _parse_scheme_type(self.scheme_type))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"scheme:{self.origin}|{str(self.scheme_type)}|{self.header_name}"


@dataclass(frozen=True, slots=True)
class AuthCookieObservation:
    """Cookie security metadata observed on an origin.

    Attributes:
        name: cookie name.
        origin: canonical origin.
        domain / path: cookie scope.
        secure / httponly / partitioned: boolean attributes.
        samesite: ``strict``/``lax``/``none``/``unknown``.
        max_age / expires: lifetime metadata.
        priority: cookie priority when declared.
        prefix: ``__Secure-``/``__Host-``/````.
        session: whether the cookie is a session cookie.
        persistent: whether the cookie has an explicit lifetime.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    name: str
    origin: str
    domain: str = ""
    path: str = ""
    secure: bool = False
    httponly: bool = False
    partitioned: bool = False
    samesite: str = "unknown"
    max_age: str = ""
    expires: str = ""
    priority: str = ""
    prefix: str = ""
    session: bool = True
    persistent: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"cookie:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class TokenStorageObservation:
    """A client-side token storage indicator (never the token value).

    Attributes:
        origin: canonical origin.
        storage_type: :class:`TokenStorageType` value.
        context: surrounding static context (masked/truncated).
        token_category: ``access-token``/``refresh-token``/``id-token``/
            ``session``/``api-key``/``unknown``.
        js_asset: owning script asset URL.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    storage_type: TokenStorageType | str = TokenStorageType.UNKNOWN
    context: str = ""
    token_category: str = "unknown"
    js_asset: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "storage_type", _parse_storage_type(self.storage_type))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"storage:{self.origin}|{str(self.storage_type)}|{self.token_category}|{self.js_asset}"


@dataclass(frozen=True, slots=True)
class CSRFObservation:
    """A CSRF protection mechanism indicator.

    Attributes:
        origin: canonical origin.
        kind: :class:`CSRFKind` value.
        endpoint: endpoint the mechanism protects (``""`` when global).
        cookie_name / header_name / parameter_name: mechanism tokens.
        samesite: observed SameSite value when present.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    kind: CSRFKind | str = CSRFKind.UNKNOWN
    endpoint: str = ""
    cookie_name: str = ""
    header_name: str = ""
    parameter_name: str = ""
    samesite: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_csrf_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"csrf:{self.origin}|{str(self.kind)}|{self.cookie_name}|{self.header_name}"


@dataclass(frozen=True, slots=True)
class CORSObservation:
    """Observed CORS configuration indicators.

    Attributes:
        origin: canonical origin.
        allow_origin: ``Access-Control-Allow-Origin`` value.
        allow_credentials: whether credentials are allowed.
        allow_methods / allow_headers / expose_headers: declared values.
        preflight: whether preflight behavior was observed.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    allow_origin: str = ""
    allow_credentials: bool = False
    allow_methods: tuple[str, ...] = ()
    allow_headers: tuple[str, ...] = ()
    expose_headers: tuple[str, ...] = ()
    preflight: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 0.5
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"cors:{self.origin}"


@dataclass(frozen=True, slots=True)
class MFAObservation:
    """A detected MFA mechanism indicator.

    Attributes:
        origin: canonical origin.
        kind: :class:`MFAKind` value.
        endpoint: endpoint where the mechanism is exercised.
        ui: UI/page where the mechanism is offered.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    kind: MFAKind | str = MFAKind.UNKNOWN
    endpoint: str = ""
    ui: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_mfa_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"mfa:{self.origin}|{str(self.kind)}|{self.endpoint}"


@dataclass(frozen=True, slots=True)
class WebAuthnObservation:
    """A WebAuthn/passkey indicator (static/observable metadata only).

    Attributes:
        origin: canonical origin.
        kind: ``registration``/``authentication``/``unknown``.
        api: observed API (``navigator.credentials``/``PublicKeyCredential``).
        js_asset: owning script asset URL.
        challenge_ref: reference (never the challenge value) to a challenge.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    kind: str = "unknown"
    api: str = ""
    js_asset: str = ""
    challenge_ref: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"webauthn:{self.origin}|{self.kind}|{self.api}|{self.js_asset}"


@dataclass(frozen=True, slots=True)
class RoleObservation:
    """An observed role identifier (evidence-backed, never inferred)."""

    origin: str
    name: str
    context: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"role:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class ScopeObservation:
    """An observed OAuth/OIDC scope identifier."""

    origin: str
    name: str
    description: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"scope:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class PermissionObservation:
    """An observed permission identifier."""

    origin: str
    name: str
    action: str = ""
    resource: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"permission:{self.origin}|{self.name}"


@dataclass(frozen=True, slots=True)
class TenantObservation:
    """A multi-tenancy indicator.

    Attributes:
        origin: canonical origin.
        name: tenant/organization/workspace/account identifier observed.
        tenant_type: ``id``/``header``/``claim``/``path``/``query``/``unknown``.
        location: where the indicator was observed (header name, claim, path).
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    name: str
    tenant_type: str = "unknown"
    location: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.3
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"tenant:{self.origin}|{self.tenant_type}|{self.name}"


@dataclass(frozen=True, slots=True)
class AuthObservation:
    """A generic authentication-adjacent observation.

    Attributes:
        origin: canonical origin.
        kind: :class:`AuthObservationKind` value.
        name: canonical observation name.
        value: normalized, masked value (never a raw secret).
        detail: contextual detail.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str
    kind: AuthObservationKind | str = AuthObservationKind.UNKNOWN
    name: str = ""
    value: str = ""
    detail: str = ""
    indicators: tuple[str, ...] = ()
    confidence: float = 0.4
    evidence: tuple[AuthEvidence, ...] = ()
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_observation_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"observation:{self.origin}|{str(self.kind)}|{self.name}"


# ---------------------------------------------------------------------------
# conflicts, changes, summaries, batch
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthConflict:
    """A preserved contradiction between authentication intelligence sources.

    Attributes:
        subject: affected key.
        subject_type: affected record class.
        conflict_type: ``identity``/``scheme``/``presence``/``kind``.
        observations: disagreeing observations with provenance.
        selected: canonical value selected.
        selected_source: provenance of the selected value.
        reason: selection rationale.
        confidence: selection confidence in ``[0, 1]``.
        detected_at: UTC ISO-8601 detection timestamp.

    """

    subject: str
    subject_type: str = "surface"
    conflict_type: str = "identity"
    observations: tuple[dict[str, Any], ...] = ()
    selected: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    detected_at: str = field(default_factory=utcnow_iso)

    def key(self) -> str:
        """Return the canonical key of this conflict."""
        return f"auth:{self.subject_type}|{self.subject}"


@dataclass(frozen=True, slots=True)
class AuthChange:
    """A detected difference between historical and current auth state.

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
    detected_at: str = field(default_factory=utcnow_iso)
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        """Return the canonical key of the changed subject."""
        return f"auth:{self.subject_type}|{self.subject}"


@dataclass(frozen=True, slots=True)
class AuthExecutionSummary:
    """Outcome of running one auth-analysis tool through the execution engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        observations: number of observations produced.
        endpoints: number of distinct auth endpoints produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    observations: int = 0
    endpoints: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class AuthBatch:
    """The result of one authentication intelligence run.

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
    target: AuthTarget
    mode: ReconMode = ReconMode.HYBRID
    raw: list[Any] = field(default_factory=list)
    records: list[Any] = field(default_factory=list)
    conflicts: list[AuthConflict] = field(default_factory=list)
    changes: list[AuthChange] = field(default_factory=list)
    executions: list[AuthExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_observation(self, observation: Any) -> None:
        """Append a raw observation to the batch."""
        self.raw.append(observation)

    def add_record(self, record: Any) -> None:
        """Append a correlated canonical record to the batch."""
        self.records.append(record)

    def add_conflict(self, conflict: AuthConflict) -> None:
        """Append a conflict to the batch."""
        self.conflicts.append(conflict)

    def add_change(self, change: AuthChange) -> None:
        """Append a historical change to the batch."""
        self.changes.append(change)

    def add_execution(self, summary: AuthExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)

    def endpoint_count(self) -> int:
        """Return the number of correlated auth endpoints."""
        return sum(1 for record in self.records if _record_type(record) == "auth-endpoint")

    def surface_count(self) -> int:
        """Return the number of correlated auth surfaces."""
        return sum(1 for record in self.records if _record_type(record) == "auth-surface")

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
class AuthInput:
    """The normalized input bundle fed to the authentication analyzer.

    Carries one HTTP response snapshot, associated script content, API security
    schemes, observed URLs and pre-existing TIDB intelligence so the analyzer
    stays pure (no I/O) and deterministic.

    Attributes:
        target: canonical target identifier.
        url: the URL the snapshot was observed on.
        status_code: HTTP status observed.
        headers: lowercased header name/value pairs.
        cookies: parsed cookie attribute tables.
        html: HTML body text (bounded).
        content_type: response content type.
        final_url: redirect target when a redirect was observed.
        scripts: ``(url, content)`` script assets.
        api_schemes: API security-scheme records.
        documents: parsed documents (OIDC discovery JSON, SAML metadata).
        observed_urls: other observed URLs on the target.
        tidb_hints: pre-existing TIDB intelligence records.
        source / tool_id: provenance.

    """

    target: str
    url: str = ""
    status_code: int = 0
    headers: tuple[tuple[str, str], ...] = ()
    cookies: tuple[dict[str, object], ...] = ()
    html: str = ""
    content_type: str = ""
    final_url: str = ""
    scripts: tuple[tuple[str, str], ...] = ()
    api_schemes: tuple[dict[str, object], ...] = ()
    documents: tuple[dict[str, object], ...] = ()
    observed_urls: tuple[str, ...] = ()
    tidb_hints: tuple[dict[str, object], ...] = ()
    source: str = "auth"
    tool_id: str = ""


# ---------------------------------------------------------------------------
# payload bridge
# ---------------------------------------------------------------------------


#: Record type discriminators -> builder class.
_BUILDERS: dict[str, type] = {
    "auth-surface": AuthSurfaceObservation,
    "auth-endpoint": AuthEndpointObservation,
    "auth-flow": AuthFlowObservation,
    "identity-provider": IdPObservation,
    "oauth": OAuthObservation,
    "oidc": OIDCObservation,
    "saml": SAMLIndicatorObservation,
    "jwt": JWTIndicatorObservation,
    "auth-scheme": AuthSchemeObservation,
    "cookie": AuthCookieObservation,
    "token-storage": TokenStorageObservation,
    "csrf": CSRFObservation,
    "cors": CORSObservation,
    "mfa": MFAObservation,
    "webauthn": WebAuthnObservation,
    "role": RoleObservation,
    "scope": ScopeObservation,
    "permission": PermissionObservation,
    "tenant": TenantObservation,
    "auth-observation": AuthObservation,
}


def observations_from_payload(payload: Mapping[str, Any] | None) -> list[Any]:
    """Extract canonical observations from a pipeline JSON payload.

    Auth adapters serialise their detections under the ``auth`` key of the JSON
    payload they attach to the execution output. Each entry carries a ``type``
    discriminator. This helper rebuilds the typed records so downstream services
    never touch raw dictionaries.
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
    """Return the payload discriminator for an auth record."""
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


def _parse_surface_kind(value: object) -> AuthSurfaceKind:
    try:
        return AuthSurfaceKind(str(value).lower())
    except ValueError:
        return AuthSurfaceKind.UNKNOWN


def _parse_endpoint_kind(value: object) -> AuthEndpointKind:
    try:
        return AuthEndpointKind(str(value).lower())
    except ValueError:
        return AuthEndpointKind.UNKNOWN


def _parse_access_state(value: object) -> AuthAccessState:
    try:
        return AuthAccessState(str(value).lower())
    except ValueError:
        return AuthAccessState.UNKNOWN


def _parse_scheme_type(value: object) -> AuthSchemeType:
    try:
        return AuthSchemeType(str(value).lower())
    except ValueError:
        return AuthSchemeType.UNKNOWN


def _parse_idp_kind(value: object) -> IdPKind:
    try:
        return IdPKind(str(value).lower())
    except ValueError:
        return IdPKind.UNKNOWN


def _parse_storage_type(value: object) -> TokenStorageType:
    try:
        return TokenStorageType(str(value).lower())
    except ValueError:
        return TokenStorageType.UNKNOWN


def _parse_csrf_kind(value: object) -> CSRFKind:
    try:
        return CSRFKind(str(value).lower())
    except ValueError:
        return CSRFKind.UNKNOWN


def _parse_mfa_kind(value: object) -> MFAKind:
    try:
        return MFAKind(str(value).lower())
    except ValueError:
        return MFAKind.UNKNOWN


def _parse_flow_kind(value: object) -> FlowKind:
    try:
        return FlowKind(str(value).lower())
    except ValueError:
        return FlowKind.UNKNOWN


def _parse_session_state(value: object) -> SessionState:
    try:
        return SessionState(str(value).lower())
    except ValueError:
        return SessionState.UNKNOWN


def _parse_observation_kind(value: object) -> AuthObservationKind:
    try:
        return AuthObservationKind(str(value).lower())
    except ValueError:
        return AuthObservationKind.UNKNOWN


def _parse_evidence_type(value: object) -> EvidenceType:
    try:
        return EvidenceType(str(value).lower())
    except ValueError:
        return EvidenceType.OTHER


def _parse_evidence_strength(value: object) -> EvidenceStrength:
    try:
        return EvidenceStrength(str(value).lower())
    except ValueError:
        return EvidenceStrength.MODERATE
