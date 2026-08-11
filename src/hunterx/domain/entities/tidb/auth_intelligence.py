# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication, session & identity intelligence TIDB entities.

System-of-record entities for the Wave 9 authentication intelligence
capability (Sprint 015). They carry the canonical, evidence-backed identity &
authentication inventory of an authorized target: authentication surfaces,
authentication endpoints, modeled flows, identity providers, OAuth/OIDC/SAML
configurations, authentication schemes, cookie security metadata, token storage
indicators, CSRF/CORS configurations, MFA/WebAuthn mechanisms, role/scope/
permission/tenant indicators and the derived intelligence (observations,
evidence, changes and run records).

Security boundary: intelligence only. These entities store metadata and
masked/derived values — never raw passwords, session cookie values, access or
refresh tokens, API secrets, OTP values, recovery codes or authorization
header values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class AuthRun(TidbEntity):
    """Observability record for an authentication intelligence run.

    Attributes:
        mission_id: owning mission id.
        target_key: canonical target the run covered.
        target_id: owning target record id.
        status: terminal run status.
        mode: execution posture (passive/active/hybrid).
        surfaces / endpoints / flows / identity_providers / oauth_configs /
            oidc_configs / saml_configs / schemes / cookies / mfa / changes /
            conflicts: artifact counts.
        started_at / completed_at / duration_ms: timing.
        summary: free-form run summary (tools, stats).
        correlation_id: correlation id of the run.

    """

    mission_id: str = ""
    target_key: str = ""
    target_id: str | None = None
    status: str = "running"
    mode: str = "hybrid"
    surfaces: int = 0
    endpoints: int = 0
    flows: int = 0
    identity_providers: int = 0
    oauth_configs: int = 0
    oidc_configs: int = 0
    saml_configs: int = 0
    schemes: int = 0
    cookies: int = 0
    mfa: int = 0
    changes: int = 0
    conflicts: int = 0
    started_at: str = ""
    completed_at: str | None = None
    duration_ms: int = 0
    summary: dict[str, object] = field(default_factory=dict)
    correlation_id: str = ""


@dataclass(slots=True)
class AuthSurface(TidbEntity):
    """A discovered authentication surface on an origin.

    Attributes:
        url: canonical URL of the surface.
        origin: canonical ``scheme://host[:port]``.
        surface_kind: ``login``/``registration``/``password-reset``/
            ``logout``/``mfa``/``sso``/``identity-provider``/``unknown``.
        access_state: ``public``/``auth-required``/``authenticated-only``/
            ``unknown`` with an evidence-backed classification.
        indicators: evidence strings that triggered the discovery.
        confidence: intelligence confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id.

    """

    url: str = ""
    origin: str = ""
    surface_kind: str = "unknown"
    access_state: str = "unknown"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.5
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthEndpoint(TidbEntity):
    """An authentication-related endpoint.

    Attributes:
        url: endpoint URL.
        method: HTTP method (``GET``/``POST``/...).
        origin: canonical origin.
        kind: ``login``/``logout``/``registration``/``password-reset``/
            ``password-change``/``password-recovery``/``email-verification``/
            ``mfa-enrollment``/``mfa-challenge``/``mfa-recovery``/
            ``token-endpoint``/``authorization-endpoint``/``callback``/
            ``session-refresh``/``token-refresh``/``account-verification``/
            ``account-recovery``/``sso-entrypoint``/``userinfo``/``unknown``.
        api_id: owning API host when API-scoped.
        documented: whether a spec/documentation declared the endpoint.
        indicators: evidence strings that triggered the discovery.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    url: str = ""
    method: str = "GET"
    origin: str = ""
    kind: str = "unknown"
    api_id: str | None = None
    documented: bool = False
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.5
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthFlow(TidbEntity):
    """A modeled stateful authentication flow.

    Attributes:
        name: flow label (``login``, ``oauth-authorization-code``,
            ``oidc-authorization-code``, ...).
        flow_kind: ``traditional-login``/``oauth2``/``oidc``/``saml``/
            ``password-reset``/``registration``/``logout``/``custom``.
        origin: canonical origin.
        start_state / end_state: observable session states bounding the flow.
        steps: ordered endpoint kinds/URLs composing the flow.
        indicators: evidence strings supporting the flow model.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    name: str = ""
    flow_kind: str = "custom"
    origin: str = ""
    start_state: str = "anonymous"
    end_state: str = "unknown"
    steps: list[dict[str, str]] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class IdentityProvider(TidbEntity):
    """A detected identity provider.

    Attributes:
        name: canonical provider name (``Auth0``, ``Keycloak``, ``Okta``, ...).
        provider_kind: canonical :class:`IdPKind` value.
        origin: canonical origin where the provider was observed.
        issuer: detected issuer identifier when available.
        discovery_url: OIDC discovery document URL when found.
        endpoints: provider endpoint table (``authorization``, ``token``,
            ``jwks``, ``userinfo``, ``metadata``, ``acs``, ...).
        indicators: evidence strings that triggered the detection.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    name: str = ""
    provider_kind: str = "unknown"
    origin: str = ""
    issuer: str = ""
    discovery_url: str = ""
    endpoints: list[dict[str, str]] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class OAuthConfig(TidbEntity):
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

    origin: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    revocation_endpoint: str = ""
    introspection_endpoint: str = ""
    userinfo_endpoint: str = ""
    issuer: str = ""
    jwks_uri: str = ""
    client_ids: list[str] = field(default_factory=list)
    redirect_uris: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    response_types: list[str] = field(default_factory=list)
    grant_types: list[str] = field(default_factory=list)
    pkce: bool = False
    state_parameter: bool = False
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class OIDCConfig(TidbEntity):
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

    origin: str = ""
    issuer: str = ""
    discovery_url: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    scopes: list[str] = field(default_factory=list)
    claims: list[str] = field(default_factory=list)
    response_types: list[str] = field(default_factory=list)
    subject_types: list[str] = field(default_factory=list)
    id_token_signing_alg_values: list[str] = field(default_factory=list)
    code_challenge_methods_supported: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class SAMLConfig(TidbEntity):
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

    origin: str = ""
    entity_id: str = ""
    sso_url: str = ""
    acs_url: str = ""
    metadata_url: str = ""
    idp_name: str = ""
    sp_name: str = ""
    relay_state: bool = False
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthScheme(TidbEntity):
    """An authentication scheme observed on an origin/API.

    Attributes:
        origin: canonical origin.
        api_id: owning API host when API-scoped.
        scheme_type: ``basic``/``bearer``/``apikey``/``digest``/``dpop``/
            ``oauth2``/``oidc``/``saml``/``session``/``cookie``/``custom``/
            ``none``/``unknown``.
        name: scheme name from a spec.
        token_location: ``header``/``query``/``cookie``.
        header_name: authentication header name when identified.
        documented: whether a spec declared the scheme.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str = ""
    api_id: str | None = None
    scheme_type: str = "unknown"
    name: str = ""
    token_location: str = "header"
    header_name: str = ""
    documented: bool = False
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthCookie(TidbEntity):
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

    name: str = ""
    origin: str = ""
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
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.5
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class TokenStorageIndicator(TidbEntity):
    """A client-side token storage indicator (never the token value).

    Attributes:
        origin: canonical origin.
        storage_type: ``local-storage``/``session-storage``/``cookie``/
            ``indexed-db``/``memory``/``wrapper``/``unknown``.
        context: surrounding static context (masked/truncated).
        token_category: ``access-token``/``refresh-token``/``id-token``/
            ``session``/``api-key``/``unknown``.
        js_asset: owning script asset URL.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str = ""
    storage_type: str = "unknown"
    context: str = ""
    token_category: str = "unknown"
    js_asset: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CSRFMechanism(TidbEntity):
    """A CSRF protection mechanism indicator.

    Attributes:
        origin: canonical origin.
        kind: ``synchronizer-token``/``double-submit-cookie``/``same-site``/
            ``custom-header``/``origin-check``/``referer-check``/``framework``/
            ``unknown``.
        endpoint: endpoint the mechanism protects (``""`` when global).
        cookie_name / header_name / parameter_name: mechanism tokens.
        samesite: observed SameSite value when present.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str = ""
    kind: str = "unknown"
    endpoint: str = ""
    cookie_name: str = ""
    header_name: str = ""
    parameter_name: str = ""
    samesite: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CORSPolicy(TidbEntity):
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

    origin: str = ""
    allow_origin: str = ""
    allow_credentials: bool = False
    allow_methods: list[str] = field(default_factory=list)
    allow_headers: list[str] = field(default_factory=list)
    expose_headers: list[str] = field(default_factory=list)
    preflight: bool = False
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.5
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class MFAMechanism(TidbEntity):
    """A detected MFA mechanism indicator.

    Attributes:
        origin: canonical origin.
        kind: ``totp``/``sms-otp``/``email-otp``/``push``/``webauthn``/
            ``fido2``/``passkey``/``recovery-codes``/``unknown``.
        endpoint: endpoint where the mechanism is exercised.
        ui: UI/page where the mechanism is offered.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str = ""
    kind: str = "unknown"
    endpoint: str = ""
    ui: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class WebAuthnIndicator(TidbEntity):
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

    origin: str = ""
    kind: str = "unknown"
    api: str = ""
    js_asset: str = ""
    challenge_ref: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class RoleIndicator(TidbEntity):
    """An observed role identifier (evidence-backed, never inferred)."""

    origin: str = ""
    name: str = ""
    context: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class ScopeIndicator(TidbEntity):
    """An observed OAuth/OIDC scope identifier."""

    origin: str = ""
    name: str = ""
    description: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class PermissionIndicator(TidbEntity):
    """An observed permission identifier."""

    origin: str = ""
    name: str = ""
    action: str = ""
    resource: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class TenantIndicator(TidbEntity):
    """A multi-tenancy indicator.

    Attributes:
        origin: canonical origin.
        name: tenant/organization/workspace/account identifier observed.
        tenant_type: ``id``/``header``/``claim``/``path``/``query``/``unknown``.
        location: where the indicator was observed (header name, claim, path).
        api_id: owning API host when API-scoped.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str = ""
    name: str = ""
    tenant_type: str = "unknown"
    location: str = ""
    api_id: str | None = None
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.3
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthObservation(TidbEntity):
    """A generic authentication-adjacent observation.

    Attributes:
        origin: canonical origin.
        kind: ``header``/``jwt``/``session-state``/``password-policy``/
            ``account-lifecycle``/``claim``/``preflight``/``unknown``.
        name: canonical observation name.
        value: normalized, masked value (never a raw secret).
        detail: contextual detail.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    origin: str = ""
    kind: str = "unknown"
    name: str = ""
    value: str = ""
    detail: str = ""
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.4
    source: str = "auth"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthEvidence(TidbEntity):
    """One piece of evidence backing authentication intelligence.

    Attributes:
        subject_type: owning record class (``surface``/``endpoint``/``flow``/
            ``identity-provider``/``oauth``/``oidc``/``saml``/``scheme``/
            ``cookie``/``token-storage``/``csrf``/``cors``/``mfa``/
            ``webauthn``/``role``/``scope``/``permission``/``tenant``/
            ``observation``).
        subject_id: owning record id.
        evidence_type: ``http-header``/``cookie``/``html``/``http-status``/
            ``url-pattern``/``location``/``javascript``/``openid-discovery``/
            ``saml-metadata``/``openapi-security``/``js-indicator``/
            ``tidb-intelligence``/``tool-output``/``known-signature``/``other``.
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
    source: str = "auth"
    strength: str = "moderate"
    tool_id: str = ""
    detail: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthChange(TidbEntity):
    """A detected temporal change in the authentication surface.

    Attributes:
        subject_type: affected record class.
        subject: canonical subject key.
        change_type: ``added``/``removed``/``changed``.
        previous / current: values.
        tool_id: producing tool.
        confidence: change confidence.
        mission_id / correlation_id: provenance.

    """

    subject_type: str = "surface"
    subject: str = ""
    change_type: str = "changed"
    previous: str = ""
    current: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""
