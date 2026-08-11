# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Static/observable authentication intelligence detection engine.

The analyzer turns an :class:`AuthInput` bundle — one HTTP response snapshot,
associated script content, API security schemes, observed URLs and pre-existing
TIDB intelligence — into a canonical set of authentication observations with
deterministic evidence and confidence. It is pure: no I/O, no execution, no
authentication attempts, no token validation. Sensitive values are masked
before they ever reach an observation.

Detectors: surfaces & endpoints, cookie security metadata, authentication
schemes, OAuth 2.x, OIDC discovery, SAML indicators, JWT indicators, token
storage, CSRF, CORS, MFA, WebAuthn, identity providers, roles/scopes/
permissions, multi-tenancy, session state and access classification.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.auth.models import (
    AuthAccessState,
    AuthCookieObservation,
    AuthEndpointKind,
    AuthEndpointObservation,
    AuthFlowObservation,
    AuthInput,
    AuthObservation,
    AuthObservationKind,
    AuthSchemeObservation,
    AuthSchemeType,
    AuthSurfaceKind,
    AuthSurfaceObservation,
    CORSObservation,
    CSRFKind,
    CSRFObservation,
    EvidenceStrength,
    EvidenceType,
    FlowKind,
    IdPKind,
    IdPObservation,
    JWTIndicatorObservation,
    MFAKind,
    MFAObservation,
    OAuthObservation,
    OIDCObservation,
    PermissionObservation,
    RoleObservation,
    SAMLIndicatorObservation,
    ScopeObservation,
    SessionState,
    TenantObservation,
    TokenStorageObservation,
    TokenStorageType,
    WebAuthnObservation,
    make_evidence,
    origin_of,
)
from hunterx.shared.masking import mask_value

#: Maximum context length persisted for token-storage / observation context.
_CONTEXT_LIMIT = 256

#: Evidence strength for a direct HTTP observation (headers, status, cookies).
_STRONG = EvidenceStrength.STRONG
_MODERATE = EvidenceStrength.MODERATE
_WEAK = EvidenceStrength.WEAK

#: Confidence for single-source detections by evidence strength.
_CONF_STRONG = 0.9
_CONF_MODERATE = 0.7
_CONF_WEAK = 0.45


@dataclass(slots=True)
class AuthAnalysis:
    """The complete set of authentication observations for one input bundle.

    Every collection is deterministically ordered; :meth:`all_observations`
    flattens them in a stable order for persistence and correlation.
    """

    surfaces: list[AuthSurfaceObservation] = field(default_factory=list)
    endpoints: list[AuthEndpointObservation] = field(default_factory=list)
    flows: list[AuthFlowObservation] = field(default_factory=list)
    identity_providers: list[IdPObservation] = field(default_factory=list)
    oauth: list[OAuthObservation] = field(default_factory=list)
    oidc: list[OIDCObservation] = field(default_factory=list)
    saml: list[SAMLIndicatorObservation] = field(default_factory=list)
    jwt: list[JWTIndicatorObservation] = field(default_factory=list)
    schemes: list[AuthSchemeObservation] = field(default_factory=list)
    cookies: list[AuthCookieObservation] = field(default_factory=list)
    token_storage: list[TokenStorageObservation] = field(default_factory=list)
    csrf: list[CSRFObservation] = field(default_factory=list)
    cors: list[CORSObservation] = field(default_factory=list)
    mfa: list[MFAObservation] = field(default_factory=list)
    webauthn: list[WebAuthnObservation] = field(default_factory=list)
    roles: list[RoleObservation] = field(default_factory=list)
    scopes: list[ScopeObservation] = field(default_factory=list)
    permissions: list[PermissionObservation] = field(default_factory=list)
    tenants: list[TenantObservation] = field(default_factory=list)
    observations: list[AuthObservation] = field(default_factory=list)

    def all_observations(self) -> list[Any]:
        """Return every observation in a stable deterministic order."""
        result: list[Any] = []
        for collection in (
            self.surfaces,
            self.endpoints,
            self.flows,
            self.identity_providers,
            self.oauth,
            self.oidc,
            self.saml,
            self.jwt,
            self.schemes,
            self.cookies,
            self.token_storage,
            self.csrf,
            self.cors,
            self.mfa,
            self.webauthn,
            self.roles,
            self.scopes,
            self.permissions,
            self.tenants,
            self.observations,
        ):
            result.extend(collection)
        return result


class AuthAnalyzer:
    """Run deterministic authentication-signal detection over an input bundle.

    Usage::

        analysis = AuthAnalyzer().analyze(auth_input)
    """

    def analyze(self, bundle: AuthInput) -> AuthAnalysis:
        """Analyze ``bundle`` and return the complete :class:`AuthAnalysis`."""
        context = _Context(bundle)
        analysis = AuthAnalysis()

        self._detect_endpoints(analysis, context)
        self._detect_surfaces(analysis, context)
        self._detect_cookies(analysis, context)
        self._detect_schemes(analysis, context)
        self._detect_oauth(analysis, context)
        self._detect_oidc(analysis, context)
        self._detect_saml(analysis, context)
        self._detect_jwt(analysis, context)
        self._detect_token_storage(analysis, context)
        self._detect_csrf(analysis, context)
        self._detect_cors(analysis, context)
        self._detect_mfa(analysis, context)
        self._detect_webauthn(analysis, context)
        self._detect_identity_providers(analysis, context)
        self._detect_identity_models(analysis, context)
        self._detect_tenants(analysis, context)
        self._detect_session_state(analysis, context)
        self._detect_policies(analysis, context)

        self._build_flows(analysis, context)
        return analysis

    # -- endpoints & surfaces ------------------------------------------------

    def _detect_endpoints(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        urls = [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]
        seen: set[Any] = set()
        for url in urls:
            if not url:
                continue
            origin = origin_of(url) or ctx.origin
            path = _path_of(url)
            matched = _match_endpoint_patterns(path)
            for kind in matched:
                key = (url, kind.value)
                if key in seen:
                    continue
                seen.add(key)
                confidence, strength = _pattern_confidence(kind)
                evidence = (
                    make_evidence(
                        EvidenceType.URL_PATTERN,
                        url,
                        source="auth",
                        strength=strength,
                        tool_id=ctx.bundle.tool_id,
                        detail=f"URL pattern indicates {kind.value}",
                    ),
                )
                analysis.endpoints.append(
                    AuthEndpointObservation(
                        url=url,
                        method="GET",
                        origin=origin,
                        kind=kind,
                        documented=_documented_endpoint(kind, ctx),
                        indicators=(f"url-pattern:{path}",),
                        confidence=confidence,
                        evidence=evidence,
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        # HTML form actions reveal login/registration/mfa endpoints.
        for endpoint in _endpoints_from_html(ctx.bundle.html, ctx.bundle.url):
            key = (endpoint.url, str(endpoint.kind))
            if key in seen:
                continue
            seen.add(key)
            analysis.endpoints.append(
                AuthEndpointObservation(
                    url=endpoint.url,
                    method=endpoint.method,
                    origin=origin_of(endpoint.url) or ctx.origin,
                    kind=endpoint.kind,
                    indicators=endpoint.indicators,
                    confidence=_CONF_MODERATE,
                    evidence=endpoint.evidence,
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    def _detect_surfaces(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        page = ctx.bundle.url
        origin = ctx.origin
        lowered = ctx.html_lower
        indicators: list[str] = []
        kind = AuthSurfaceKind.UNKNOWN
        if _has_password_field(ctx.bundle.html):
            indicators.append("password input present")
            if _login_keywords(lowered):
                kind = AuthSurfaceKind.LOGIN
                indicators.append("login keywords present")
            elif _registration_keywords(lowered):
                kind = AuthSurfaceKind.REGISTRATION
                indicators.append("registration keywords present")
        if _reset_keywords(lowered):
            kind = AuthSurfaceKind.PASSWORD_RESET
            indicators.append("password-reset keywords present")
        if _mfa_keywords(lowered) or _mfa_keywords(_path_of(page)):
            if kind == AuthSurfaceKind.UNKNOWN:
                kind = AuthSurfaceKind.MFA_CHALLENGE
            indicators.append("mfa keywords present")
        if _sso_keywords(lowered) or _sso_keywords(_path_of(page)):
            if kind == AuthSurfaceKind.UNKNOWN:
                kind = AuthSurfaceKind.SSO_ENTRYPOINT
            indicators.append("sso keywords present")
        if ctx.status in (401, 403) or ctx.headers.get("www-authenticate"):
            indicators.append(f"http {ctx.status} observed" if ctx.status in (401, 403) else "www-authenticate observed")
        if not indicators:
            return
        access = self._classify_access(ctx, kind, indicators)
        evidence = (
            make_evidence(
                EvidenceType.HTML if _has_password_field(ctx.bundle.html) else EvidenceType.HTTP_STATUS,
                indicators[0],
                source="auth",
                strength=_MODERATE,
                tool_id=ctx.bundle.tool_id,
                detail=f"surface {kind.value}",
            ),
        )
        analysis.surfaces.append(
            AuthSurfaceObservation(
                url=page,
                origin=origin,
                surface_kind=kind,
                access_state=access,
                indicators=tuple(dict.fromkeys(indicators)),
                confidence=_surface_confidence(indicators),
                evidence=evidence,
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )

    def _classify_access(self, ctx: _Context, kind: AuthSurfaceKind, indicators: list[str]) -> AuthAccessState:
        """Classify a resource as public vs authentication-required (evidence-backed)."""
        if kind in (
            AuthSurfaceKind.LOGIN,
            AuthSurfaceKind.REGISTRATION,
            AuthSurfaceKind.PASSWORD_RESET,
            AuthSurfaceKind.PASSWORD_RECOVERY,
            AuthSurfaceKind.EMAIL_VERIFICATION,
            AuthSurfaceKind.MFA_ENROLLMENT,
            AuthSurfaceKind.ACCOUNT_RECOVERY,
        ):
            return AuthAccessState.PUBLIC
        if ctx.status in (401, 403):
            return AuthAccessState.AUTH_REQUIRED
        if ctx.headers.get("www-authenticate"):
            return AuthAccessState.AUTH_REQUIRED
        if ctx.bundle.final_url and _login_keywords(_path_of(ctx.bundle.final_url)):
            return AuthAccessState.AUTH_REQUIRED
        if _login_keywords(ctx.html_lower) and kind in (AuthSurfaceKind.UNKNOWN, AuthSurfaceKind.LOGIN):
            return AuthAccessState.PUBLIC
        return AuthAccessState.UNKNOWN

    # -- cookies -------------------------------------------------------------

    def _detect_cookies(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        seen: set[Any] = set()
        for cookie in ctx.cookies:
            name = str(cookie.get("name") or "")
            if not name:
                continue
            key = name
            if key in seen:
                continue
            seen.add(key)
            analysis.cookies.append(_cookie_observation(name, cookie, ctx))

    # -- schemes -------------------------------------------------------------

    def _detect_schemes(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        origin = ctx.origin
        seen: set[Any] = set()
        www_authenticate = ctx.headers.get("www-authenticate") or ""
        if www_authenticate:
            scheme_type = _www_authenticate_scheme(www_authenticate)
            key = ("header", scheme_type.value)
            if key not in seen:
                seen.add(key)
                analysis.schemes.append(
                    AuthSchemeObservation(
                        origin=origin,
                        scheme_type=scheme_type,
                        header_name="WWW-Authenticate",
                        indicators=(f"www-authenticate: {_head(www_authenticate)}",),
                        confidence=_CONF_STRONG,
                        evidence=(
                            make_evidence(
                                EvidenceType.HTTP_HEADER,
                                _head(www_authenticate),
                                source="auth",
                                strength=_STRONG,
                                tool_id=ctx.bundle.tool_id,
                                detail="WWW-Authenticate challenge observed",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        authorization = ctx.headers.get("authorization") or ""
        if authorization:
            scheme_type = _authorization_scheme(authorization)
            key = ("header", scheme_type.value)
            if key not in seen:
                seen.add(key)
                analysis.schemes.append(
                    AuthSchemeObservation(
                        origin=origin,
                        scheme_type=scheme_type,
                        header_name="Authorization",
                        indicators=(f"authorization scheme {scheme_type.value}",),
                        confidence=_CONF_STRONG,
                        evidence=(
                            make_evidence(
                                EvidenceType.HTTP_HEADER,
                                "authorization: " + mask_value(_head(authorization)),
                                source="auth",
                                strength=_STRONG,
                                tool_id=ctx.bundle.tool_id,
                                detail="authorization header scheme observed",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for name, value in ctx.headers.items():
            lowered = name.lower()
            if lowered.startswith(("x-api-key", "x-auth-token", "x-access-token", "apikey", "x-tenant-key")):
                key = ("custom", lowered)
                if key in seen:
                    continue
                seen.add(key)
                analysis.schemes.append(
                    AuthSchemeObservation(
                        origin=origin,
                        scheme_type=AuthSchemeType.APIKEY,
                        header_name=name,
                        indicators=(f"{name} header observed",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                EvidenceType.HTTP_HEADER,
                                f"{name}: {mask_value(value)}",
                                source="auth",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail="custom authentication header observed",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for scheme in ctx.bundle.api_schemes:
            self._scheme_from_api(analysis, scheme, ctx, seen)

    def _scheme_from_api(self, analysis: AuthAnalysis, scheme: dict[str, object], ctx: _Context, seen: set[Any]) -> None:
        scheme_type = _api_scheme_type(scheme.get("scheme_type"))
        key = ("api", scheme_type.value)
        if key in seen:
            return
        seen.add(key)
        name = str(scheme.get("name") or "")
        analysis.schemes.append(
            AuthSchemeObservation(
                origin=ctx.origin,
                scheme_type=scheme_type,
                name=name,
                token_location=str(scheme.get("token_location") or "header"),
                documented=bool(scheme.get("documented") or False),
                indicators=(f"openapi security scheme {scheme_type.value}",),
                confidence=_CONF_STRONG,
                evidence=(
                    make_evidence(
                        EvidenceType.OPENAPI_SECURITY,
                        f"{scheme_type.value}:{name}",
                        source=str(scheme.get("source") or "api"),
                        strength=_STRONG,
                        tool_id=ctx.bundle.tool_id,
                        detail="declared OpenAPI security scheme",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )
        # OAuth/scope metadata declared in the scheme feeds scope + oauth records.
        scopes = _str_items(scheme.get("scopes"))
        flows = _str_items(scheme.get("flows"))
        if scopes or flows or scheme_type in (AuthSchemeType.OAUTH2, AuthSchemeType.OIDC):
            self._oauth_from_api(analysis, scheme, scopes, flows, ctx)
        if scheme_type == AuthSchemeType.OIDC:
            self._oidc_from_api(analysis, scheme, scopes, ctx)

    def _oauth_from_api(
        self,
        analysis: AuthAnalysis,
        scheme: dict[str, object],
        scopes: tuple[str, ...],
        flows: tuple[str, ...],
        ctx: _Context,
    ) -> None:
        if any(record.origin == ctx.origin for record in analysis.oauth):
            record = analysis.oauth[0]
            record = _with_scopes(record, scopes)
            analysis.oauth[0] = record
            return
        analysis.oauth.append(
            OAuthObservation(
                origin=ctx.origin,
                scopes=scopes,
                grant_types=flows,
                indicators=(f"openapi security scheme ({', '.join(flows) or 'oauth2'})",),
                confidence=_CONF_STRONG,
                evidence=(
                    make_evidence(
                        EvidenceType.OPENAPI_SECURITY,
                        "oauth2",
                        source="auth",
                        strength=_STRONG,
                        tool_id=ctx.bundle.tool_id,
                        detail="declared OAuth2 security scheme",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )
        for scope in scopes:
            analysis.scopes.append(
                ScopeObservation(
                    origin=ctx.origin,
                    name=scope,
                    indicators=(f"openapi security scheme scope {scope}",),
                    confidence=_CONF_STRONG,
                    evidence=(
                        make_evidence(
                            EvidenceType.OPENAPI_SECURITY,
                            scope,
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="declared OAuth scope",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    def _oidc_from_api(
        self,
        analysis: AuthAnalysis,
        scheme: dict[str, object],
        scopes: tuple[str, ...],
        ctx: _Context,
    ) -> None:
        if any(record.origin == ctx.origin for record in analysis.oidc):
            return
        analysis.oidc.append(
            OIDCObservation(
                origin=ctx.origin,
                scopes=scopes,
                indicators=("openapi oidc security scheme",),
                confidence=_CONF_STRONG,
                evidence=(
                    make_evidence(
                        EvidenceType.OPENAPI_SECURITY,
                        "oidc",
                        source="auth",
                        strength=_STRONG,
                        tool_id=ctx.bundle.tool_id,
                        detail="declared OIDC security scheme",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )

    # -- oauth ---------------------------------------------------------------

    def _detect_oauth(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        found: dict[str, str] = {}
        indicators: list[str] = []
        combined = _join(ctx)
        for pattern, key in _OAUTH_URL_PATTERNS.items():
            match = pattern.search(combined)
            if match:
                found[key] = match.group(1) or match.group(0)
                indicators.append(f"oauth {key} observed")
        if not found and not _oauth_keywords(combined):
            return
        if found:
            # OAuth endpoint URLs also surface as typed auth endpoints.
            for key, url in found.items():
                kind = _OAUTH_ENDPOINT_KIND.get(key)
                if kind is not None:
                    analysis.endpoints.append(
                        AuthEndpointObservation(
                            url=url,
                            method="GET",
                            origin=origin_of(url) or ctx.origin,
                            kind=kind,
                            documented=True,
                            indicators=(f"oauth {key}",),
                            confidence=_CONF_MODERATE,
                            evidence=(
                                make_evidence(
                                    EvidenceType.JAVASCRIPT,
                                    _bounded(url, _CONTEXT_LIMIT),
                                    source="auth",
                                    strength=_MODERATE,
                                    tool_id=ctx.bundle.tool_id,
                                    detail=f"oauth {key} discovered",
                                ),
                            ),
                            source=ctx.bundle.source,
                            tool_id=ctx.bundle.tool_id,
                            target_key=ctx.bundle.target,
                        )
                    )
        record = OAuthObservation(
            origin=ctx.origin,
            authorization_endpoint=found.get("authorization_endpoint", ""),
            token_endpoint=found.get("token_endpoint", ""),
            userinfo_endpoint=found.get("userinfo_endpoint", ""),
            issuer=found.get("issuer", ""),
            jwks_uri=found.get("jwks_uri", ""),
            client_ids=tuple(dict.fromkeys(_extract_client_ids(combined))),
            redirect_uris=tuple(dict.fromkeys(_extract_redirect_uris(combined))),
            scopes=tuple(dict.fromkeys(_extract_oauth_scopes(combined))),
            response_types=tuple(dict.fromkeys(_extract_response_types(combined))),
            grant_types=tuple(dict.fromkeys(_extract_grant_types(combined))),
            pkce=_pkce_indicated(combined),
            state_parameter=_state_indicated(combined),
            indicators=tuple(dict.fromkeys(indicators)),
            confidence=_CONF_MODERATE if found else _CONF_WEAK,
            evidence=(
                make_evidence(
                    EvidenceType.JS_INDICATOR,
                    indicators[0] if indicators else "oauth keywords present",
                    source="auth",
                    strength=_MODERATE if found else _WEAK,
                    tool_id=ctx.bundle.tool_id,
                    detail="oauth configuration observed",
                ),
            ),
            source=ctx.bundle.source,
            tool_id=ctx.bundle.tool_id,
            target_key=ctx.bundle.target,
        )
        analysis.oauth.append(record)

    # -- oidc ----------------------------------------------------------------

    def _detect_oidc(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        for document in ctx.bundle.documents:
            kind = str(document.get("kind") or "")
            if kind not in ("openid-discovery", "oidc-discovery"):
                continue
            content = document.get("content")
            if not isinstance(content, dict):
                continue
            record = OIDCObservation(
                origin=ctx.origin,
                issuer=str(content.get("issuer") or ""),
                discovery_url=str(document.get("url") or ""),
                authorization_endpoint=str(content.get("authorization_endpoint") or ""),
                token_endpoint=str(content.get("token_endpoint") or ""),
                userinfo_endpoint=str(content.get("userinfo_endpoint") or ""),
                jwks_uri=str(content.get("jwks_uri") or ""),
                scopes=tuple(str(item) for item in content.get("scopes_supported") or () if item),
                claims=tuple(str(item) for item in content.get("claims_supported") or () if item),
                response_types=tuple(str(item) for item in content.get("response_types_supported") or () if item),
                subject_types=tuple(str(item) for item in content.get("subject_types_supported") or () if item),
                id_token_signing_alg_values=tuple(
                    str(item) for item in content.get("id_token_signing_alg_values_supported") or () if item
                ),
                code_challenge_methods_supported=tuple(
                    str(item) for item in content.get("code_challenge_methods_supported") or () if item
                ),
                indicators=("valid OIDC discovery document",),
                confidence=0.95,
                evidence=(
                    make_evidence(
                        EvidenceType.OPENID_DISCOVERY,
                        str(content.get("issuer") or document.get("url") or ""),
                        source="auth",
                        strength=_STRONG,
                        tool_id=ctx.bundle.tool_id,
                        detail="valid OIDC discovery document parsed",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
            analysis.oidc.append(record)
            self._idp_from_oidc(analysis, record, ctx)
            return
        combined = _join(ctx)
        issuer = _extract_issuer(combined)
        if issuer:
            record = OIDCObservation(
                origin=ctx.origin,
                issuer=issuer,
                discovery_url=_extract_discovery_url(combined),
                indicators=("oidc issuer observed",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        EvidenceType.JS_INDICATOR,
                        issuer,
                        source="auth",
                        strength=_MODERATE,
                        tool_id=ctx.bundle.tool_id,
                        detail="oidc issuer detected in static material",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
            analysis.oidc.append(record)
            self._idp_from_oidc(analysis, record, ctx)

    def _idp_from_oidc(self, analysis: AuthAnalysis, record: OIDCObservation, ctx: _Context) -> None:
        provider = _idp_from_issuer(record.issuer)
        if any(item.issuer == record.issuer for item in analysis.identity_providers):
            return
        if provider is None:
            name = _issuer_host(record.issuer) or "identity-provider"
            analysis.identity_providers.append(
                IdPObservation(
                    name=name,
                    provider_kind=IdPKind.UNKNOWN,
                    origin=ctx.origin,
                    issuer=record.issuer,
                    discovery_url=record.discovery_url,
                    endpoints=(
                        {"type": "authorization", "url": record.authorization_endpoint},
                        {"type": "token", "url": record.token_endpoint},
                        {"type": "jwks", "url": record.jwks_uri},
                        {"type": "userinfo", "url": record.userinfo_endpoint},
                    ),
                    indicators=("oidc issuer observed",),
                    confidence=0.9,
                    evidence=(
                        make_evidence(
                            EvidenceType.OPENID_DISCOVERY,
                            record.issuer,
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="identity provider identified via OIDC issuer",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
            return
        analysis.identity_providers.append(
            IdPObservation(
                name=provider[0],
                provider_kind=provider[1],
                origin=ctx.origin,
                issuer=record.issuer,
                discovery_url=record.discovery_url,
                endpoints=(
                    {"type": "authorization", "url": record.authorization_endpoint},
                    {"type": "token", "url": record.token_endpoint},
                    {"type": "jwks", "url": record.jwks_uri},
                    {"type": "userinfo", "url": record.userinfo_endpoint},
                ),
                indicators=("oidc issuer correlates to known identity provider",),
                confidence=0.9,
                evidence=(
                    make_evidence(
                        EvidenceType.OPENID_DISCOVERY,
                        record.issuer,
                        source="auth",
                        strength=_STRONG,
                        tool_id=ctx.bundle.tool_id,
                        detail="known identity provider identified via OIDC issuer",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )

    # -- saml ----------------------------------------------------------------

    def _detect_saml(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        combined = _join(ctx)
        indicators: list[str] = []
        for token in ("samlrequest", "samlresponse", "relaystate", "assertionconsumerservice", "entityid", "md:entityid"):
            if token in combined:
                indicators.append(f"saml {token} observed")
        for document in ctx.bundle.documents:
            kind = str(document.get("kind") or "")
            if kind not in ("saml-metadata", "saml"):
                continue
            content = document.get("content")
            text = content if isinstance(content, str) else _text_of(content)
            if not text:
                continue
            entity_id = _first_match(r'entityID\s*=\s*["\']([^"\']+)', text)
            sso_url = _first_match(r'<SingleSignOnService[^>]*Location="([^"]+)"', text)
            acs_url = _first_match(r'<AssertionConsumerService[^>]*Location="([^"]+)"', text)
            metadata_url = str(document.get("url") or "")
            if entity_id or sso_url or acs_url:
                analysis.saml.append(
                    SAMLIndicatorObservation(
                        origin=ctx.origin,
                        entity_id=entity_id,
                        sso_url=sso_url,
                        acs_url=acs_url,
                        metadata_url=metadata_url,
                        indicators=("saml metadata document parsed",),
                        confidence=0.9,
                        evidence=(
                            make_evidence(
                                EvidenceType.SAML_METADATA,
                                metadata_url or entity_id,
                                source="auth",
                                strength=_STRONG,
                                tool_id=ctx.bundle.tool_id,
                                detail="safe SAML metadata extracted",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
                return
        if indicators:
            analysis.saml.append(
                SAMLIndicatorObservation(
                    origin=ctx.origin,
                    indicators=tuple(dict.fromkeys(indicators)),
                    confidence=_CONF_WEAK,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTML,
                            indicators[0],
                            source="auth",
                            strength=_WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="saml indicator observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    # -- jwt ---------------------------------------------------------------

    def _detect_jwt(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        seen: set[Any] = set()
        authorization = ctx.headers.get("authorization") or ""
        if authorization and _looks_like_bearer_jwt(authorization):
            token = _token_from_authorization(authorization)
            alg = _jwt_algorithm(token)
            key = ("authorization-header", "")
            if key not in seen:
                seen.add(key)
                analysis.jwt.append(
                    JWTIndicatorObservation(
                        origin=ctx.origin,
                        transport="authorization-header",
                        location="authorization",
                        algorithm=alg,
                        indicators=("authorization header carries a JWT-like value",),
                        confidence=0.95,
                        evidence=(
                            make_evidence(
                                EvidenceType.HTTP_HEADER,
                                "authorization: " + mask_value(token),
                                source="auth",
                                strength=_STRONG,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"JWT structure with {alg} algorithm indicator",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for cookie in ctx.cookies:
            name = str(cookie.get("name") or "")
            value = str(cookie.get("value") or "")
            if _jwt_like_cookie(name, value):
                key = ("cookie", name)
                if key in seen:
                    continue
                seen.add(key)
                analysis.jwt.append(
                    JWTIndicatorObservation(
                        origin=ctx.origin,
                        transport="cookie",
                        location=name,
                        algorithm=_jwt_algorithm(value),
                        indicators=(f"cookie '{name}' carries a JWT-like value",),
                        confidence=0.9,
                        evidence=(
                            make_evidence(
                                EvidenceType.COOKIE,
                                name,
                                source="auth",
                                strength=_STRONG,
                                tool_id=ctx.bundle.tool_id,
                                detail="JWT-like structure in cookie (value masked)",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for url, content in ctx.bundle.scripts:
            matches = _jwt_matches(content)
            for match in matches[:5]:
                key = ("script", match.group(0))
                if key in seen:
                    continue
                seen.add(key)
                analysis.jwt.append(
                    JWTIndicatorObservation(
                        origin=ctx.origin,
                        transport="static",
                        location=url,
                        indicators=("static script material carries JWT references",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                EvidenceType.JAVASCRIPT,
                                mask_value(match.group(0)),
                                source="auth",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail="JWT reference in static script material",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    # -- token storage -------------------------------------------------------

    def _detect_token_storage(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        seen: set[Any] = set()
        for url, content in ctx.bundle.scripts:
            for storage_type, patterns in _STORAGE_PATTERNS.items():
                for pattern in patterns:
                    for match in pattern.finditer(content):
                        key = (storage_type, match.group(1) or match.group(0))
                        if key in seen:
                            continue
                        seen.add(key)
                        token_category = _token_category(match.group(1) or match.group(0))
                        analysis.token_storage.append(
                            TokenStorageObservation(
                                origin=ctx.origin,
                                storage_type=storage_type,
                                context=_mask_sensitive(_clean_snippet(content, match.start()), _CONTEXT_LIMIT),
                                token_category=token_category,
                                js_asset=url,
                                indicators=(f"{storage_type.value} write for '{match.group(1) or ''}'",),
                                confidence=_CONF_STRONG,
                                evidence=(
                                    make_evidence(
                                        EvidenceType.JAVASCRIPT,
                                        match.group(1) or storage_type.value,
                                        source="auth",
                                        strength=_STRONG,
                                        tool_id=ctx.bundle.tool_id,
                                        detail=f"{storage_type.value} token storage indicator",
                                    ),
                                ),
                                source=ctx.bundle.source,
                                tool_id=ctx.bundle.tool_id,
                                target_key=ctx.bundle.target,
                            )
                        )

    # -- csrf ----------------------------------------------------------------

    def _detect_csrf(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        origin = ctx.origin
        csrf_cookies = [c for c in ctx.cookies if _csrf_cookie_name(str(c.get("name") or ""))]
        csrf_headers = [name for name in ctx.headers if _csrf_header_name(name)]
        hidden_params = _csrf_parameters(ctx.bundle.html)
        same_site = any(_samesite_of(c) == "lax" or _samesite_of(c) == "strict" for c in ctx.cookies)
        if csrf_cookies and csrf_headers:
            cookie_name = str(csrf_cookies[0].get("name") or "")
            analysis.csrf.append(
                CSRFObservation(
                    origin=origin,
                    kind=CSRFKind.DOUBLE_SUBMIT_COOKIE,
                    cookie_name=cookie_name,
                    header_name=csrf_headers[0],
                    indicators=("csrf cookie mirrored in a request header",),
                    confidence=0.9,
                    evidence=(
                        make_evidence(
                            EvidenceType.COOKIE,
                            cookie_name,
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="double-submit CSRF cookie/header pair observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
            return
        if hidden_params:
            parameter_name = hidden_params[0]
            cookie_name = str(csrf_cookies[0].get("name") or "") if csrf_cookies else ""
            analysis.csrf.append(
                CSRFObservation(
                    origin=origin,
                    kind=CSRFKind.SYNCHRONIZER_TOKEN,
                    cookie_name=str(cookie_name or ""),
                    parameter_name=parameter_name,
                    indicators=(f"hidden csrf parameter '{parameter_name}' present",),
                    confidence=0.85,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTML,
                            parameter_name,
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="synchronizer CSRF token field present",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
            return
        if csrf_cookies:
            cookie_name = str(csrf_cookies[0].get("name") or "")
            analysis.csrf.append(
                CSRFObservation(
                    origin=origin,
                    kind=CSRFKind.FRAMEWORK,
                    cookie_name=cookie_name,
                    samesite=_samesite_of(csrf_cookies[0]),
                    indicators=(f"framework csrf cookie '{cookie_name}' present",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.COOKIE,
                            cookie_name,
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="framework CSRF protection cookie observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
            return
        if csrf_headers:
            analysis.csrf.append(
                CSRFObservation(
                    origin=origin,
                    kind=CSRFKind.CUSTOM_HEADER,
                    header_name=csrf_headers[0],
                    indicators=(f"csrf header '{csrf_headers[0]}' observed",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTTP_HEADER,
                            csrf_headers[0],
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="custom CSRF header observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
            return
        if same_site:
            analysis.csrf.append(
                CSRFObservation(
                    origin=origin,
                    kind=CSRFKind.SAME_SITE,
                    indicators=("same-site cookies observed",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.COOKIE,
                            "samesite",
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="SameSite cookie control observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    # -- cors ---------------------------------------------------------------

    def _detect_cors(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        allow_origin = ctx.headers.get("access-control-allow-origin")
        allow_credentials = ctx.headers.get("access-control-allow-credentials")
        allow_methods = ctx.headers.get("access-control-allow-methods")
        allow_headers = ctx.headers.get("access-control-allow-headers")
        expose_headers = ctx.headers.get("access-control-expose-headers")
        if not any((allow_origin, allow_credentials, allow_methods, allow_headers, expose_headers)):
            return
        indicators = [
            name
            for name, _value in (
                ("access-control-allow-origin", allow_origin),
                ("access-control-allow-credentials", allow_credentials),
                ("access-control-allow-methods", allow_methods),
                ("access-control-allow-headers", allow_headers),
                ("access-control-expose-headers", expose_headers),
            )
            if _value
        ]
        analysis.cors.append(
            CORSObservation(
                origin=ctx.origin,
                allow_origin=allow_origin or "",
                allow_credentials=_true(allow_credentials),
                allow_methods=_split_list(allow_methods),
                allow_headers=_split_list(allow_headers),
                expose_headers=_split_list(expose_headers),
                preflight=ctx.status in (200, 204) and bool(allow_origin),
                indicators=tuple(indicators),
                confidence=0.95,
                evidence=(
                    make_evidence(
                        EvidenceType.HTTP_HEADER,
                        indicators[0],
                        source="auth",
                        strength=_STRONG,
                        tool_id=ctx.bundle.tool_id,
                        detail="CORS configuration headers observed",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )

    # -- mfa -----------------------------------------------------------------

    def _detect_mfa(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        combined = _join(ctx)
        lowered = combined.lower()
        for kind, tokens in _MFA_KEYWORDS.items():
            if any(token in lowered for token in tokens):
                analysis.mfa.append(
                    MFAObservation(
                        origin=ctx.origin,
                        kind=kind,
                        endpoint=ctx.bundle.url,
                        indicators=(f"mfa {kind.value} indicators present",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                EvidenceType.HTML,
                                tokens[0],
                                source="auth",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"{kind.value} MFA indicators observed",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        if _has_otp_field(ctx.bundle.html):
            analysis.mfa.append(
                MFAObservation(
                    origin=ctx.origin,
                    kind=MFAKind.UNKNOWN,
                    endpoint=ctx.bundle.url,
                    indicators=("one-time code input field present",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTML,
                            "otp input",
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="one-time password input observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        if not analysis.mfa and _mfa_keywords(combined):
            analysis.mfa.append(
                MFAObservation(
                    origin=ctx.origin,
                    kind=MFAKind.UNKNOWN,
                    endpoint=ctx.bundle.url,
                    indicators=("mfa keywords present",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTML,
                            "mfa",
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="multi-factor authentication indicators observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    # -- webauthn ------------------------------------------------------------

    def _detect_webauthn(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        seen: set[tuple[str, str]] = set()
        for url, content in ctx.bundle.scripts:
            if "navigator.credentials" not in content and "PublicKeyCredential" not in content:
                continue
            kind = "authentication"
            if "create(" in content and "PublicKeyCredential" in content:
                kind = "registration"
            key = (kind, url)
            if key in seen:
                continue
            seen.add(key)
            api = "navigator.credentials"
            analysis.webauthn.append(
                WebAuthnObservation(
                    origin=ctx.origin,
                    kind=kind,
                    api=api,
                    js_asset=url,
                    indicators=("webauthn api usage in script material",),
                    confidence=0.95,
                    evidence=(
                        make_evidence(
                            EvidenceType.JAVASCRIPT,
                            api,
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="WebAuthn credential API usage observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
            analysis.mfa.append(
                MFAObservation(
                    origin=ctx.origin,
                    kind=MFAKind.WEBAUTHN,
                    endpoint=ctx.bundle.url,
                    ui=url,
                    indicators=("webauthn credential api present",),
                    confidence=0.9,
                    evidence=(
                        make_evidence(
                            EvidenceType.JAVASCRIPT,
                            "webauthn",
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="WebAuthn acts as an MFA mechanism",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    # -- identity providers --------------------------------------------------

    def _detect_identity_providers(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        combined = _join(ctx)
        lowered = combined.lower()
        for provider, tokens in _IDP_PATTERNS.items():
            if any(token in lowered for token in tokens):
                if any(item.provider_kind == provider for item in analysis.identity_providers):
                    continue
                analysis.identity_providers.append(
                    IdPObservation(
                        name=provider.value,
                        provider_kind=provider,
                        origin=ctx.origin,
                        indicators=(f"identity provider {provider.value} indicators present",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                EvidenceType.HTML if _html_has(ctx.bundle.html, tokens) else EvidenceType.JS_INDICATOR,
                                provider.value,
                                source="auth",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail="identity provider detected via observable indicators",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
                break

    # -- roles / scopes / permissions ----------------------------------------

    def _detect_identity_models(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        seen_roles: set[str] = set()
        seen_permissions: set[str] = set()
        seen_claims: set[str] = set()
        for _url, content in ctx.bundle.scripts:
            for match in _ROLE_PATTERN.finditer(content):
                value = match.group(1) or match.group(2)
                if value and value not in seen_roles:
                    seen_roles.add(value)
                    analysis.roles.append(
                        RoleObservation(
                            origin=ctx.origin,
                            name=value,
                            indicators=("role identifier in script configuration",),
                            confidence=_CONF_MODERATE,
                            evidence=(
                                make_evidence(
                                    EvidenceType.JAVASCRIPT,
                                    value,
                                    source="auth",
                                    strength=_MODERATE,
                                    tool_id=ctx.bundle.tool_id,
                                    detail="role identifier observed in static configuration",
                                ),
                            ),
                            source=ctx.bundle.source,
                            tool_id=ctx.bundle.tool_id,
                            target_key=ctx.bundle.target,
                        )
                    )
            for match in _PERMISSION_PATTERN.finditer(content):
                value = match.group(1)
                if value and value not in seen_permissions:
                    seen_permissions.add(value)
                    analysis.permissions.append(
                        PermissionObservation(
                            origin=ctx.origin,
                            name=value,
                            indicators=("permission identifier in script configuration",),
                            confidence=_CONF_MODERATE,
                            evidence=(
                                make_evidence(
                                    EvidenceType.JAVASCRIPT,
                                    value,
                                    source="auth",
                                    strength=_MODERATE,
                                    tool_id=ctx.bundle.tool_id,
                                    detail="permission identifier observed in static configuration",
                                ),
                            ),
                            source=ctx.bundle.source,
                            tool_id=ctx.bundle.tool_id,
                            target_key=ctx.bundle.target,
                        )
                    )
            for match in _CLAIM_PATTERN.finditer(content):
                value = match.group(1)
                if value and value not in seen_claims:
                    seen_claims.add(value)
                    analysis.observations.append(
                        AuthObservation(
                            origin=ctx.origin,
                            kind=AuthObservationKind.CLAIM,
                            name=value,
                            indicators=("claim reference in static material",),
                            confidence=_CONF_MODERATE,
                            evidence=(
                                make_evidence(
                                    EvidenceType.JAVASCRIPT,
                                    value,
                                    source="auth",
                                    strength=_MODERATE,
                                    tool_id=ctx.bundle.tool_id,
                                    detail="identity claim reference observed",
                                ),
                            ),
                            source=ctx.bundle.source,
                            tool_id=ctx.bundle.tool_id,
                            target_key=ctx.bundle.target,
                        )
                    )

    # -- multi-tenancy -------------------------------------------------------

    def _detect_tenants(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        seen: set[Any] = set()
        for header_name in _TENANT_HEADERS:
            value = ctx.headers.get(header_name)
            if value:
                key = f"header|{header_name}|{value}"
                if key in seen:
                    continue
                seen.add(key)
                analysis.tenants.append(
                    TenantObservation(
                        origin=ctx.origin,
                        name=value,
                        tenant_type="header",
                        location=header_name,
                        indicators=(f"tenant header '{header_name}' observed",),
                        confidence=0.9,
                        evidence=(
                            make_evidence(
                                EvidenceType.HTTP_HEADER,
                                f"{header_name}: {mask_value(value)}",
                                source="auth",
                                strength=_STRONG,
                                tool_id=ctx.bundle.tool_id,
                                detail="tenant identifier header observed",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        combined = _join(ctx)
        lowered = combined.lower()
        for token in ("tenantid", "tenant_id", "organizationid", "org_id", "workspaceid", "workspace_id", "accountid", "account_id"):
            if token in lowered:
                value = _first_match(
                    rf"(?:{re.escape(token)})\s*[:=]\s*[\"']([^\"']+)",
                    combined,
                )
                name = value or token
                key = f"static|{token}|{name}"
                if key in seen:
                    continue
                seen.add(key)
                analysis.tenants.append(
                    TenantObservation(
                        origin=ctx.origin,
                        name=name,
                        tenant_type="unknown",
                        location="static-material",
                        indicators=(f"tenant indicator '{token}' present",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                EvidenceType.JS_INDICATOR,
                                name,
                                source="auth",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="tenant identifier referenced in static material",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    # -- session state -------------------------------------------------------

    def _detect_session_state(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        observations: list[AuthObservation] = []
        session_cookie_names = [c.name for c in analysis.cookies if c.session]
        if session_cookie_names:
            observations.append(
                AuthObservation(
                    origin=ctx.origin,
                    kind=AuthObservationKind.SESSION_STATE,
                    name="session-cookie",
                    value=",".join(sorted(session_cookie_names)),
                    detail="session cookies observed (values never stored)",
                    indicators=("session cookies present",),
                    confidence=_CONF_STRONG,
                    evidence=(
                        make_evidence(
                            EvidenceType.COOKIE,
                            ",".join(sorted(session_cookie_names)),
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="session cookie indicators observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        if ctx.status in (401, 403):
            observations.append(
                AuthObservation(
                    origin=ctx.origin,
                    kind=AuthObservationKind.SESSION_STATE,
                    name="auth-required",
                    value=str(ctx.status),
                    detail=f"http {ctx.status} indicates authentication is required",
                    indicators=("authentication challenge status observed",),
                    confidence=_CONF_STRONG,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTTP_STATUS,
                            str(ctx.status),
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="authentication-required status observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        if ctx.bundle.final_url and _logout_keywords(_path_of(ctx.bundle.final_url)):
            observations.append(
                AuthObservation(
                    origin=ctx.origin,
                    kind=AuthObservationKind.SESSION_STATE,
                    name="logout",
                    value=ctx.bundle.final_url,
                    detail="redirect to a logout surface observed",
                    indicators=("logout redirect observed",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.LOCATION,
                            ctx.bundle.final_url,
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="logout surface redirect observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        analysis.observations.extend(observations)

    # -- password policy / account lifecycle ---------------------------------

    def _detect_policies(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        lowered = ctx.html_lower
        password_indicators = [token for token in _PASSWORD_POLICY_TOKENS if token in lowered]
        if password_indicators:
            analysis.observations.append(
                AuthObservation(
                    origin=ctx.origin,
                    kind=AuthObservationKind.PASSWORD_POLICY,
                    name="password-policy",
                    value=password_indicators[0],
                    detail="documented password policy requirements observed",
                    indicators=tuple(password_indicators[:8]),
                    confidence=_CONF_WEAK,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTML,
                            password_indicators[0],
                            source="auth",
                            strength=_WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="password policy requirements documented",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        lifecycle_indicators = [token for token in _LIFECYCLE_TOKENS if token in lowered]
        if lifecycle_indicators:
            analysis.observations.append(
                AuthObservation(
                    origin=ctx.origin,
                    kind=AuthObservationKind.ACCOUNT_LIFECYCLE,
                    name="account-lifecycle",
                    value=lifecycle_indicators[0],
                    detail="account lifecycle workflow indicators observed",
                    indicators=tuple(lifecycle_indicators[:8]),
                    confidence=_CONF_WEAK,
                    evidence=(
                        make_evidence(
                            EvidenceType.HTML,
                            lifecycle_indicators[0],
                            source="auth",
                            strength=_WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="account lifecycle indicators documented",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    # -- flow modeling -------------------------------------------------------

    def _build_flows(self, analysis: AuthAnalysis, ctx: _Context) -> None:
        kinds = {endpoint.kind for endpoint in analysis.endpoints}
        if AuthEndpointKind.LOGIN in kinds:
            analysis.flows.append(
                AuthFlowObservation(
                    name="traditional-login",
                    flow_kind=FlowKind.TRADITIONAL_LOGIN,
                    origin=ctx.origin,
                    start_state=SessionState.ANONYMOUS,
                    end_state=SessionState.AUTHENTICATED,
                    steps=(
                        {"kind": "login", "state": "anonymous"},
                        {"kind": "authentication", "state": "auth-initiated"},
                        {"kind": "session", "state": "authenticated"},
                    ),
                    indicators=("login endpoint observed",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.URL_PATTERN,
                            "login",
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="traditional login flow modeled",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        oauth = analysis.oauth[0] if analysis.oauth else None
        if oauth is not None and (oauth.authorization_endpoint or oauth.token_endpoint):
            analysis.flows.append(
                AuthFlowObservation(
                    name="oauth2-authorization-code",
                    flow_kind=FlowKind.OAUTH2,
                    origin=ctx.origin,
                    start_state=SessionState.ANONYMOUS,
                    end_state=SessionState.AUTHENTICATED,
                    steps=(
                        {"kind": "authorization-endpoint", "url": oauth.authorization_endpoint},
                        {"kind": "identity-provider", "url": oauth.issuer},
                        {"kind": "callback"},
                        {"kind": "token-endpoint", "url": oauth.token_endpoint},
                        {"kind": "session", "state": "session-established"},
                    ),
                    indicators=("oauth endpoints observed",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            EvidenceType.JS_INDICATOR,
                            "oauth2",
                            source="auth",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="OAuth authorization-code flow modeled",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        oidc = analysis.oidc[0] if analysis.oidc else None
        if oidc is not None and oidc.issuer:
            analysis.flows.append(
                AuthFlowObservation(
                    name="oidc-authorization-code",
                    flow_kind=FlowKind.OIDC,
                    origin=ctx.origin,
                    start_state=SessionState.ANONYMOUS,
                    end_state=SessionState.AUTHENTICATED,
                    steps=(
                        {"kind": "authorization", "url": oidc.authorization_endpoint},
                        {"kind": "identity-provider", "url": oidc.issuer},
                        {"kind": "callback"},
                        {"kind": "token", "url": oidc.token_endpoint},
                        {"kind": "id-token"},
                        {"kind": "session", "state": "session-established"},
                    ),
                    indicators=("oidc metadata observed",),
                    confidence=0.9,
                    evidence=(
                        make_evidence(
                            EvidenceType.OPENID_DISCOVERY,
                            oidc.issuer,
                            source="auth",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="OIDC authorization-code flow modeled",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        saml = analysis.saml[0] if analysis.saml else None
        if saml is not None and (saml.sso_url or saml.acs_url or saml.indicators):
            analysis.flows.append(
                AuthFlowObservation(
                    name="saml-sso",
                    flow_kind=FlowKind.SAML,
                    origin=ctx.origin,
                    start_state=SessionState.ANONYMOUS,
                    end_state=SessionState.AUTHENTICATED,
                    steps=(
                        {"kind": "saml-request", "url": saml.sso_url},
                        {"kind": "identity-provider", "entity": saml.entity_id},
                        {"kind": "saml-assertion", "url": saml.acs_url},
                        {"kind": "session", "state": "session-established"},
                    ),
                    indicators=("saml indicators observed",),
                    confidence=_CONF_MODERATE if saml.indicators else 0.9,
                    evidence=(
                        make_evidence(
                            EvidenceType.SAML_METADATA if saml.sso_url else EvidenceType.HTML,
                            "saml",
                            source="auth",
                            strength=_STRONG if saml.sso_url else _WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="SAML SSO flow modeled",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )


# ---------------------------------------------------------------------------
# context + helpers
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Context:
    """Normalized bundle access with a shared lowercase HTML text."""

    bundle: AuthInput
    headers: dict[str, str] = field(init=False)
    cookies: list[dict[str, object]] = field(init=False)
    html_lower: str = field(init=False)
    origin: str = field(init=False)
    status: int = field(init=False)

    def __post_init__(self) -> None:
        self.headers = {name.lower(): value for name, value in self.bundle.headers}
        self.cookies = list(self.bundle.cookies)
        self.html_lower = (self.bundle.html or "").lower()
        self.origin = origin_of(self.bundle.url) or self.bundle.target
        self.status = int(self.bundle.status_code or 0)
        self.cookies = _merge_cookies(self.cookies, _cookies_from_pairs(self.bundle.headers))


# endpoint detection tables ---------------------------------------------------


def _match_endpoint_patterns(path: str) -> list[AuthEndpointKind]:
    lowered = path.lower()
    matched: list[AuthEndpointKind] = []
    for pattern, kind in _ENDPOINT_PATTERNS:
        if pattern.search(lowered) and kind not in matched:
            matched.append(kind)
    return matched


def _pattern_confidence(kind: AuthEndpointKind) -> tuple[float, EvidenceStrength]:
    if kind in (
        AuthEndpointKind.TOKEN_ENDPOINT,
        AuthEndpointKind.AUTHORIZATION_ENDPOINT,
        AuthEndpointKind.JWKS_URI,
        AuthEndpointKind.DISCOVERY_DOCUMENT,
        AuthEndpointKind.USERINFO_ENDPOINT,
        AuthEndpointKind.INTROSPECTION_ENDPOINT,
        AuthEndpointKind.REVOCATION_ENDPOINT,
    ):
        return 0.7, EvidenceStrength.MODERATE
    return 0.5, EvidenceStrength.WEAK


def _documented_endpoint(kind: AuthEndpointKind, ctx: _Context) -> bool:
    return kind in (
        AuthEndpointKind.TOKEN_ENDPOINT,
        AuthEndpointKind.AUTHORIZATION_ENDPOINT,
        AuthEndpointKind.JWKS_URI,
        AuthEndpointKind.DISCOVERY_DOCUMENT,
        AuthEndpointKind.USERINFO_ENDPOINT,
    )


def _endpoints_from_html(html: str, base_url: str) -> list[AuthEndpointObservation]:
    """Extract auth endpoint candidates from HTML forms."""
    results: list[AuthEndpointObservation] = []
    for match in _FORM_ACTION_PATTERN.finditer(html):
        action = (match.group(1) or "").strip()
        if not action or action.startswith("#") or action.lower() in ("javascript:void(0)", "javascript:;"):
            continue
        url = _resolve_url(action, base_url)
        lowered = action.lower()
        kind = AuthEndpointKind.UNKNOWN
        if _login_keywords(lowered) and "logout" not in lowered:
            kind = AuthEndpointKind.LOGIN
        elif _registration_keywords(lowered):
            kind = AuthEndpointKind.REGISTRATION
        elif _reset_keywords(lowered):
            kind = AuthEndpointKind.PASSWORD_RESET
        elif "logout" in lowered or "signout" in lowered:
            kind = AuthEndpointKind.LOGOUT
        if kind is AuthEndpointKind.UNKNOWN:
            continue
        results.append(
            AuthEndpointObservation(
                url=url,
                method="POST",
                kind=kind,
                indicators=(f"form action: {action}",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        EvidenceType.HTML,
                        action,
                        source="auth",
                        strength=_MODERATE,
                        tool_id="",
                        detail="auth form action observed",
                    ),
                ),
            )
        )
    return results


# keyword matchers ------------------------------------------------------------


def _login_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("login", "sign in", "signin", "log in", "logon"))


def _logout_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("logout", "sign out", "signout"))


def _registration_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("sign up", "signup", "register", "create account", "createaccount"))


def _reset_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("reset password", "forgot password", "forgotpassword", "password reset"))


def _mfa_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("two-factor", "2fa", "multi-factor", "mfa", "authenticator", "otp", "totp"))


def _sso_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("single sign-on", "single sign on", "sso", "sign in with", "login with"))


def _oauth_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in ("oauth", "client_id", "clientid", "grant_type", "response_type", "redirect_uri"))


def _has_password_field(html: str) -> bool:
    return bool(re.search(r'<input[^>]*type\s*=\s*["\']?password', html, re.IGNORECASE))


def _has_otp_field(html: str) -> bool:
    lowered = html.lower()
    return any(
        re.search(rf'name\s*=\s*["\']{token}["\']', lowered, re.IGNORECASE)
        for token in ("otp", "totp", "mfa_code", "mfa-code", "verification_code")
    )


def _html_has(html: str, tokens: Sequence[str]) -> bool:
    lowered = html.lower()
    return any(token in lowered for token in tokens)


def _csrf_cookie_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ("csrf", "xsrf", "csrftoken"))


def _csrf_header_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ("x-csrf", "x-xsrf", "csrf-token", "x-csrf-token"))


def _csrf_parameters(html: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r'name\s*=\s*["\']([^"\']*)["\']', html, re.IGNORECASE):
        name = match.group(1).lower()
        if any(token in name for token in ("csrf", "xsrf", "_token", "requestverificationtoken")) and name not in names:
            names.append(name)
    return names


def _www_authenticate_scheme(value: str) -> AuthSchemeType:
    lowered = value.lower()
    if lowered.startswith("bearer"):
        return AuthSchemeType.BEARER
    if lowered.startswith("basic"):
        return AuthSchemeType.BASIC
    if lowered.startswith("digest"):
        return AuthSchemeType.DIGEST
    return AuthSchemeType.CUSTOM


def _authorization_scheme(value: str) -> AuthSchemeType:
    lowered = value.strip().lower()
    if lowered.startswith("bearer"):
        return AuthSchemeType.BEARER
    if lowered.startswith("basic"):
        return AuthSchemeType.BASIC
    if lowered.startswith("digest"):
        return AuthSchemeType.DIGEST
    if lowered.startswith("dpop"):
        return AuthSchemeType.DPOF
    return AuthSchemeType.CUSTOM


def _api_scheme_type(value: object) -> AuthSchemeType:
    name = str(value or "").lower()
    mapping = {
        "basic": AuthSchemeType.BASIC,
        "bearer": AuthSchemeType.BEARER,
        "apikey": AuthSchemeType.APIKEY,
        "api_key": AuthSchemeType.APIKEY,
        "digest": AuthSchemeType.DIGEST,
        "oauth2": AuthSchemeType.OAUTH2,
        "oidc": AuthSchemeType.OIDC,
        "openid": AuthSchemeType.OIDC,
        "mutual-tls": AuthSchemeType.CUSTOM,
        "session": AuthSchemeType.SESSION,
        "cookie": AuthSchemeType.COOKIE,
        "none": AuthSchemeType.NONE,
    }
    return mapping.get(name, AuthSchemeType.UNKNOWN)


def _looks_like_bearer_jwt(authorization: str) -> bool:
    token = _token_from_authorization(authorization)
    return bool(_JWT_STRUCTURE.match(token))


def _token_from_authorization(authorization: str) -> str:
    parts = authorization.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else authorization.strip()


def _jwt_like_cookie(name: str, value: str) -> bool:
    lowered = name.lower()
    if _JWT_STRUCTURE.match(value):
        return True
    return any(token in lowered for token in ("jwt", "token", "auth")) and _JWT_STRUCTURE.match(value) is None


def _jwt_algorithm(token: str) -> str:
    """Safely infer the JWT algorithm indicator from the (non-secret) header."""
    try:
        header = token.split(".")[0]
        padding = "=" * (-len(header) % 4)
        decoded = json.loads(__import__("base64").urlsafe_b64decode(header + padding))
        if isinstance(decoded, dict):
            return str(decoded.get("alg") or "")
    except (ValueError, TypeError, KeyError, __import__("json").JSONDecodeError):
        pass
    return ""


def _jwt_matches(content: str) -> list[re.Match[str]]:
    return list(_JWT_STRUCTURE.finditer(content))


def _samesite_of(cookie: dict[str, object]) -> str:
    value = str(cookie.get("samesite") or cookie.get("same_site") or "").lower()
    return value if value in ("strict", "lax", "none") else ""


def _cookies_from_headers(headers: dict[str, str]) -> list[dict[str, object]]:
    """Parse ``Set-Cookie`` header values into cookie attribute tables.

    Only metadata is retained; the cookie value is never stored anywhere.
    """
    return _cookies_from_pairs(tuple(headers.items()))


def _cookies_from_pairs(pairs: tuple[tuple[str, str], ...]) -> list[dict[str, object]]:
    """Parse every ``Set-Cookie`` header from the original header pairs."""
    cookies: list[dict[str, object]] = []
    for name, value in pairs:
        if name.lower() != "set-cookie" or not value:
            continue
        cookie = _parse_set_cookie(value)
        if cookie:
            cookies.append(cookie)
    return cookies


def _parse_set_cookie(value: str) -> dict[str, object] | None:
    """Parse a single ``Set-Cookie`` header value into an attribute table."""
    parts = [part.strip() for part in value.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, raw_value = parts[0].split("=", 1)
    cookie: dict[str, object] = {"name": name.strip(), "value": ""}
    for part in parts[1:]:
        if not part:
            continue
        key, _, attr_value = part.partition("=")
        key = key.strip().lower()
        attr_value = attr_value.strip().strip('"')
        if key in ("domain", "path", "expires", "max-age", "priority"):
            cookie[key] = attr_value
        elif key == "samesite":
            cookie["samesite"] = attr_value.lower()
        elif key in ("secure", "httponly", "partitioned"):
            cookie[key] = True
    return cookie


def _merge_cookies(existing: list[dict[str, object]], parsed: list[dict[str, object]]) -> list[dict[str, object]]:
    """Merge parsed Set-Cookie tables with pre-parsed cookies (deduped by name)."""
    seen: set[str] = {str(cookie.get("name") or "") for cookie in existing if cookie.get("name")}
    merged = list(existing)
    for cookie in parsed:
        name = str(cookie.get("name") or "")
        if name in seen:
            continue
        seen.add(name)
        merged.append(cookie)
    return merged


def _true(value: str | None) -> bool:
    return bool(value and value.strip().lower() == "true")


def _split_list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _head(value: str, limit: int = 64) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[:limit] + "…"


def _bounded(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


def _path_of(url: str) -> str:
    if "://" not in url:
        return url
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).path
    except ValueError:
        return url


def _resolve_url(value: str, base_url: str) -> str:
    from urllib.parse import urljoin

    try:
        return urljoin(base_url or "https://example.invalid/", value)
    except ValueError:
        return value


def _clean_snippet(content: str, start: int, radius: int = 80) -> str:
    snippet = content[max(0, start - radius): start + radius]
    return " ".join(snippet.split())


def _str_items(value: object) -> tuple[str, ...]:
    """Coerce a value into a tuple of strings (empty for non-iterables)."""
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in value if item is not None)
    return ()


def _mask_sensitive(text: str, limit: int) -> str:
    """Mask token-like material in a context snippet before retention."""
    masked = _JWT_STRUCTURE.sub("<masked>", text)
    masked = _TOKEN_LITERAL.sub("'<masked>'", masked)
    return _bounded(masked, limit)


def _join(ctx: _Context) -> str:
    parts = [ctx.bundle.url, ctx.bundle.final_url, ctx.bundle.html, *ctx.bundle.observed_urls]
    for url, content in ctx.bundle.scripts:
        parts.append(url)
        if content:
            parts.append(_bounded(content, 4096))
    return " ".join(part for part in parts if part)


def _surface_confidence(indicators: list[str]) -> float:
    unique = len(set(indicators))
    if unique >= 3:
        return 0.8
    if unique == 2:
        return 0.65
    return 0.5


def _text_of(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return json.dumps(value)
    return str(value)


def _with_scopes(record: OAuthObservation, scopes: tuple[str, ...]) -> OAuthObservation:
    from dataclasses import replace

    return replace(record, scopes=tuple(dict.fromkeys((*record.scopes, *scopes))))


def _token_category(key: str) -> str:
    lowered = key.lower()
    if "refresh" in lowered:
        return "refresh-token"
    if "access" in lowered:
        return "access-token"
    if "id_token" in lowered or "idtoken" in lowered:
        return "id-token"
    if "apikey" in lowered or "api_key" in lowered:
        return "api-key"
    return "unknown"


def _cookie_observation(name: str, cookie: dict[str, object], ctx: _Context) -> AuthCookieObservation:
    """Map a parsed cookie table onto a canonical cookie observation (metadata only)."""
    domain = str(cookie.get("domain") or "")
    path = str(cookie.get("path") or "")
    samesite = _samesite_of(cookie)
    max_age = str(cookie.get("max_age") or cookie.get("max-age") or "")
    expires = str(cookie.get("expires") or "")
    priority = str(cookie.get("priority") or "")
    prefix = ""
    if name.startswith("__Host-"):
        prefix = "__Host-"
    elif name.startswith("__Secure-"):
        prefix = "__Secure-"
    session = not (max_age or expires)
    indicators: list[str] = []
    for flag in ("secure", "httponly", "partitioned"):
        if bool(cookie.get(flag) or cookie.get(flag.lower())):
            indicators.append(flag)
    if samesite:
        indicators.append(f"samesite={samesite}")
    if prefix:
        indicators.append(f"prefix={prefix}")
    if session:
        indicators.append("session")
    else:
        indicators.append("persistent")
    strength = _STRONG if session or samesite or prefix else _MODERATE
    return AuthCookieObservation(
        name=name,
        origin=ctx.origin,
        domain=domain,
        path=path,
        secure=bool(cookie.get("secure") or False),
        httponly=bool(cookie.get("httponly") or cookie.get("http_only") or False),
        partitioned=bool(cookie.get("partitioned") or False),
        samesite=samesite or "unknown",
        max_age=max_age,
        expires=expires,
        priority=priority,
        prefix=prefix,
        session=session,
        persistent=not session,
        indicators=tuple(dict.fromkeys(indicators)),
        confidence=0.95 if strength == _STRONG else 0.7,
        evidence=(
            make_evidence(
                EvidenceType.COOKIE,
                name,
                source="auth",
                strength=strength,
                tool_id=ctx.bundle.tool_id,
                detail="cookie security attributes observed (value never stored)",
            ),
        ),
        source=ctx.bundle.source,
        tool_id=ctx.bundle.tool_id,
        target_key=ctx.bundle.target,
    )


def _idp_from_issuer(issuer: str) -> tuple[str, IdPKind] | None:
    lowered = issuer.lower()
    for needle, name, kind in (
        ("auth0.com", "Auth0", IdPKind.AUTH0),
        ("okta.com", "Okta", IdPKind.OKTA),
        ("keycloak", "Keycloak", IdPKind.KEYCLOAK),
        ("login.microsoftonline.com", "Microsoft Entra ID", IdPKind.AZURE_AD),
        ("login.microsoft.com", "Microsoft Entra ID", IdPKind.AZURE_AD),
        ("accounts.google.com", "Google Identity", IdPKind.GOOGLE),
        ("cognito", "AWS Cognito", IdPKind.AWS_COGNITO),
        ("amazoncognito.com", "AWS Cognito", IdPKind.AWS_COGNITO),
        ("firebaseapp.com", "Firebase Auth", IdPKind.FIREBASE),
        ("identitytoolkit", "Firebase Auth", IdPKind.FIREBASE),
        ("supabase.co", "Supabase Auth", IdPKind.SUPABASE),
        ("github.com", "GitHub", IdPKind.GITHUB),
        ("gitlab.com", "GitLab", IdPKind.GITLAB),
        ("pingidentity.com", "Ping Identity", IdPKind.PING),
    ):
        if needle in lowered:
            return name, kind
    return None


def _issuer_host(issuer: str) -> str:
    """Return the host part of an issuer URL (``""`` when unparseable)."""
    if "://" not in issuer:
        return issuer
    try:
        from urllib.parse import urlsplit

        return urlsplit(issuer).netloc
    except ValueError:
        return issuer


def _extract_client_ids(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r'(?:client_id|clientId)\s*[:=]\s*["\']([A-Za-z0-9._-]{4,128})["\']', text, re.IGNORECASE):
        value = match.group(1)
        if value not in values:
            values.append(value)
    return values


def _extract_redirect_uris(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r'(?:redirect_uri|redirectUri|redirect_url)\s*[:=]\s*["\']([^"\']+)["\']', text, re.IGNORECASE):
        value = match.group(1)
        if value not in values:
            values.append(value)
    return values


def _extract_oauth_scopes(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r'(?:scope|scopes)\s*[:=]\s*["\']([^"\']+)["\']', text, re.IGNORECASE):
        for value in match.group(1).split():
            if value not in values:
                values.append(value)
    return values


def _extract_response_types(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r'(?:response_type|responseType)\s*[:=]\s*["\']([^"\']+)["\']', text, re.IGNORECASE):
        for value in match.group(1).split():
            if value not in values:
                values.append(value)
    return values


def _extract_grant_types(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r'(?:grant_type|grantType)\s*[:=]\s*["\']([^"\']+)["\']', text, re.IGNORECASE):
        value = match.group(1)
        if value not in values:
            values.append(value)
    return values


def _pkce_indicated(text: str) -> bool:
    lowered = text.lower()
    return "code_challenge" in lowered or "codechallenge" in lowered or "pkce" in lowered


def _state_indicated(text: str) -> bool:
    lowered = text.lower()
    return re.search(r"\bstate\b", lowered) is not None


def _extract_issuer(text: str) -> str:
    match = re.search(r'(?:issuer|iss)\s*[:=]\s*["\'](https?://[^"\']+)["\']', text, re.IGNORECASE)
    return match.group(1) if match else ""


def _extract_discovery_url(text: str) -> str:
    match = re.search(r'(https?://[^"\'\s]+\.well-known/openid-configuration)', text, re.IGNORECASE)
    return match.group(1) if match else ""


def _first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# static detection tables
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS: list[tuple[re.Pattern[str], AuthEndpointKind]] = [
    (re.compile(r"/login(?:/|$|\?)"), AuthEndpointKind.LOGIN),
    (re.compile(r"/signin(?:/|$|\?)"), AuthEndpointKind.LOGIN),
    (re.compile(r"/logon(?:/|$|\?)"), AuthEndpointKind.LOGIN),
    (re.compile(r"/logout(?:/|$|\?)"), AuthEndpointKind.LOGOUT),
    (re.compile(r"/signout(?:/|$|\?)"), AuthEndpointKind.LOGOUT),
    (re.compile(r"/signup(?:/|$|\?)"), AuthEndpointKind.REGISTRATION),
    (re.compile(r"/register(?:/|$|\?)"), AuthEndpointKind.REGISTRATION),
    (re.compile(r"/reset-password(?:/|$|\?)"), AuthEndpointKind.PASSWORD_RESET),
    (re.compile(r"/forgot-password(?:/|$|\?)"), AuthEndpointKind.PASSWORD_RESET),
    (re.compile(r"/forgotpassword(?:/|$|\?)"), AuthEndpointKind.PASSWORD_RESET),
    (re.compile(r"/password/reset"), AuthEndpointKind.PASSWORD_RESET),
    (re.compile(r"/change-password(?:/|$|\?)"), AuthEndpointKind.PASSWORD_CHANGE),
    (re.compile(r"/password/change"), AuthEndpointKind.PASSWORD_CHANGE),
    (re.compile(r"/verify-email(?:/|$|\?)"), AuthEndpointKind.EMAIL_VERIFICATION),
    (re.compile(r"/email/verify"), AuthEndpointKind.EMAIL_VERIFICATION),
    (re.compile(r"/activate(?:/|$|\?)"), AuthEndpointKind.ACCOUNT_VERIFICATION),
    (re.compile(r"/account/verify"), AuthEndpointKind.ACCOUNT_VERIFICATION),
    (re.compile(r"/account/recovery"), AuthEndpointKind.ACCOUNT_RECOVERY),
    (re.compile(r"/recovery(?:/|$|\?)"), AuthEndpointKind.ACCOUNT_RECOVERY),
    (re.compile(r"/mfa(?:/|$|\?)"), AuthEndpointKind.MFA_CHALLENGE),
    (re.compile(r"/2fa(?:/|$|\?)"), AuthEndpointKind.MFA_CHALLENGE),
    (re.compile(r"/otp(?:/|$|\?)"), AuthEndpointKind.MFA_CHALLENGE),
    (re.compile(r"/totp(?:/|$|\?)"), AuthEndpointKind.MFA_ENROLLMENT),
    (re.compile(r"/authenticator(?:/|$|\?)"), AuthEndpointKind.MFA_ENROLLMENT),
    (re.compile(r"/enroll-mfa"), AuthEndpointKind.MFA_ENROLLMENT),
    (re.compile(r"/authorize(?:/|$|\?)"), AuthEndpointKind.AUTHORIZATION_ENDPOINT),
    (re.compile(r"/oauth/authorize"), AuthEndpointKind.AUTHORIZATION_ENDPOINT),
    (re.compile(r"/token(?:/|$|\?)"), AuthEndpointKind.TOKEN_ENDPOINT),
    (re.compile(r"/oauth/token"), AuthEndpointKind.TOKEN_ENDPOINT),
    (re.compile(r"/oauth2/token"), AuthEndpointKind.TOKEN_ENDPOINT),
    (re.compile(r"/revoke(?:/|$|\?)"), AuthEndpointKind.REVOCATION_ENDPOINT),
    (re.compile(r"/introspect(?:/|$|\?)"), AuthEndpointKind.INTROSPECTION_ENDPOINT),
    (re.compile(r"/userinfo(?:/|$|\?)"), AuthEndpointKind.USERINFO_ENDPOINT),
    (re.compile(r"/jwks(?:/|$|\?)"), AuthEndpointKind.JWKS_URI),
    (re.compile(r"\.well-known/openid-configuration"), AuthEndpointKind.DISCOVERY_DOCUMENT),
    (re.compile(r"/callback(?:/|$|\?)"), AuthEndpointKind.AUTH_CALLBACK),
    (re.compile(r"/oauth/callback"), AuthEndpointKind.AUTHORIZATION_CALLBACK),
    (re.compile(r"/sso(?:/|$|\?)"), AuthEndpointKind.SSO_ENTRYPOINT),
    (re.compile(r"/saml(?:/|$|\?)"), AuthEndpointKind.SSO_ENTRYPOINT),
    (re.compile(r"/saml/acs"), AuthEndpointKind.ACS),
    (re.compile(r"/slo(?:/|$|\?)"), AuthEndpointKind.SLO),
    (re.compile(r"/refresh(?:/|$|\?)"), AuthEndpointKind.TOKEN_REFRESH),
    (re.compile(r"/session/refresh"), AuthEndpointKind.SESSION_REFRESH),
]

_FORM_ACTION_PATTERN = re.compile(r'<form[^>]*action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

_JWT_STRUCTURE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}")

#: Quoted token-like literals (long mixed alnum/`._-=` strings) inside context.
_TOKEN_LITERAL = re.compile(r"['\"][A-Za-z0-9+/_\-\.]{16,}=*['\"]")

_STORAGE_PATTERNS: dict[TokenStorageType, tuple[re.Pattern[str], ...]] = {
    TokenStorageType.LOCAL_STORAGE: (
        re.compile(r"localStorage\s*\.\s*setItem\s*\(\s*[\"']([^\"']+)[\"']"),
        re.compile(r"localStorage\s*\[\s*[\"']([^\"']+)[\"']\s*\]"),
    ),
    TokenStorageType.SESSION_STORAGE: (
        re.compile(r"sessionStorage\s*\.\s*setItem\s*\(\s*[\"']([^\"']+)[\"']"),
        re.compile(r"sessionStorage\s*\[\s*[\"']([^\"']+)[\"']\s*\]"),
    ),
    TokenStorageType.INDEXED_DB: (
        re.compile(r"indexedDB|IDBDatabase|IDBObjectStore"),
    ),
    TokenStorageType.COOKIE: (
        re.compile(r"document\s*\.\s*cookie\s*=\s*[\"'][^\"']*([A-Za-z0-9_:-]+)[\"']"),
    ),
}

_MFA_KEYWORDS: dict[MFAKind, tuple[str, ...]] = {
    MFAKind.TOTP: ("authenticator app", "google authenticator", "totp", "time-based one-time"),
    MFAKind.SMS_OTP: ("sms code", "text message code", "via text", "sms verification"),
    MFAKind.EMAIL_OTP: ("email code", "email verification code", "sent to your email"),
    MFAKind.PUSH: ("push notification", "approve sign-in", "approve login"),
    MFAKind.RECOVERY_CODES: ("recovery code", "backup code", "recovery codes"),
}

_IDP_PATTERNS: dict[IdPKind, tuple[str, ...]] = {
    IdPKind.AUTH0: ("auth0", "auth0.com"),
    IdPKind.OKTA: ("okta", "okta.com"),
    IdPKind.KEYCLOAK: ("keycloak",),
    IdPKind.AZURE_AD: ("microsoft entra", "azure ad", "login.microsoftonline.com", "login.microsoft.com", "sign in with microsoft"),
    IdPKind.GOOGLE: ("accounts.google.com", "sign in with google", "login with google"),
    IdPKind.AWS_COGNITO: ("amazon cognito", "cognito", "cognito-idp"),
    IdPKind.FIREBASE: ("firebase", "firebaseauth", "identitytoolkit"),
    IdPKind.SUPABASE: ("supabase", "supabase.co/auth"),
    IdPKind.GITHUB: ("sign in with github", "login with github", "github oauth"),
    IdPKind.GITLAB: ("sign in with gitlab", "login with gitlab", "gitlab oauth"),
    IdPKind.PING: ("pingidentity.com",),
}

_ROLE_PATTERN = re.compile(r"(?:role|roles)\s*[:=]\s*[\"'][\"']([^\"']+)[\"']|(?:role|roles)\s*[:=]\s*\[\s*[\"']([^\"']+)[\"']")
_PERMISSION_PATTERN = re.compile(r"permissions?\s*[:=]\s*\[\s*[\"']([^\"']+)[\"']")
_CLAIM_PATTERN = re.compile(r"(?:claim|claims)\s*[:=]\s*\[\s*[\"']([^\"']+)[\"']")

_TENANT_HEADERS = (
    "x-tenant-id",
    "x-tenant",
    "x-organization-id",
    "x-org-id",
    "x-workspace-id",
    "x-account-id",
    "x-tenant-key",
)

_OAUTH_URL_PATTERNS: dict[re.Pattern[str], str] = {
    re.compile(r"(?:authorization_endpoint|authorizationUrl|authorization_url|authUrl)\s*[:=]\s*[\"']([^\"']+)[\"']"): "authorization_endpoint",
    re.compile(r"(?:token_endpoint|tokenUrl|token_url)\s*[:=]\s*[\"']([^\"']+)[\"']"): "token_endpoint",
    re.compile(r"(?:userinfo_endpoint|userInfoEndpoint)\s*[:=]\s*[\"']([^\"']+)[\"']"): "userinfo_endpoint",
    re.compile(r"(?:jwks_uri|jwksUri)\s*[:=]\s*[\"']([^\"']+)[\"']"): "jwks_uri",
    re.compile(r"(?:issuer|iss)\s*[:=]\s*[\"'](https?://[^\"']+)[\"']"): "issuer",
}

_OAUTH_ENDPOINT_KIND: dict[str, AuthEndpointKind] = {
    "authorization_endpoint": AuthEndpointKind.AUTHORIZATION_ENDPOINT,
    "token_endpoint": AuthEndpointKind.TOKEN_ENDPOINT,
    "userinfo_endpoint": AuthEndpointKind.USERINFO_ENDPOINT,
    "jwks_uri": AuthEndpointKind.JWKS_URI,
}

_PASSWORD_POLICY_TOKENS = (
    "minimum 8 characters",
    "at least 8 characters",
    "must contain",
    "uppercase",
    "lowercase",
    "special character",
    "at least one number",
    "password requirements",
    "must be at least",
)

_LIFECYCLE_TOKENS = (
    "account locked",
    "too many attempts",
    "try again later",
    "unlock your account",
    "verify your email",
    "activate your account",
    "resend verification",
    "check your inbox",
    "account suspended",
)
