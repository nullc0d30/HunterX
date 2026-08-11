# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB authentication-intelligence entities.

Mirrors ``hunterx.domain.entities.tidb.auth_intelligence`` one-to-one. Every
model carries the shared TIDB envelope via :class:`TidbModelMixin` plus the
canonical authentication-inventory columns. No model stores raw credentials,
token values or session-cookie values — only metadata and masked indicators.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class AuthRunModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthRun`."""

    __tablename__ = "tidb_auth_runs"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="hybrid")
    surfaces: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoints: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    identity_providers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    oauth_configs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    oidc_configs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    saml_configs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    schemes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cookies: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mfa: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthSurfaceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthSurface`."""

    __tablename__ = "tidb_auth_surfaces"

    url: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    surface_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    access_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthEndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthEndpoint`."""

    __tablename__ = "tidb_auth_endpoints"

    url: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_auth_endpoints_url_kind", "url", "kind"),
    )


class AuthFlowModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthFlow`."""

    __tablename__ = "tidb_auth_flows"

    name: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    flow_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="custom", index=True)
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    start_state: Mapped[str] = mapped_column(String(32), nullable=False, default="anonymous")
    end_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    steps: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class IdentityProviderModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.IdentityProvider`."""

    __tablename__ = "tidb_identity_providers"

    name: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    provider_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    discovery_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    endpoints: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class OAuthConfigModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.OAuthConfig`."""

    __tablename__ = "tidb_oauth_configs"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    authorization_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    token_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    revocation_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    introspection_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    userinfo_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    issuer: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    jwks_uri: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    client_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    response_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    grant_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    pkce: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    state_parameter: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class OIDCConfigModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.OIDCConfig`."""

    __tablename__ = "tidb_oidc_configs"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    discovery_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    authorization_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    token_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    userinfo_endpoint: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    jwks_uri: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    claims: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    response_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    subject_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    id_token_signing_alg_values: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    code_challenge_methods_supported: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class SAMLConfigModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.SAMLConfig`."""

    __tablename__ = "tidb_saml_configs"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    entity_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    sso_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    acs_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    metadata_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    idp_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    sp_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    relay_state: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthSchemeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthScheme`."""

    __tablename__ = "tidb_auth_schemes"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    scheme_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    token_location: Mapped[str] = mapped_column(String(32), nullable=False, default="header")
    header_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_auth_schemes_origin_type", "origin", "scheme_type"),
    )


class AuthCookieModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthCookie`."""

    __tablename__ = "tidb_auth_cookies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    path: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    secure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    httponly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    partitioned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    samesite: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    max_age: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    expires: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    priority: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    prefix: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    session: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    persistent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_auth_cookies_name_origin", "name", "origin"),
    )


class TokenStorageIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.TokenStorageIndicator`."""

    __tablename__ = "tidb_token_storage_indicators"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    storage_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    token_category: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    js_asset: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CSRFMechanismModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.CSRFMechanism`."""

    __tablename__ = "tidb_csrf_mechanisms"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cookie_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    header_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    parameter_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    samesite: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class CORSPolicyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.CORSPolicy`."""

    __tablename__ = "tidb_cors_policies"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    allow_origin: Mapped[str] = mapped_column(Text, nullable=False, default="")
    allow_credentials: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_methods: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allow_headers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expose_headers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    preflight: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class MFAMechanismModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.MFAMechanism`."""

    __tablename__ = "tidb_mfa_mechanisms"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ui: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class WebAuthnIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.WebAuthnIndicator`."""

    __tablename__ = "tidb_webauthn_indicators"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    api: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    js_asset: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    challenge_ref: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class RoleIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.RoleIndicator`."""

    __tablename__ = "tidb_role_indicators"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class ScopeIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.ScopeIndicator`."""

    __tablename__ = "tidb_scope_indicators"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class PermissionIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.PermissionIndicator`."""

    __tablename__ = "tidb_permission_indicators"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    resource: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class TenantIndicatorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.TenantIndicator`."""

    __tablename__ = "tidb_tenant_indicators"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    tenant_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    location: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    api_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.3)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class AuthObservationModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthObservation`."""

    __tablename__ = "tidb_auth_observations"

    origin: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    indicators: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.4)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_auth_observations_origin_kind", "origin", "kind"),
    )


class AuthEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthEvidence`."""

    __tablename__ = "tidb_auth_evidence"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="observation", index=True)
    subject_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="auth")
    strength: Mapped[str] = mapped_column(String(16), nullable=False, default="moderate")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_auth_evidence_subject", "subject_type", "subject_id"),
    )


class AuthChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.auth_intelligence.AuthChange`."""

    __tablename__ = "tidb_auth_changes"

    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, default="surface")
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, default="changed")
    previous: Mapped[str] = mapped_column(Text, nullable=False, default="")
    current: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_auth_changes_subject_type", "subject_type", "subject"),
    )
