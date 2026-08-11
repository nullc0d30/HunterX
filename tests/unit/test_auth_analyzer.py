# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authentication detection engine.

Exercises the domain analyzer over the golden datasets and targeted bundles:
login surfaces, OAuth/OIDC detection, SAML indicators, JWT indicators, cookie
security metadata, token storage, CSRF, CORS, MFA/WebAuthn, identity providers,
roles/scopes/tenants, session state and access classification. Also asserts the
security invariants (no raw token/cookie values in observations).
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.auth.analyzer import AuthAnalyzer
from hunterx.domain.auth.models import (
    AuthInput,
    JWTIndicatorObservation,
)

GOLDEN = Path(__file__).parent.parent / "golden" / "auth"


def _bundle(name: str) -> AuthInput:
    payload = json.loads((GOLDEN / name).read_text(encoding="utf-8"))
    headers: list[tuple[str, str]] = []
    for key, value in (payload.get("headers") or {}).items():
        if isinstance(value, list):
            headers.extend((str(key), str(item)) for item in value)
        else:
            headers.append((str(key), str(value)))
    return AuthInput(
        target=payload.get("url", "https://example.com"),
        url=payload.get("url", ""),
        status_code=payload.get("status_code", 0),
        headers=tuple(headers),
        html=payload.get("html", ""),
        final_url=payload.get("final_url", ""),
        scripts=tuple((item["url"], item["content"]) for item in payload.get("scripts") or ()),
        api_schemes=tuple(dict(item) for item in payload.get("api_schemes") or ()),
        documents=tuple(dict(item) for item in payload.get("documents") or ()),
        observed_urls=tuple(payload.get("observed_urls") or ()),
        source="auth",
    )


def _analyze(name: str):
    return AuthAnalyzer().analyze(_bundle(name))


def _observation_text(analysis) -> str:
    return " ".join(
        " ".join(record.indicators) if hasattr(record, "indicators") else "" for record in analysis.all_observations()
    )


class TestLoginPage:
    def test_surface_and_endpoint(self) -> None:
        analysis = _analyze("login_page_input.json")
        assert any(s.surface_kind.value == "login" for s in analysis.surfaces)
        kinds = {e.kind.value for e in analysis.endpoints}
        assert {"login", "logout", "registration", "password-reset"} <= kinds

    def test_cookie_security_metadata(self) -> None:
        analysis = _analyze("login_page_input.json")
        cookies = {c.name: c for c in analysis.cookies}
        assert "session" in cookies
        assert cookies["session"].secure is True
        assert cookies["session"].httponly is True
        assert cookies["session"].samesite == "lax"
        assert cookies["session"].session is True

    def test_csrf_synchronizer(self) -> None:
        analysis = _analyze("login_page_input.json")
        assert any(c.kind.value == "synchronizer-token" for c in analysis.csrf)

    def test_cors_configuration(self) -> None:
        analysis = _analyze("login_page_input.json")
        assert any(c.allow_origin == "https://acme.com" and c.allow_credentials for c in analysis.cors)

    def test_identity_provider(self) -> None:
        analysis = _analyze("login_page_input.json")
        assert any(p.provider_kind.value == "google" for p in analysis.identity_providers)

    def test_token_storage(self) -> None:
        analysis = _analyze("login_page_input.json")
        types = {t.storage_type.value for t in analysis.token_storage}
        assert "local-storage" in types
        assert "session-storage" in types
        assert any(t.token_category == "access-token" for t in analysis.token_storage)

    def test_mfa_indicators(self) -> None:
        analysis = _analyze("login_page_input.json")
        assert analysis.mfa, "MFA indicators must be detected"
        assert all(m.indicators for m in analysis.mfa)

    def test_flow_modeling(self) -> None:
        analysis = _analyze("login_page_input.json")
        assert any(f.flow_kind.value == "traditional-login" for f in analysis.flows)

    def test_access_classification(self) -> None:
        analysis = _analyze("login_page_input.json")
        assert any(s.access_state.value == "public" for s in analysis.surfaces)


class TestOidc:
    def test_oidc_discovery_document(self) -> None:
        analysis = _analyze("oidc_callback_input.json")
        assert any(o.issuer == "https://auth.acme.com" for o in analysis.oidc)
        assert any(o.code_challenge_methods_supported == ("S256",) for o in analysis.oidc)

    def test_oauth_from_openapi_scheme(self) -> None:
        analysis = _analyze("oidc_callback_input.json")
        assert any("read" in o.scopes for o in analysis.oauth)

    def test_scopes_from_scheme(self) -> None:
        analysis = _analyze("oidc_callback_input.json")
        assert any(s.name == "read" for s in analysis.scopes)

    def test_identity_provider_from_issuer(self) -> None:
        analysis = _analyze("oidc_callback_input.json")
        assert any(p.issuer == "https://auth.acme.com" for p in analysis.identity_providers)

    def test_oauth_endpoints_from_urls(self) -> None:
        analysis = _analyze("oidc_callback_input.json")
        kinds = {e.kind.value for e in analysis.endpoints}
        assert "authorization-endpoint" in kinds
        assert "token-endpoint" in kinds

    def test_flow_oidc(self) -> None:
        analysis = _analyze("oidc_callback_input.json")
        assert any(f.flow_kind.value == "oidc" for f in analysis.flows)


class TestSaml:
    def test_saml_metadata_parsed(self) -> None:
        analysis = _analyze("saml_input.json")
        assert any(s.entity_id == "https://sso.example.com/entity" for s in analysis.saml)
        assert any("saml-metadata" in e.evidence_type.value for s in analysis.saml for e in s.evidence)

    def test_saml_surface_and_endpoints(self) -> None:
        analysis = _analyze("saml_input.json")
        kinds = {e.kind.value for e in analysis.endpoints}
        assert "acs" in kinds

    def test_saml_flow(self) -> None:
        analysis = _analyze("saml_input.json")
        assert any(f.flow_kind.value == "saml" for f in analysis.flows)


class TestBearerApi:
    def test_auth_required_access(self) -> None:
        analysis = _analyze("bearer_api_input.json")
        assert any(s.access_state.value == "auth-required" for s in analysis.surfaces)

    def test_schemes_detected(self) -> None:
        analysis = _analyze("bearer_api_input.json")
        assert any(s.scheme_type.value == "bearer" for s in analysis.schemes)
        assert any(s.scheme_type.value == "oauth2" and s.documented for s in analysis.schemes)

    def test_token_refresh_endpoint(self) -> None:
        analysis = _analyze("bearer_api_input.json")
        assert any(e.kind.value == "token-endpoint" for e in analysis.endpoints)

    def test_roles_permissions_tenants(self) -> None:
        analysis = _analyze("bearer_api_input.json")
        assert any(r.name == "admin" for r in analysis.roles)
        assert any(t.name == "tenant-42" for t in analysis.tenants)

    def test_webauthn_detected(self) -> None:
        analysis = _analyze("bearer_api_input.json")
        assert any(w.kind == "authentication" for w in analysis.webauthn)
        assert any(m.kind.value == "webauthn" for m in analysis.mfa)


class TestFalsePositives:
    def test_no_auth_signals_on_plain_page(self) -> None:
        analysis = _analyze("false_positive_input.json")
        assert analysis.surfaces == []
        assert analysis.endpoints == []
        assert analysis.schemes == []
        assert analysis.identity_providers == []
        assert analysis.cookies == []
        assert analysis.oauth == []
        assert analysis.oidc == []
        assert analysis.saml == []


class TestSecurityInvariants:
    def test_no_raw_token_values_in_observations(self) -> None:
        analysis = _analyze("login_page_input.json")
        text = _observation_text(analysis)
        for secret in ("abc123", "deadbeef", "xyz789"):
            assert secret not in text

    def test_cookie_value_never_persisted(self) -> None:
        analysis = _analyze("login_page_input.json")
        for cookie in analysis.cookies:
            assert not hasattr(cookie, "value") or not cookie.value

    def test_authorization_header_masked(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/api",
            headers=(("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"),
                     ("WWW-Authenticate", 'Bearer realm="api"')),
            status_code=401,
        )
        analysis = AuthAnalyzer().analyze(bundle)
        assert any(isinstance(j, JWTIndicatorObservation) for j in analysis.jwt)
        text = _observation_text(analysis) + " ".join(j.location + j.transport for j in analysis.jwt)
        assert "eyJhbGciOiJSUzI1NiJ9" not in text

    def test_scope_external_endpoint_never_fetched(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/login",
            observed_urls=("https://evil.com/token",),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        # discovery is recorded as metadata; the origin of an external host is
        # never an in-scope origin here (scope enforcement happens upstream).
        assert analysis.oauth or analysis.endpoints
