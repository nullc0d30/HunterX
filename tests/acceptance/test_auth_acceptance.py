# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the authentication intelligence capability.

Each test maps to one acceptance criterion of Sprint 015: surfaces inventoried,
flows represented, login/registration/recovery surfaces identified, OAuth/OIDC/
SAML/JWT identified, sessions and cookie metadata captured, token storage
identified, CSRF/CORS inventoried, MFA/WebAuthn identified, identity providers
correlated, roles/scopes/tenants represented, public-vs-authenticated
classified with evidence, historical changes detected and deterministic
comparison supported.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.application.auth import AuthQueryService, AuthService
from hunterx.domain.auth.analyzer import AuthAnalyzer
from hunterx.domain.auth.models import AuthInput
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.auth.registry import register_auth_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "auth"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


def _bundle(name: str) -> AuthInput:
    payload = _golden(name)
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


def _engine() -> ExecutionEngine:
    engine = ExecutionEngine()
    adapters = register_auth_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


class TestAuthenticationAcceptance:
    def test_login_registration_recovery_surfaces_identified(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        kinds = {surface.surface_kind.value for surface in analysis.surfaces}
        assert "login" in kinds
        endpoint_kinds = {endpoint.kind.value for endpoint in analysis.endpoints}
        assert {"registration", "password-reset", "logout"} <= endpoint_kinds

    def test_oauth_identified(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("oidc_callback_input.json"))
        assert analysis.oauth

    def test_oidc_identified(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("oidc_callback_input.json"))
        assert any(record.issuer for record in analysis.oidc)

    def test_saml_indicators_identified(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("saml_input.json"))
        assert analysis.saml

    def test_jwt_indicators_identified(self) -> None:
        from hunterx.domain.auth.models import AuthInput

        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/api",
            status_code=401,
            headers=(("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"),),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        assert analysis.jwt
        assert any(record.transport == "authorization-header" for record in analysis.jwt)

    def test_session_mechanisms_identified(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        assert any(cookie.session for cookie in analysis.cookies)

    def test_cookie_security_metadata_captured(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        cookies = {cookie.name: cookie for cookie in analysis.cookies}
        assert cookies["session"].httponly and cookies["session"].secure
        assert cookies["session"].samesite == "lax"

    def test_token_storage_identified(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        assert analysis.token_storage

    def test_csrf_and_cors_inventoried(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        assert analysis.csrf
        assert analysis.cors

    def test_mfa_and_webauthn_identified(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("bearer_api_input.json"))
        assert analysis.mfa
        assert any(record.kind == "authentication" for record in analysis.webauthn)

    def test_identity_providers_correlated(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        assert analysis.identity_providers

    def test_roles_scopes_permissions_tenants_represented(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("bearer_api_input.json"))
        assert analysis.roles
        assert analysis.permissions
        assert analysis.tenants

    def test_public_vs_authenticated_classified_with_evidence(self) -> None:
        public = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        assert any(surface.access_state.value == "public" for surface in public.surfaces)
        protected = AuthAnalyzer().analyze(_bundle("bearer_api_input.json"))
        assert any(surface.access_state.value == "auth-required" for surface in protected.surfaces)

    def test_historical_changes_detected(self) -> None:
        service = AuthService(engine=_engine(), stores=InMemoryTidbRepositoryFactory())
        first = service.run(
            mission_id="a1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
            with_history=True,
            historical=[],
        )
        assert first.change_count() >= 1
        second = service.run(
            mission_id="a2",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
            with_history=True,
            historical=first.records,
        )
        assert second.change_count() == 0

    def test_deterministic_comparison(self) -> None:
        service = AuthService(engine=_engine(), stores=InMemoryTidbRepositoryFactory())
        one = service.run(
            mission_id="d1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        two = service.run(
            mission_id="d2",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        assert [record.key() for record in one.records] == [record.key() for record in two.records]

    def test_sensitive_values_never_exposed(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("login_page_input.json"))
        blob = " ".join(
            " ".join(getattr(record, "indicators", ())) for record in analysis.all_observations()
        )
        for secret in ("abc123", "deadbeef"):
            assert secret not in blob

    def test_all_findings_have_provenance(self) -> None:
        analysis = AuthAnalyzer().analyze(_bundle("oidc_callback_input.json"))
        for record in analysis.all_observations():
            assert record.source
            assert record.record_id

    def test_query_service_produces_all_reports(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=_engine(), stores=stores)
        service.run(
            mission_id="q1",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        query = AuthQueryService(stores=stores)
        for method in (
            "surfaces",
            "endpoints",
            "flows",
            "identity_providers",
            "oauth",
            "oidc",
            "saml",
            "cookies",
            "token_storage",
            "csrf",
            "cors",
            "mfa",
            "webauthn",
            "roles",
            "scopes",
            "permissions",
            "tenants",
            "observations",
            "schemes",
            "changes",
            "runs",
        ):
            getattr(query, method)()
        summary = query.summary()
        assert summary["surfaces"] >= 1
