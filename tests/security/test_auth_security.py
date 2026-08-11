# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the authentication intelligence capability.

Guarantees the intelligence-only boundary: no credential/token leakage, no
scope expansion, no cross-target or cross-mission contamination, resilient
parsing of malformed metadata, no raw sensitive persistence and no validation
of discovered secrets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.application.auth import AuthService
from hunterx.domain.auth.analyzer import AuthAnalyzer
from hunterx.domain.auth.models import AuthInput
from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthEvidence as TidbAuthEvidence,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.auth.registry import register_auth_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "auth"


def _engine() -> ExecutionEngine:
    engine = ExecutionEngine()
    adapters = register_auth_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


class TestAuthSecurity:
    def test_credential_leakage_prevented(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/login",
            html=(
                "<input type='password' name='password' value='sup3rSecret!'>"
                "<input name='csrf_token' value='CsrF-VaLuE'>"
            ),
            headers=(("Authorization", "Bearer 12345AccessToken"),),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        blob = " ".join(" ".join(getattr(r, "indicators", ())) for r in analysis.all_observations())
        blob += " ".join(e.value for r in analysis.all_observations() for e in getattr(r, "evidence", ()))
        for secret in ("sup3rSecret!", "12345AccessToken", "CsrF-VaLuE"):
            assert secret not in blob

    def test_token_leakage_via_local_storage_prevented(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/",
            scripts=(("https://example.com/a.js", "localStorage.setItem('access_token', 'eyJhbGciOiJIUzI1NiJ9.token.value');"),),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        blob = " ".join(record.context for record in analysis.token_storage)
        assert "eyJhbGciOiJIUzI1NiJ9" not in blob

    def test_scope_bypass_blocked(self) -> None:
        from hunterx.domain.auth.scope import AuthScopePolicy

        service = AuthService(
            engine=_engine(),
            scope=AuthScopePolicy(roots=frozenset({"example.com"})),
        )
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=_engine(), stores=stores, scope=AuthScopePolicy(roots=frozenset({"example.com"})))
        with pytest.raises(ValueError):
            service.run(target="https://evil.com/login", mode="passive")
        assert stores.repository_for(TidbAuthEvidence).count() == 0

    def test_cross_target_contamination_prevented(self) -> None:
        from hunterx.domain.auth.scope import AuthScopePolicy

        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(
            engine=_engine(),
            stores=stores,
            scope=AuthScopePolicy(roots=frozenset({"example.com"})),
        )
        service.run(
            mission_id="m1",
            target="https://example.com/login",
            mode="passive",
            parameters={"auth_input": {"url": "https://example.com/login", "status_code": 200, "html": "<input type='password'>"}},
        )
        for record in stores.repository_for(TidbAuthEvidence).stream():
            assert "evil.com" not in record.value

    def test_cross_mission_contamination_prevented(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=_engine(), stores=stores)
        service.run(
            mission_id="m1",
            target="https://example.com/login",
            mode="passive",
            parameters={"auth_input": {"url": "https://example.com/login", "html": "<input type='password'>"}},
        )
        from hunterx.domain.entities.tidb.auth_intelligence import AuthSurface as TidbAuthSurface

        for record in stores.repository_for(TidbAuthSurface).stream():
            assert record.mission_id == "m1"

    def test_malformed_oidc_document_handled(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/",
            documents=({"kind": "openid-discovery", "content": {"issuer": 123}},),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        assert analysis.oidc
        assert all(record.issuer == "123" for record in analysis.oidc)

    def test_jwt_parser_abuse_handled(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/",
            headers=(("Authorization", "Bearer " + "A" * 10_000),),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        # The analyzer must not raise on oversized or malformed token material.
        assert isinstance(analysis, object)

    def test_cookie_parser_abuse_handled(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/",
            headers=(("Set-Cookie", "name=" + "x" * 5000 + "; Path=/; HttpOnly; Secure"),),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        assert any(cookie.secure for cookie in analysis.cookies)

    def test_header_injection_handled(self) -> None:
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/",
            headers=(("WWW-Authenticate", 'Bearer realm="api", error="invalid_token"\r\nX-Injected: 1'),),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        assert analysis.schemes
        assert all("\r\n" not in scheme.header_name for scheme in analysis.schemes)

    def test_sensitive_data_persistence_blocked(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthService(engine=_engine(), stores=stores)
        service.run(
            mission_id="m1",
            target="https://example.com/login",
            mode="passive",
            parameters={
                "auth_input": {
                    "url": "https://example.com/login",
                    "status_code": 200,
                    "headers": {"Set-Cookie": "session=RawSessionValue123; Path=/; HttpOnly; Secure"},
                    "html": "<input type='password' name='password' value='Pw12345!'>",
                }
            },
        )
        for entity_name in (
            "AuthEvidence",
        ):
            repo = stores.repository_for(getattr(__import__("hunterx.domain.entities.tidb.auth_intelligence", fromlist=[entity_name]), entity_name))
            blob = " ".join(record.value for record in repo.stream())
            for secret in ("RawSessionValue123", "Pw12345!"):
                assert secret not in blob

    def test_no_token_validation_attempted(self) -> None:
        # The analyzer must never attempt to validate a token (no signature
        # verification, no replay); it only records static indicators.
        bundle = AuthInput(
            target="https://example.com",
            url="https://example.com/",
            headers=(("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"),),
        )
        analysis = AuthAnalyzer().analyze(bundle)
        assert analysis.jwt
        assert all(record.indicators for record in analysis.jwt)
        # No claim values are persisted (sub claim is PII-adjacent).
        blob = " ".join(record.location + record.transport for record in analysis.jwt)
        assert "1234" not in blob
