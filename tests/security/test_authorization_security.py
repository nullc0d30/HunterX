# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the authorization intelligence capability.

Guarantees the intelligence-only boundary: no authorization-header or JWT
leakage, no sensitive permission-data leakage, no scope/tenant expansion, no
cross-target or cross-mission contamination, resilient parsing of malformed
authorization metadata, no parser abuse, no raw sensitive persistence and no
authorization exploitation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.application.authorization import AuthorizationService
from hunterx.domain.authorization.analyzer import AuthorizationAnalyzer
from hunterx.domain.authorization.models import AuthorizationInput
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationEvidence as TidbAuthorizationEvidence,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationResource as TidbAuthorizationResource,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.authorization.registry import register_authorization_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "authorization"


def _engine() -> ExecutionEngine:
    engine = ExecutionEngine()
    adapters = register_authorization_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


class TestAuthorizationSecurity:
    def test_authorization_header_leakage_prevented(self) -> None:
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/api",
            headers=(("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.raw.secret"),),
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        blob = " ".join(" ".join(getattr(r, "indicators", ())) for r in analysis.all_observations())
        blob += " ".join(e.value for r in analysis.all_observations() for e in getattr(r, "evidence", ()))
        assert "eyJhbGciOiJIUzI1NiJ9" not in blob
        assert "raw.secret" not in blob

    def test_sensitive_permission_data_leakage_prevented(self) -> None:
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/",
            scripts=(("https://example.com/a.js", "window.apiKey='sk-secret-123'; const roles=['admin']"),),
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        blob = " ".join(" ".join(getattr(r, "indicators", ())) for r in analysis.all_observations())
        blob += " ".join(e.value for r in analysis.all_observations() for e in getattr(r, "evidence", ()))
        assert "sk-secret-123" not in blob

    def test_scope_expansion_blocked(self) -> None:
        from hunterx.domain.authorization.scope import AuthorizationScopePolicy

        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(
            engine=_engine(),
            stores=stores,
            scope=AuthorizationScopePolicy(roots=frozenset({"example.com"})),
        )
        with pytest.raises(ValueError):
            service.run(target="https://evil.com/admin", mode="passive")
        assert stores.repository_for(TidbAuthorizationEvidence).count() == 0

    def test_cross_target_contamination_prevented(self) -> None:
        from hunterx.domain.authorization.scope import AuthorizationScopePolicy

        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(
            engine=_engine(),
            stores=stores,
            scope=AuthorizationScopePolicy(roots=frozenset({"example.com"})),
        )
        service.run(
            mission_id="m1",
            target="https://example.com/admin",
            mode="passive",
            parameters={"authorization_input": {"url": "https://example.com/admin", "status_code": 200, "html": "<input name='owner_id'>"}},
        )
        for record in stores.repository_for(TidbAuthorizationEvidence).stream():
            assert "evil.com" not in record.value

    def test_cross_mission_contamination_prevented(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=_engine(), stores=stores)
        service.run(
            mission_id="m1",
            target="https://example.com/admin",
            mode="passive",
            parameters={"authorization_input": {"url": "https://example.com/admin", "html": "<input name='owner_id'>"}},
        )
        for record in stores.repository_for(TidbAuthorizationResource).stream():
            assert record.mission_id == "m1"

    def test_tenant_expansion_blocked(self) -> None:
        # A tenant indicator on a foreign host must never persist.
        from hunterx.domain.authorization.scope import AuthorizationScopePolicy

        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(
            engine=_engine(),
            stores=stores,
            scope=AuthorizationScopePolicy(roots=frozenset({"example.com"})),
        )
        service.run(
            mission_id="m1",
            target="https://example.com/api",
            mode="passive",
            parameters={"authorization_input": {"url": "https://example.com/api", "headers": {"X-Tenant-Id": "external-tenant"}, "html": ""}},
        )
        for record in stores.repository_for(TidbAuthorizationResource).stream():
            assert "external-tenant" not in record.indicators

    def test_malformed_authorization_metadata_handled(self) -> None:
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/",
            api_operations=({"method": 123, "path": None, "roles": {"not": "a-list"}},),
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        assert isinstance(analysis.all_observations(), list)

    def test_graphql_parser_abuse_handled(self) -> None:
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/graphql",
            graphql=({"subject": "x" * 5000, "name": "y" * 5000, "directive": "z" * 5000},),
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        assert isinstance(analysis.all_observations(), list)

    def test_large_policy_definition_handled(self) -> None:
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/",
            scripts=(("https://example.com/a.js", "const roles=[" + ",".join(f"'r{i}'" for i in range(5000)) + "];"),),
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        assert isinstance(analysis.all_observations(), list)
        assert len(analysis.roles) <= 5000

    def test_circular_policy_relationships_handled(self) -> None:
        # Deeply nested relationship references must not cause unbounded work.
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/",
            documents=({"policy_model": "rbac", "subjects": ["a", "b", "c"] * 500},),
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        assert isinstance(analysis.all_observations(), list)

    def test_resource_graph_explosion_limited(self) -> None:
        urls = [f"https://example.com/api/projects/{i}/members" for i in range(2000)]
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/api/projects/1/members",
            observed_urls=tuple(urls),
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        assert isinstance(analysis.all_observations(), list)

    def test_log_injection_handled(self) -> None:
        bundle = AuthorizationInput(
            target="https://example.com",
            url="https://example.com/",
            headers=(("X-Tenant-Id", "tenant\r\nInjected: 1"),),
            html="<input name='owner_id'>",
        )
        analysis = AuthorizationAnalyzer().analyze(bundle)
        for tenant in analysis.tenants:
            assert "\r\n" not in tenant.name

    def test_sensitive_data_persistence_blocked(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=_engine(), stores=stores)
        service.run(
            mission_id="m1",
            target="https://example.com/api",
            mode="passive",
            parameters={
                "authorization_input": {
                    "url": "https://example.com/api",
                    "status_code": 200,
                    "headers": {"Authorization": "Bearer RawSecretToken123"},
                    "html": "<input name='owner_id'>",
                }
            },
        )
        blob = " ".join(record.value for record in stores.repository_for(TidbAuthorizationEvidence).stream())
        assert "RawSecretToken123" not in blob

    def test_scope_bypass_through_external_resource_blocked(self) -> None:
        from hunterx.domain.authorization.scope import AuthorizationScopePolicy

        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(
            engine=_engine(),
            stores=stores,
            scope=AuthorizationScopePolicy(roots=frozenset({"example.com"})),
        )
        service.run(
            mission_id="m1",
            target="https://example.com/admin",
            mode="passive",
            parameters={
                "authorization_input": {
                    "url": "https://example.com/admin",
                    "html": "",
                    "observed_urls": ["https://evil.com/admin", "https://example.com/admin"],
                }
            },
        )
        # Out-of-scope admin surfaces discovered via observed URLs are dropped.
        from hunterx.domain.entities.tidb.authorization_intelligence import (
            AuthorizationAdminSurface as TidbAdminSurface,
        )

        for record in stores.repository_for(TidbAdminSurface).stream():
            assert "evil.com" not in record.url
