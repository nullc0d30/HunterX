# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the authorization intelligence capability.

Each test maps to one acceptance criterion of Sprint 016: subjects modeled,
roles/groups/permissions/scopes/claims modeled, policies modeled, resources and
actions modeled, ownership and tenant boundaries modeled, RBAC/ABAC/ReBAC/ACL
indicators detected, admin surfaces inventoried, function/object/field-level
surfaces identified, frontend and backend authorization logic correlated, API
authorization requirements correlated, GraphQL/WebSocket/service authorization
represented, historical changes detected, deterministic comparison, no
authorization exploitation, sensitive values protected, provenance on every
finding, deterministic confidence, TIDB persistence, topology updates and
query-service reporting.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.application.authorization import AuthorizationQueryService, AuthorizationService
from hunterx.domain.authorization.analyzer import AuthorizationAnalyzer
from hunterx.domain.authorization.models import AuthorizationInput
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.authorization.registry import register_authorization_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "authorization"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


def _bundle(name: str) -> AuthorizationInput:
    payload = _golden(name)
    headers: list[tuple[str, str]] = []
    for key, value in (payload.get("headers") or {}).items():
        if isinstance(value, list):
            headers.extend((str(key), str(item)) for item in value)
        else:
            headers.append((str(key), str(value)))
    return AuthorizationInput(
        target=payload.get("url", "https://example.com"),
        url=payload.get("url", ""),
        status_code=payload.get("status_code", 0),
        headers=tuple(headers),
        html=payload.get("html", ""),
        final_url=payload.get("final_url", ""),
        scripts=tuple((item["url"], item["content"]) for item in payload.get("scripts") or ()),
        api_schemes=tuple(dict(item) for item in payload.get("api_schemes") or ()),
        api_operations=tuple(dict(item) for item in payload.get("api_operations") or ()),
        graphql=tuple(dict(item) for item in payload.get("graphql") or ()),
        websockets=tuple(dict(item) for item in payload.get("websockets") or ()),
        documents=tuple(dict(item) for item in payload.get("documents") or ()),
        observed_urls=tuple(payload.get("observed_urls") or ()),
        source="authorization",
    )


def _engine() -> ExecutionEngine:
    engine = ExecutionEngine()
    adapters = register_authorization_adapters(engine)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


class TestAuthorizationAcceptance:
    def test_subjects_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.subjects

    def test_roles_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.roles

    def test_groups_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.groups

    def test_permissions_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.permissions
        assert any(permission.name == "users.read" for permission in analysis.permissions)

    def test_scopes_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.scopes
        assert any(scope.name == "users:read" for scope in analysis.scopes)

    def test_claims_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.claims

    def test_policies_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.policies
        assert any(str(policy.model_kind) == "rbac" for policy in analysis.policies)

    def test_resources_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.resources

    def test_actions_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.actions

    def test_ownership_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.ownership

    def test_tenant_boundaries_modeled(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.tenants

    def test_rbac_indicators_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert any(str(policy.model_kind) == "rbac" for policy in analysis.policies)

    def test_rebac_indicators_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("tenant_rebac_app.json"))
        assert any(str(policy.model_kind) == "rebac" for policy in analysis.policies)

    def test_admin_surfaces_inventoried(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.admin_surfaces
        assert any(surface.surface_kind.value == "admin-ui" for surface in analysis.admin_surfaces)

    def test_function_level_surfaces_identified(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.function_level

    def test_object_level_surfaces_identified(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.object_level

    def test_field_level_indicators_identified(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.field_level

    def test_frontend_authorization_correlated(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.frontend

    def test_backend_authorization_correlated(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.backend

    def test_api_authorization_correlated(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.api_correlations

    def test_graphql_authorization_represented(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.graphql

    def test_websocket_authorization_represented(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("tenant_rebac_app.json"))
        assert analysis.websockets

    def test_service_authorization_represented(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.services

    def test_historical_changes_detected(self) -> None:
        service = AuthorizationService(engine=_engine(), stores=InMemoryTidbRepositoryFactory())
        first = service.run(
            mission_id="a1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
            with_history=True,
            historical=[],
        )
        assert first.change_count() >= 1
        second = service.run(
            mission_id="a2",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
            with_history=True,
            historical=first.records,
        )
        assert second.change_count() == 0

    def test_deterministic_comparison(self) -> None:
        service = AuthorizationService(engine=_engine(), stores=InMemoryTidbRepositoryFactory())
        one = service.run(
            mission_id="d1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        two = service.run(
            mission_id="d2",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        assert [record.key() for record in one.records] == [record.key() for record in two.records]

    def test_no_authorization_exploitation(self) -> None:
        # No record type carries an identifier that could be used to access
        # another resource: identifiers are metadata-only and never substituted.
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        for record in analysis.object_level:
            assert record.identifier, "object-level identifiers are recorded as metadata"
        blob = " ".join(
            " ".join(getattr(record, "indicators", ())) for record in analysis.all_observations()
        )
        assert "swap" not in blob and "bypass" not in blob

    def test_sensitive_values_protected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        blob = " ".join(
            " ".join(getattr(record, "indicators", ())) for record in analysis.all_observations()
        )
        assert "eyJ" not in blob

    def test_all_findings_have_provenance(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        for record in analysis.all_observations():
            assert record.source
            assert record.record_id
            assert record.confidence >= 0.0 and record.confidence <= 1.0

    def test_results_persist_in_tidb(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=_engine(), stores=stores)
        service.run(
            mission_id="p1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        from hunterx.domain.entities.tidb.authorization_intelligence import (
            AuthorizationResource as TidbResource,
        )
        from hunterx.domain.entities.tidb.authorization_intelligence import (
            AuthorizationRun as TidbRun,
        )

        assert stores.repository_for(TidbRun).count() == 1
        assert stores.repository_for(TidbResource).count() >= 1

    def test_knowledge_graph_relationships_updated(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=_engine(), stores=stores)
        service.run(
            mission_id="g1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        from hunterx.domain.entities.tidb.topology import TopologyRelationship

        assert stores.repository_for(TopologyRelationship).count() > 0

    def test_query_service_produces_all_reports(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = AuthorizationService(engine=_engine(), stores=stores)
        service.run(
            mission_id="q1",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        query = AuthorizationQueryService(stores=stores)
        for method in (
            "subjects",
            "roles",
            "groups",
            "permissions",
            "scopes",
            "claims",
            "policies",
            "resources",
            "actions",
            "identifiers",
            "ownership",
            "tenants",
            "admin_surfaces",
            "function_level",
            "object_level",
            "field_level",
            "frontend",
            "backend",
            "api_correlations",
            "graphql",
            "websockets",
            "services",
            "decisions",
            "mass_assignment",
            "access_control",
            "observations",
            "changes",
            "runs",
        ):
            getattr(query, method)()
        summary = query.summary()
        assert summary["resources"] >= 1
