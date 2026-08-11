# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authorization intelligence analyzer.

Exercises the deterministic detection engine over golden and synthetic input
bundles: subjects, roles, groups, permissions, scopes, claims, policies,
resources, actions, identifiers, ownership, tenants, admin surfaces,
function/object/field-level access control, frontend/backend logic, API
correlation, GraphQL/WebSocket/service authorization, decisions and
mass-assignment indicators.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.authorization.analyzer import AuthorizationAnalyzer
from hunterx.domain.authorization.models import AuthorizationInput

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


class TestAnalyzer:
    def test_subjects_roles_permissions_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.roles
        assert any(role.name == "admin" for role in analysis.roles)
        assert any(permission.name == "users.read" for permission in analysis.permissions)

    def test_policy_models_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.policies
        assert any(str(policy.model_kind) == "rbac" for policy in analysis.policies)

    def test_resources_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.resources
        assert any(resource.name == "users" for resource in analysis.resources)

    def test_admin_surfaces_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.admin_surfaces
        assert any(surface.surface_kind.value == "admin-ui" for surface in analysis.admin_surfaces)

    def test_object_level_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.object_level
        assert any(level.resource == "users" for level in analysis.object_level)

    def test_function_level_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.function_level
        assert any(level.function in ("administer", "user-management") for level in analysis.function_level)

    def test_field_level_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.field_level
        assert any(level.field == "is_admin" for level in analysis.field_level)

    def test_ownership_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.ownership
        assert any(obs.name == "owner_id" for obs in analysis.ownership)

    def test_tenants_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.tenants
        assert any(tenant.name == "x-tenant-id" for tenant in analysis.tenants)

    def test_frontend_checks_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.frontend
        check_types = {check.check_type for check in analysis.frontend}
        assert {"isAdmin", "hasRole", "hasPermission", "can"} <= check_types

    def test_backend_signals_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.backend
        assert any(record.mechanism == "decorator" for record in analysis.backend)

    def test_api_correlation_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.api_correlations
        assert any(record.endpoint == "/api/v1/users/{id}" for record in analysis.api_correlations)
        assert any(record.role == "admin" for record in analysis.api_correlations)

    def test_graphql_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.graphql
        assert any(record.directive == "@auth" for record in analysis.graphql)

    def test_websocket_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("tenant_rebac_app.json"))
        assert analysis.websockets
        assert any(record.mechanism == "channel-auth" for record in analysis.websockets)

    def test_service_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.services
        assert any(record.name == "svc-billing-worker" for record in analysis.services)

    def test_decision_indicators_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("tenant_rebac_app.json"))
        assert analysis.decisions
        assert any(str(record.decision) == "deny" for record in analysis.decisions)

    def test_mass_assignment_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.mass_assignment
        assert any(record.model == "User" for record in analysis.mass_assignment)

    def test_identifiers_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.identifiers
        assert any(record.location == "path" for record in analysis.identifiers)

    def test_actions_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.actions
        assert any(record.name == "delete" for record in analysis.actions)

    def test_claims_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.claims
        assert any(record.name == "roles" for record in analysis.claims)

    def test_groups_detected(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.groups

    def test_access_controls_built(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        assert analysis.access_controls
        assert any(record.relationship_type == "role" for record in analysis.access_controls)

    def test_false_positive_quiet(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("false_positive_input.json"))
        observations = analysis.all_observations()
        assert not analysis.admin_surfaces
        assert not analysis.roles
        # A plain marketing page may still surface a public "allow" decision.
        assert len(observations) < 4

    def test_no_sensitive_values_persisted_in_indicators(self) -> None:
        analysis = AuthorizationAnalyzer().analyze(_bundle("admin_rbac_api.json"))
        blob = " ".join(
            " ".join(getattr(record, "indicators", ())) for record in analysis.all_observations()
        )
        assert "eyJ" not in blob
