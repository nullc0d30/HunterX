# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization surface classification.

Deterministic classification of observed authorization material into canonical
resource kinds, admin-surface kinds and decision indicators. The classifier
never infers a semantic privilege from a name alone and never claims an
authorization decision that was not safely observed — every classification is a
pure function of the observed indicators and is explainable through them.
"""

from __future__ import annotations

from hunterx.domain.authorization.models import (
    AdminSurfaceKind,
    AuthzAdminSurfaceObservation,
    AuthzResourceObservation,
    DecisionKind,
    ResourceKind,
)

#: Admin-surface signal table: URL token -> canonical kind.
_ADMIN_SURFACE_SIGNALS: list[tuple[str, AdminSurfaceKind]] = [
    ("/admin/login", AdminSurfaceKind.ADMIN_LOGIN),
    ("/admin/api", AdminSurfaceKind.ADMIN_API),
    ("/api/admin", AdminSurfaceKind.ADMIN_API),
    ("/management-api", AdminSurfaceKind.MANAGEMENT_API),
    ("/admin", AdminSurfaceKind.ADMIN_UI),
    ("/manage", AdminSurfaceKind.ADMIN_UI),
    ("/backoffice", AdminSurfaceKind.ADMIN_UI),
    ("/console", AdminSurfaceKind.ADMIN_UI),
    ("/internal", AdminSurfaceKind.ADMIN_UI),
    ("/roles", AdminSurfaceKind.ROLE_MANAGEMENT),
    ("/permissions", AdminSurfaceKind.PERMISSION_MANAGEMENT),
    ("/user-management", AdminSurfaceKind.USER_MANAGEMENT),
    ("/users/manage", AdminSurfaceKind.USER_MANAGEMENT),
    ("/config", AdminSurfaceKind.CONFIGURATION_MANAGEMENT),
    ("/configuration", AdminSurfaceKind.CONFIGURATION_MANAGEMENT),
    ("/security", AdminSurfaceKind.SECURITY_CONTROLS),
    ("/audit", AdminSurfaceKind.AUDIT_ACCESS),
    ("/integrations", AdminSurfaceKind.INTEGRATION_MANAGEMENT),
    ("/credentials", AdminSurfaceKind.CREDENTIAL_MANAGEMENT),
    ("/api-management", AdminSurfaceKind.API_MANAGEMENT),
    ("/token-management", AdminSurfaceKind.TOKEN_MANAGEMENT),
    ("/billing", AdminSurfaceKind.BILLING_MANAGEMENT),
]

#: Resource-kind signal table: URL token -> canonical kind.
_RESOURCE_SIGNALS: list[tuple[str, ResourceKind]] = [
    ("users", ResourceKind.USER),
    ("user", ResourceKind.USER),
    ("accounts", ResourceKind.ACCOUNT),
    ("account", ResourceKind.ACCOUNT),
    ("organizations", ResourceKind.ORGANIZATION),
    ("organization", ResourceKind.ORGANIZATION),
    ("tenants", ResourceKind.TENANT),
    ("tenant", ResourceKind.TENANT),
    ("workspaces", ResourceKind.WORKSPACE),
    ("workspace", ResourceKind.WORKSPACE),
    ("projects", ResourceKind.PROJECT),
    ("project", ResourceKind.PROJECT),
    ("repositories", ResourceKind.REPOSITORY),
    ("repo", ResourceKind.REPOSITORY),
    ("documents", ResourceKind.DOCUMENT),
    ("document", ResourceKind.DOCUMENT),
    ("files", ResourceKind.FILE),
    ("file", ResourceKind.FILE),
    ("reports", ResourceKind.REPORT),
    ("report", ResourceKind.REPORT),
    ("findings", ResourceKind.FINDING),
    ("finding", ResourceKind.FINDING),
    ("assets", ResourceKind.ASSET),
    ("asset", ResourceKind.ASSET),
    ("api-keys", ResourceKind.API_KEY),
    ("apikeys", ResourceKind.API_KEY),
    ("tokens", ResourceKind.TOKEN),
    ("token", ResourceKind.TOKEN),
    ("integrations", ResourceKind.INTEGRATION),
    ("integration", ResourceKind.INTEGRATION),
    ("webhooks", ResourceKind.WEBHOOK),
    ("webhook", ResourceKind.WEBHOOK),
    ("deployments", ResourceKind.DEPLOYMENT),
    ("deployment", ResourceKind.DEPLOYMENT),
    ("configurations", ResourceKind.CONFIGURATION),
    ("configuration", ResourceKind.CONFIGURATION),
    ("billing", ResourceKind.BILLING_OBJECT),
    ("invoices", ResourceKind.BILLING_OBJECT),
    ("policies", ResourceKind.SECURITY_POLICY),
    ("security-policies", ResourceKind.SECURITY_POLICY),
    ("roles", ResourceKind.ROLE),
    ("role", ResourceKind.ROLE),
    ("permissions", ResourceKind.PERMISSION),
    ("permission", ResourceKind.PERMISSION),
]


class AuthorizationClassifier:
    """Classify admin surfaces, resources and decisions deterministically."""

    def classify_admin_surface(
        self,
        observation: AuthzAdminSurfaceObservation,
    ) -> AuthzAdminSurfaceObservation:
        """Refine an admin-surface observation's kind from its URL/indicators."""
        if observation.surface_kind is not AdminSurfaceKind.UNKNOWN:
            return observation
        url = (observation.url or "").lower()
        for token, kind in _ADMIN_SURFACE_SIGNALS:
            if token in url:
                from dataclasses import replace

                return replace(observation, surface_kind=kind)
        return observation

    def classify_resource(
        self,
        observation: AuthzResourceObservation,
    ) -> AuthzResourceObservation:
        """Refine a resource observation's kind from its name/URL."""
        if observation.resource_kind is not ResourceKind.UNKNOWN:
            return observation
        lowered = (observation.name or "").lower()
        for token, kind in _RESOURCE_SIGNALS:
            if lowered == token or lowered == f"{token}s":
                from dataclasses import replace

                return replace(observation, resource_kind=kind)
        return observation

    def classify_decision(
        self,
        *,
        status_code: int = 0,
        documented: str = "",
    ) -> DecisionKind:
        """Classify a decision indicator from safely observed status/documentation."""
        if status_code in (401, 403):
            return DecisionKind.DENY
        if documented.lower() in ("allow", "deny", "conditional"):
            try:
                return DecisionKind(documented.lower())
            except ValueError:
                return DecisionKind.UNKNOWN
        if status_code in (200, 201, 204):
            return DecisionKind.ALLOW
        return DecisionKind.UNKNOWN
