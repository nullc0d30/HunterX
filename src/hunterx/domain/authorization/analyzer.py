# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Static/observable authorization intelligence detection engine.

The analyzer turns an :class:`AuthorizationInput` bundle — one HTTP response
snapshot, associated script content, API security schemes and operations,
GraphQL metadata, WebSocket endpoints, observed URLs, policy documents and
pre-existing TIDB intelligence — into a canonical set of authorization
observations with deterministic evidence and confidence. It is pure: no I/O, no
execution, no authorization testing, no identifier substitution. Sensitive
values are masked before they ever reach an observation.

Detectors: subjects, roles, groups, permissions, scopes, claims, policies,
resources, actions, resource identifiers, ownership, tenants, admin surfaces,
function/object/field-level access control, frontend authorization logic,
backend authorization logic, API authorization correlation, GraphQL, WebSocket,
service-to-service, decision indicators and mass-assignment fields.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.authorization.models import (
    ActionKind,
    AdminSurfaceKind,
    AuthorizationInput,
    AuthzAccessControlObservation,
    AuthzActionObservation,
    AuthzAdminSurfaceObservation,
    AuthzApiCorrelationObservation,
    AuthzBackendObservation,
    AuthzClaimObservation,
    AuthzDecisionObservation,
    AuthzEvidenceType,
    AuthzFieldLevelObservation,
    AuthzFrontendObservation,
    AuthzFunctionLevelObservation,
    AuthzGraphQLObservation,
    AuthzGroupObservation,
    AuthzMassAssignmentObservation,
    AuthzObjectLevelObservation,
    AuthzObservation,
    AuthzOwnershipObservation,
    AuthzPermissionObservation,
    AuthzPolicyObservation,
    AuthzResourceIdentifierObservation,
    AuthzResourceObservation,
    AuthzRoleObservation,
    AuthzScopeObservation,
    AuthzServiceObservation,
    AuthzSubjectObservation,
    AuthzTenantObservation,
    AuthzWebSocketObservation,
    DecisionKind,
    EvidenceStrength,
    IdentifierKind,
    OwnershipKind,
    PolicyModelKind,
    ResourceKind,
    SubjectKind,
    TenantKind,
    make_evidence,
    origin_of,
)
from hunterx.shared.masking import mask_value

#: Maximum context length persisted for context-bearing observations.
_CONTEXT_LIMIT = 256

#: Evidence strength for a direct HTTP observation (headers, status, responses).
_STRONG = EvidenceStrength.STRONG
_MODERATE = EvidenceStrength.MODERATE
_WEAK = EvidenceStrength.WEAK

#: Confidence for single-source detections by evidence strength.
_CONF_STRONG = 0.9
_CONF_MODERATE = 0.7
_CONF_WEAK = 0.45

#: Token/sensitive-literal detector used to scrub contexts.
_TOKEN_LITERAL = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


@dataclass(slots=True)
class AuthorizationAnalysis:
    """The complete set of authorization observations for one input bundle.

    Every collection is deterministically ordered; :meth:`all_observations`
    flattens them in a stable order for persistence and correlation.
    """

    subjects: list[AuthzSubjectObservation] = field(default_factory=list)
    roles: list[AuthzRoleObservation] = field(default_factory=list)
    groups: list[AuthzGroupObservation] = field(default_factory=list)
    permissions: list[AuthzPermissionObservation] = field(default_factory=list)
    scopes: list[AuthzScopeObservation] = field(default_factory=list)
    claims: list[AuthzClaimObservation] = field(default_factory=list)
    policies: list[AuthzPolicyObservation] = field(default_factory=list)
    resources: list[AuthzResourceObservation] = field(default_factory=list)
    actions: list[AuthzActionObservation] = field(default_factory=list)
    identifiers: list[AuthzResourceIdentifierObservation] = field(default_factory=list)
    ownership: list[AuthzOwnershipObservation] = field(default_factory=list)
    tenants: list[AuthzTenantObservation] = field(default_factory=list)
    admin_surfaces: list[AuthzAdminSurfaceObservation] = field(default_factory=list)
    function_level: list[AuthzFunctionLevelObservation] = field(default_factory=list)
    object_level: list[AuthzObjectLevelObservation] = field(default_factory=list)
    field_level: list[AuthzFieldLevelObservation] = field(default_factory=list)
    frontend: list[AuthzFrontendObservation] = field(default_factory=list)
    backend: list[AuthzBackendObservation] = field(default_factory=list)
    api_correlations: list[AuthzApiCorrelationObservation] = field(default_factory=list)
    graphql: list[AuthzGraphQLObservation] = field(default_factory=list)
    websockets: list[AuthzWebSocketObservation] = field(default_factory=list)
    services: list[AuthzServiceObservation] = field(default_factory=list)
    decisions: list[AuthzDecisionObservation] = field(default_factory=list)
    mass_assignment: list[AuthzMassAssignmentObservation] = field(default_factory=list)
    access_controls: list[AuthzAccessControlObservation] = field(default_factory=list)
    observations: list[AuthzObservation] = field(default_factory=list)

    def all_observations(self) -> list[Any]:
        """Return every observation in a stable deterministic order."""
        result: list[Any] = []
        for collection in (
            self.subjects,
            self.roles,
            self.groups,
            self.permissions,
            self.scopes,
            self.claims,
            self.policies,
            self.resources,
            self.actions,
            self.identifiers,
            self.ownership,
            self.tenants,
            self.admin_surfaces,
            self.function_level,
            self.object_level,
            self.field_level,
            self.frontend,
            self.backend,
            self.api_correlations,
            self.graphql,
            self.websockets,
            self.services,
            self.decisions,
            self.mass_assignment,
            self.access_controls,
            self.observations,
        ):
            result.extend(collection)
        return result


class AuthorizationAnalyzer:
    """Run deterministic authorization-signal detection over an input bundle.

    Usage::

        analysis = AuthorizationAnalyzer().analyze(authorization_input)
    """

    def analyze(self, bundle: AuthorizationInput) -> AuthorizationAnalysis:
        """Analyze ``bundle`` and return the complete :class:`AuthorizationAnalysis`."""
        context = _Context(bundle)
        analysis = AuthorizationAnalysis()

        self._detect_subjects(analysis, context)
        self._detect_roles(analysis, context)
        self._detect_groups(analysis, context)
        self._detect_permissions(analysis, context)
        self._detect_scopes(analysis, context)
        self._detect_claims(analysis, context)
        self._detect_policies(analysis, context)
        self._detect_resources(analysis, context)
        self._detect_actions(analysis, context)
        self._detect_identifiers(analysis, context)
        self._detect_ownership(analysis, context)
        self._detect_tenants(analysis, context)
        self._detect_admin_surfaces(analysis, context)
        self._detect_function_level(analysis, context)
        self._detect_object_level(analysis, context)
        self._detect_field_level(analysis, context)
        self._detect_frontend(analysis, context)
        self._detect_backend(analysis, context)
        self._detect_api_correlation(analysis, context)
        self._detect_graphql(analysis, context)
        self._detect_websocket(analysis, context)
        self._detect_services(analysis, context)
        self._detect_decisions(analysis, context)
        self._detect_mass_assignment(analysis, context)

        self._build_access_controls(analysis, context)
        return analysis

    # -- subjects ------------------------------------------------------------

    def _detect_subjects(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect evidence-backed subjects from scripts, claims and documents."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            for match in _SUBJECT_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                kind = _subject_kind(name)
                analysis.subjects.append(
                    AuthzSubjectObservation(
                        origin=ctx.origin,
                        name=name,
                        subject_kind=kind,
                        context=_mask(_context_around(content, match.start())),
                        indicators=(f"js-indicator:subject:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="subject identifier in script configuration",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        # Service-account / api-client subjects from documents & schemes.
        for document in ctx.bundle.documents:
            _subjects_from_document(analysis, document, ctx, seen)
        for scheme in ctx.bundle.api_schemes:
            _subjects_from_scheme(analysis, scheme, ctx, seen)

    def _detect_roles(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect role identifiers from scripts, claims and API operations."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            for match in _ROLE_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                analysis.roles.append(
                    AuthzRoleObservation(
                        origin=ctx.origin,
                        name=name,
                        context=_mask(_context_around(content, match.start())),
                        custom=_role_custom(name),
                        indicators=(f"js-indicator:role:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="role identifier in script configuration",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _roles_from_operation(analysis, operation, ctx, seen)

    def _detect_groups(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect group identifiers from scripts and claims."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            for match in _GROUP_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                analysis.groups.append(
                    AuthzGroupObservation(
                        origin=ctx.origin,
                        name=name,
                        context=_mask(_context_around(content, match.start())),
                        indicators=(f"js-indicator:group:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="group identifier in script configuration",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_permissions(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect permission identifiers from scripts and API operations."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            for match in _PERMISSION_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                action, resource = _permission_parts(name)
                analysis.permissions.append(
                    AuthzPermissionObservation(
                        origin=ctx.origin,
                        name=name,
                        action=action,
                        resource=resource,
                        indicators=(f"js-indicator:permission:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="permission identifier in script configuration",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _permissions_from_operation(analysis, operation, ctx, seen)

    def _detect_scopes(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect OAuth/OIDC/API scopes from schemes, operations and scripts."""
        seen: set[Any] = set()
        for scheme in ctx.bundle.api_schemes:
            _scopes_from_scheme(analysis, scheme, ctx, seen)
        for operation in ctx.bundle.api_operations:
            _scopes_from_operation(analysis, operation, ctx, seen)
        for _script_url, content in ctx.bundle.scripts:
            for match in _SCOPE_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                analysis.scopes.append(
                    AuthzScopeObservation(
                        origin=ctx.origin,
                        name=name,
                        indicators=(f"js-indicator:scope:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="scope identifier in script configuration",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_claims(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect authorization claim references from scripts and documents."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            for match in _CLAIM_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                analysis.claims.append(
                    AuthzClaimObservation(
                        origin=ctx.origin,
                        name=name,
                        indicators=(f"js-indicator:claim:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="authorization claim reference in script",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for document in ctx.bundle.documents:
            _claims_from_document(analysis, document, ctx, seen)

    def _detect_policies(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect authorization policy models (RBAC/ABAC/ACL/ReBAC/custom)."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            lowered = content.lower()
            for keyword, model_kind in _POLICY_MODEL_SIGNALS:
                if keyword not in lowered:
                    continue
                key = (model_kind.value, keyword)
                if key in seen:
                    continue
                seen.add(key)
                analysis.policies.append(
                    AuthzPolicyObservation(
                        origin=ctx.origin,
                        name=keyword,
                        model_kind=model_kind,
                        mechanism="js-indicator",
                        indicators=(f"policy-config:{model_kind.value}:{keyword}",),
                        confidence=_CONF_MODERATE if model_kind != PolicyModelKind.CUSTOM else _CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.POLICY_CONFIG,
                                keyword,
                                source="authorization",
                                strength=_MODERATE if model_kind != PolicyModelKind.CUSTOM else _WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"policy model {model_kind.value} indicator in script",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for document in ctx.bundle.documents:
            _policies_from_document(analysis, document, ctx, seen)
        for operation in ctx.bundle.api_operations:
            _policies_from_operation(analysis, operation, ctx, seen)

    def _detect_resources(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect authorization resources from URLs, HTML, scripts and operations."""
        seen: set[Any] = set()
        urls = [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]
        for url in urls:
            for name, kind in _resources_from_url(url):
                key = (kind.value, name)
                if key in seen:
                    continue
                seen.add(key)
                analysis.resources.append(
                    AuthzResourceObservation(
                        origin=origin_of(url) or ctx.origin,
                        name=name,
                        resource_kind=kind,
                        indicators=(f"url-pattern:resource:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"URL pattern indicates {kind.value} resource",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        # Resource names surfaced in HTML body (forms, links, labels).
        for match in _RESOURCE_NAME_PATTERN.finditer(_html_text(ctx.bundle.html)):
            name = next((group for group in match.groups() if group), "")
            name = name.strip()
            if not name or name in seen:
                continue
            seen.add(name)
            analysis.resources.append(
                AuthzResourceObservation(
                    origin=ctx.origin,
                    name=name,
                    resource_kind=ResourceKind.OTHER,
                    indicators=(f"html:resource:{name}",),
                    confidence=_CONF_WEAK,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.HTML,
                            name,
                            source="authorization",
                            strength=_WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="resource label observed in HTML",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        for operation in ctx.bundle.api_operations:
            _resources_from_operation(analysis, operation, ctx, seen)

    def _detect_actions(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Normalize actions from endpoints, operations and method verbs."""
        seen: set[Any] = set()
        urls = [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]
        for url in urls:
            for match in _ACTION_VERB_PATTERN.finditer(url):
                original = match.group("verb")
                normalized = _normalize_action(original)
                key = (normalized, "")
                if key in seen:
                    continue
                seen.add(key)
                analysis.actions.append(
                    AuthzActionObservation(
                        origin=origin_of(url) or ctx.origin,
                        name=normalized,
                        original=original,
                        indicators=(f"url-pattern:action:{original}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"action verb '{original}' in URL",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            method = str(operation.get("method", "GET")).upper()
            normalized = _method_action(method)
            key = (normalized, "")
            if key in seen:
                continue
            seen.add(key)
            analysis.actions.append(
                AuthzActionObservation(
                    origin=ctx.origin,
                    name=normalized,
                    original=method,
                    indicators=(f"api-operation:action:{method}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.API_OPERATION,
                            method,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail=f"HTTP method {method} maps to {normalized}",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    def _detect_identifiers(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect resource-identifier metadata from paths, queries and bodies."""
        seen: set[Any] = set()
        urls = [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]
        for url in urls:
            origin = origin_of(url) or ctx.origin
            for segment in _path_segments(url):
                if not _looks_like_identifier(segment):
                    continue
                kind = _identifier_kind(segment)
                key = (kind.value, url, segment)
                if key in seen:
                    continue
                seen.add(key)
                analysis.identifiers.append(
                    AuthzResourceIdentifierObservation(
                        origin=origin,
                        identifier=segment,
                        identifier_kind=kind,
                        location="path",
                        endpoint=url,
                        indicators=(f"url-pattern:identifier:{kind.value}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"identifier segment ({kind.value}) in URL path",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
            # Query-parameter identifiers (e.g. ?id=123, ?user_id=).
            for param, _value in _query_parameters(url):
                if not _looks_like_identifier(param):
                    continue
                kind = IdentifierKind.QUERY
                key = (kind.value, url, param)
                if key in seen:
                    continue
                seen.add(key)
                analysis.identifiers.append(
                    AuthzResourceIdentifierObservation(
                        origin=origin,
                        identifier=param,
                        identifier_kind=kind,
                        location="query",
                        endpoint=url,
                        indicators=(f"url-pattern:identifier:query:{param}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"query identifier parameter '{param}'",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _identifiers_from_operation(analysis, operation, ctx, seen)

    def _detect_ownership(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect ownership indicators from HTML, scripts and documents."""
        seen: set[Any] = set()
        html_lower = ctx.html_lower
        for name in _OWNERSHIP_FIELDS:
            if name not in html_lower:
                continue
            key = (name, "")
            if key in seen:
                continue
            seen.add(key)
            kind = _ownership_kind(name)
            analysis.ownership.append(
                AuthzOwnershipObservation(
                    origin=ctx.origin,
                    name=name,
                    ownership_kind=kind,
                    indicators=(f"html:ownership:{name}",),
                    confidence=_CONF_WEAK,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.HTML,
                            name,
                            source="authorization",
                            strength=_WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="ownership indicator observed in HTML",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        for _script_url, content in ctx.bundle.scripts:
            for match in _OWNERSHIP_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                kind = _ownership_kind(name)
                analysis.ownership.append(
                    AuthzOwnershipObservation(
                        origin=ctx.origin,
                        name=name,
                        ownership_kind=kind,
                        resource="",
                        indicators=(f"js-indicator:ownership:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="ownership indicator in script configuration",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _ownership_from_operation(analysis, operation, ctx, seen)

    def _detect_tenants(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Detect tenant-boundary indicators from headers, claims, paths and queries."""
        seen: set[Any] = set()
        for name, _value in ctx.headers.items():
            if name not in _TENANT_HEADERS:
                continue
            key = (TenantKind.HEADER.value, name)
            if key in seen:
                continue
            seen.add(key)
            analysis.tenants.append(
                AuthzTenantObservation(
                    origin=ctx.origin,
                    name=name,
                    tenant_kind=TenantKind.HEADER,
                    location=f"header:{name}",
                    indicators=(f"http-header:tenant:{name}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.HTTP_HEADER,
                            name,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="tenant header observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        for url in [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]:
            origin = origin_of(url) or ctx.origin
            for param in _TENANT_QUERY_PARAMS:
                if param not in url:
                    continue
                key = (TenantKind.QUERY.value, param)
                if key in seen:
                    continue
                seen.add(key)
                analysis.tenants.append(
                    AuthzTenantObservation(
                        origin=origin,
                        name=param,
                        tenant_kind=TenantKind.QUERY,
                        location=f"query:{param}",
                        indicators=(f"url-pattern:tenant:{param}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="tenant query parameter observed",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        # Tenant claims from scripts/documents.
        for _script_url, content in ctx.bundle.scripts:
            for match in _TENANT_CLAIM_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                analysis.tenants.append(
                    AuthzTenantObservation(
                        origin=ctx.origin,
                        name=name,
                        tenant_kind=TenantKind.CLAIM,
                        location="claim",
                        indicators=(f"js-indicator:tenant-claim:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="tenant claim reference in script",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_admin_surfaces(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Inventory administrative surfaces from URLs, HTML and scripts."""
        seen: set[Any] = set()
        urls = [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]
        for url in urls:
            origin = origin_of(url) or ctx.origin
            for kind in _admin_surface_kinds(url):
                key = (url, kind.value)
                if key in seen:
                    continue
                seen.add(key)
                analysis.admin_surfaces.append(
                    AuthzAdminSurfaceObservation(
                        url=url,
                        origin=origin,
                        surface_kind=kind,
                        indicators=(f"url-pattern:admin-surface:{kind.value}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"URL pattern indicates {kind.value}",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for script_url, content in ctx.bundle.scripts:
            for match in _ADMIN_ROUTE_PATTERN.finditer(content):
                route = _scrub_token(match.group("route")).strip()
                if not route or (script_url, route) in seen:
                    continue
                seen.add((script_url, route))
                analysis.admin_surfaces.append(
                    AuthzAdminSurfaceObservation(
                        url=route,
                        origin=ctx.origin,
                        surface_kind=AdminSurfaceKind.ADMIN_ROUTE,
                        indicators=(f"js-indicator:admin-route:{route}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                route,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="admin route in script configuration",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_function_level(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Identify privileged functions from URLs and API operations."""
        seen: set[Any] = set()
        urls = [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]
        for url in urls:
            origin = origin_of(url) or ctx.origin
            for keyword, function in _PRIVILEGED_FUNCTIONS:
                if keyword not in url.lower():
                    continue
                key = (url, function)
                if key in seen:
                    continue
                seen.add(key)
                analysis.function_level.append(
                    AuthzFunctionLevelObservation(
                        origin=origin,
                        function=function,
                        endpoint=url,
                        method="GET",
                        indicators=(f"url-pattern:privileged:{keyword}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"privileged function indicator '{keyword}'",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _function_level_from_operation(analysis, operation, ctx, seen)

    def _detect_object_level(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Identify object-level endpoints (operating on specific objects)."""
        seen: set[Any] = set()
        urls = [ctx.bundle.url, ctx.bundle.final_url, *ctx.bundle.observed_urls]
        for url in urls:
            origin = origin_of(url) or ctx.origin
            segments = _path_segments(url)
            for index, segment in enumerate(segments):
                if not _looks_like_identifier(segment):
                    continue
                resource = segments[index - 1] if index > 0 else ""
                if not resource:
                    continue
                key = (url, resource)
                if key in seen:
                    continue
                seen.add(key)
                analysis.object_level.append(
                    AuthzObjectLevelObservation(
                        origin=origin,
                        resource=resource,
                        identifier=segment,
                        action=_method_action("GET"),
                        endpoint=url,
                        method="GET",
                        indicators=(f"url-pattern:object-level:{resource}/{{id}}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.URL_PATTERN,
                                url,
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"object-level endpoint on {resource}",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _object_level_from_operation(analysis, operation, ctx, seen)

    def _detect_field_level(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Identify potentially restricted fields from schemas, scripts and HTML."""
        seen: set[Any] = set()
        html_lower = ctx.html_lower
        for name in _RESTRICTED_FIELDS:
            if name in html_lower:
                key = (name, "")
                if key in seen:
                    continue
                seen.add(key)
                analysis.field_level.append(
                    AuthzFieldLevelObservation(
                        origin=ctx.origin,
                        field=name,
                        indicators=(f"html:field-level:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.HTML,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="potentially restricted field in HTML",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for _script_url, content in ctx.bundle.scripts:
            for match in _FIELD_LEVEL_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                analysis.field_level.append(
                    AuthzFieldLevelObservation(
                        origin=ctx.origin,
                        field=name,
                        indicators=(f"js-indicator:field-level:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="potentially restricted field in script",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _field_level_from_operation(analysis, operation, ctx, seen)
        for record in ctx.bundle.graphql:
            _field_level_from_graphql(analysis, record, ctx, seen)

    def _detect_frontend(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Correlate frontend authorization logic from scripts."""
        seen: set[Any] = set()
        for script_url, content in ctx.bundle.scripts:
            for check_type, pattern in _FRONTEND_CHECKS:
                for _match in pattern.finditer(content):
                    key = (script_url, check_type)
                    if key in seen:
                        continue
                    seen.add(key)
                    analysis.frontend.append(
                        AuthzFrontendObservation(
                            origin=ctx.origin,
                            check_type=check_type,
                            target=script_url,
                            js_asset=script_url,
                            indicators=(f"js-indicator:frontend-check:{check_type}",),
                            confidence=_CONF_MODERATE,
                            evidence=(
                                make_evidence(
                                    AuthzEvidenceType.JS_INDICATOR,
                                    check_type,
                                    source="authorization",
                                    strength=_MODERATE,
                                    tool_id=ctx.bundle.tool_id,
                                    detail=f"frontend authorization check '{check_type}'",
                                ),
                            ),
                            source=ctx.bundle.source,
                            tool_id=ctx.bundle.tool_id,
                            target_key=ctx.bundle.target,
                        )
                    )
            # Route guards: path + role/permission condition pairs.
            for match in _ROUTE_GUARD_PATTERN.finditer(content):
                route = _scrub_token(match.group("route")).strip()
                guard = _scrub_token(match.group("guard")).strip() or "unknown"
                guard_key = (script_url, route, guard)
                if guard_key in seen:
                    continue
                seen.add(guard_key)
                analysis.frontend.append(
                    AuthzFrontendObservation(
                        origin=ctx.origin,
                        check_type="route-guard",
                        target=route,
                        js_asset=script_url,
                        indicators=(f"js-indicator:route-guard:{route}:{guard}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                route,
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"route guard '{guard}' on '{route}'",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_backend(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Correlate backend authorization logic indicators."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            lowered = content.lower()
            for keyword, mechanism in _BACKEND_SIGNALS:
                if keyword not in lowered:
                    continue
                key = (mechanism, keyword)
                if key in seen:
                    continue
                seen.add(key)
                analysis.backend.append(
                    AuthzBackendObservation(
                        origin=ctx.origin,
                        mechanism=mechanism,
                        name=keyword,
                        target="script",
                        indicators=(f"js-indicator:backend:{mechanism}:{keyword}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                keyword,
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail=f"backend authorization indicator '{keyword}'",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for operation in ctx.bundle.api_operations:
            _backend_from_operation(analysis, operation, ctx, seen)

    def _detect_api_correlation(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Correlate API authorization requirements per operation."""
        seen: set[Any] = set()
        for operation in ctx.bundle.api_operations:
            endpoint = str(operation.get("path") or operation.get("endpoint") or "")
            method = str(operation.get("method", "GET")).upper()
            key = (method, endpoint)
            if key in seen:
                continue
            seen.add(key)
            security = _security_from_operation(operation)
            roles, scopes, permissions = _requirements_from_operation(operation)
            resource, action = _operation_resource_action(endpoint, method)
            documented = bool(operation.get("documented", True))
            analysis.api_correlations.append(
                AuthzApiCorrelationObservation(
                    origin=ctx.origin,
                    endpoint=endpoint,
                    method=method,
                    authentication=security,
                    role=",".join(roles),
                    scope=",".join(scopes),
                    permission=",".join(permissions),
                    resource=resource,
                    action=action,
                    tenant=str(operation.get("tenant") or ""),
                    policy=str(operation.get("policy") or ""),
                    documented=documented,
                    indicators=(f"api-operation:correlation:{method}:{endpoint}",),
                    confidence=_CONF_MODERATE if documented else _CONF_WEAK,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.API_OPERATION,
                            f"{method} {endpoint}",
                            source="authorization",
                            strength=_MODERATE if documented else _WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="API operation authorization requirements",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        # Correlate declared OpenAPI security schemes into a single operation row.
        for scheme in ctx.bundle.api_schemes:
            name = str(scheme.get("name") or scheme.get("scheme_name") or "")
            if not name:
                continue
            scopes = _scheme_scopes(scheme)
            for scope in scopes:
                analysis.api_correlations.append(
                    AuthzApiCorrelationObservation(
                        origin=ctx.origin,
                        endpoint="",
                        method="ANY",
                        authentication=name,
                        scope=scope,
                        resource="",
                        action="",
                        indicators=(f"openapi-security:correlation:{name}:{scope}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.OPENAPI_SECURITY,
                                f"{name}:{scope}",
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail="OpenAPI security scheme scope requirement",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_graphql(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Represent GraphQL authorization indicators from schema metadata."""
        seen: set[Any] = set()
        for record in ctx.bundle.graphql:
            subject = str(record.get("subject") or "field")
            name = str(record.get("name") or "")
            directive = str(record.get("directive") or "")
            key = (subject, name, directive)
            if key in seen:
                continue
            seen.add(key)
            analysis.graphql.append(
                AuthzGraphQLObservation(
                    origin=ctx.origin,
                    subject=subject,
                    name=name,
                    directive=directive,
                    indicators=(f"graphql:{subject}:{name}",),
                    confidence=_CONF_MODERATE if directive else _CONF_WEAK,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.GRAPHQL,
                            name or subject,
                            source="authorization",
                            strength=_MODERATE if directive else _WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail=f"GraphQL {subject} authorization indicator",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        # Static script hints about GraphQL authorization.
        for _script_url, content in ctx.bundle.scripts:
            lowered = content.lower()
            if "graphql" not in lowered:
                continue
            for match in _GRAPHQL_DIRECTIVE_PATTERN.finditer(content):
                directive = _scrub_token(match.group("directive")).strip()
                key = ("field", "", directive)
                if key in seen:
                    continue
                seen.add(key)
                analysis.graphql.append(
                    AuthzGraphQLObservation(
                        origin=ctx.origin,
                        subject="field",
                        name="",
                        directive=directive,
                        indicators=(f"js-indicator:graphql-directive:{directive}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                directive,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="GraphQL authorization directive in script",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_websocket(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Represent WebSocket authorization indicators."""
        seen: set[Any] = set()
        for record in ctx.bundle.websockets:
            endpoint = str(record.get("endpoint") or record.get("url") or "")
            channel = str(record.get("channel") or record.get("topic") or "")
            mechanism = str(record.get("mechanism") or "unknown")
            key = (endpoint, channel, mechanism)
            if key in seen:
                continue
            seen.add(key)
            analysis.websockets.append(
                AuthzWebSocketObservation(
                    origin=ctx.origin,
                    endpoint=endpoint,
                    channel=channel,
                    mechanism=mechanism,
                    indicators=(f"websocket:{mechanism}:{endpoint}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.WEBSOCKET,
                            endpoint or channel or mechanism,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="WebSocket authorization indicator",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        for url in [ctx.bundle.url, *ctx.bundle.observed_urls]:
            if not url.lower().startswith(("ws://", "wss://")):
                continue
            key = (url, "", "")
            if key in seen:
                continue
            seen.add(key)
            analysis.websockets.append(
                AuthzWebSocketObservation(
                    origin=origin_of(url) or ctx.origin,
                    endpoint=url,
                    mechanism="connection-auth",
                    indicators=(f"url-pattern:websocket:{url}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.URL_PATTERN,
                            url,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="WebSocket endpoint observed",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )

    def _detect_services(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Represent service-to-service authorization indicators."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            for match in _SERVICE_PATTERN.finditer(content):
                name = _scrub_token(match.group("name")).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                service_kind, mechanism = _service_kind(name, content, match.start())
                analysis.services.append(
                    AuthzServiceObservation(
                        origin=ctx.origin,
                        name=name,
                        service_kind=service_kind,
                        mechanism=mechanism,
                        indicators=(f"js-indicator:service:{service_kind}:{name}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                name,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="service identity indicator in script",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )
        for document in ctx.bundle.documents:
            _services_from_document(analysis, document, ctx, seen)

    def _detect_decisions(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Represent observed/documented authorization decision indicators.

        Only safe, already-observed evidence produces a decision indicator —
        HunterX never actively probes authorization behaviour.
        """
        if ctx.bundle.status_code in (401, 403):
            analysis.decisions.append(
                AuthzDecisionObservation(
                    origin=ctx.origin,
                    decision=DecisionKind.DENY,
                    endpoint=ctx.bundle.url,
                    method="GET",
                    indicators=(f"http-status:{ctx.bundle.status_code}",),
                    confidence=_CONF_STRONG,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.HTTP_STATUS,
                            str(ctx.bundle.status_code),
                            source="authorization",
                            strength=_STRONG,
                            tool_id=ctx.bundle.tool_id,
                            detail="observed denial status on an in-scope resource",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        elif ctx.bundle.status_code in (200, 201, 204):
            analysis.decisions.append(
                AuthzDecisionObservation(
                    origin=ctx.origin,
                    decision=DecisionKind.ALLOW,
                    endpoint=ctx.bundle.url,
                    method="GET",
                    indicators=(f"http-status:{ctx.bundle.status_code}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.HTTP_STATUS,
                            str(ctx.bundle.status_code),
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="observed success status on an already-authorized resource",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
        # Documented decisions from policy documents.
        for document in ctx.bundle.documents:
            decision = str(document.get("decision") or "").lower()
            if decision in ("allow", "deny", "conditional"):
                analysis.decisions.append(
                    AuthzDecisionObservation(
                        origin=ctx.origin,
                        decision=decision,
                        endpoint=str(document.get("endpoint") or ""),
                        method=str(document.get("method") or "GET"),
                        indicators=(f"documentation:decision:{decision}",),
                        confidence=_CONF_MODERATE,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.DOCUMENTATION,
                                decision,
                                source="authorization",
                                strength=_MODERATE,
                                tool_id=ctx.bundle.tool_id,
                                detail="documented authorization decision",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _detect_mass_assignment(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Identify models containing authorization-sensitive fields (structural only)."""
        seen: set[Any] = set()
        for _script_url, content in ctx.bundle.scripts:
            for model_match in _MODEL_DEFINITION_PATTERN.finditer(content):
                model = _scrub_token(model_match.group("model") or model_match.group("assigned") or "").strip()
                window = content[model_match.start() : model_match.start() + 400]
                fields = tuple(
                    sorted({name for name in _MASS_ASSIGNMENT_FIELDS if name in window.lower()})
                )
                if not fields:
                    continue
                key = (model, fields)
                if key in seen:
                    continue
                seen.add(key)
                analysis.mass_assignment.append(
                    AuthzMassAssignmentObservation(
                        origin=ctx.origin,
                        model=model,
                        fields=fields,
                        indicators=(f"js-indicator:mass-assignment:{model}",),
                        confidence=_CONF_WEAK,
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.JS_INDICATOR,
                                model,
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="model exposes authorization-sensitive fields",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )

    def _build_access_controls(self, analysis: AuthorizationAnalysis, ctx: _Context) -> None:
        """Synthesize evidence-backed access-control relationships."""
        seen: set[Any] = set()
        for role in analysis.roles:
            for permission in analysis.permissions:
                key = ("role", role.name, permission.name)
                if key in seen:
                    continue
                seen.add(key)
                analysis.access_controls.append(
                    AuthzAccessControlObservation(
                        origin=ctx.origin,
                        subject=role.name,
                        relationship_type="role",
                        target=permission.name,
                        resource=permission.resource,
                        indicators=(f"correlation:role->permission:{role.name}:{permission.name}",),
                        confidence=min(role.confidence, permission.confidence),
                        evidence=(
                            make_evidence(
                                AuthzEvidenceType.TIDB_INTELLIGENCE,
                                f"{role.name}->{permission.name}",
                                source="authorization",
                                strength=_WEAK,
                                tool_id=ctx.bundle.tool_id,
                                detail="role-permission association synthesized from evidence",
                            ),
                        ),
                        source=ctx.bundle.source,
                        tool_id=ctx.bundle.tool_id,
                        target_key=ctx.bundle.target,
                    )
                )


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Context:
    """Normalized context derived once from the input bundle."""

    bundle: AuthorizationInput
    headers: dict[str, str]
    html_lower: str
    origin: str

    def __init__(self, bundle: AuthorizationInput) -> None:
        self.bundle = bundle
        self.headers = {str(name).lower(): str(value) for name, value in bundle.headers}
        self.html_lower = (bundle.html or "").lower()
        self.origin = origin_of(bundle.url) or _origin_from_target(bundle.target)


def _origin_from_target(target: str) -> str:
    """Return an origin-like value for a bare hostname/domain target."""
    return str(target).strip()


# ---------------------------------------------------------------------------
# regex tables
# ---------------------------------------------------------------------------

#: Subject identifiers in script configuration/claims (evidence-backed only).
_SUBJECT_PATTERN = re.compile(
    r"""(?:currentUser|profile|session\.user|user)\s*[.:=]\s*[\{'\"]?\s*
        (?:id\s*[:\"']\s*)?(?P<name>[A-Za-z0-9_.-]{2,64})""",
    re.VERBOSE | re.IGNORECASE,
)

_ROLE_PATTERN = re.compile(
    r"""(?:roles|role|userRole|requiredRoles?)\s*[:=(\[][\s\[\]'"]*
        (?P<name>[A-Za-z0-9_.-]{2,64})""",
    re.VERBOSE | re.IGNORECASE,
)

_GROUP_PATTERN = re.compile(
    r"""(?:groups|userGroups|memberOf|teamIds)\s*[:=(\[][\s\[\]'"]*
        (?P<name>[A-Za-z0-9_.-]{2,64})""",
    re.VERBOSE | re.IGNORECASE,
)

_PERMISSION_PATTERN = re.compile(
    r"""(?:permissions|hasPermission|can|permission)\s*[:=(\[][\s\[\]'"]*
        (?P<name>[a-z][a-z0-9_.-]{1,80}(?:\.[a-z][a-z0-9_.-]{1,80})+|\b[a-z][a-z0-9_-]{2,40})""",
    re.VERBOSE | re.IGNORECASE,
)

_SCOPE_PATTERN = re.compile(
    r"""(?:scopes?|requiredScopes?)\s*[:=(\[][\s\[\]'"]*
        (?P<name>[a-zA-Z][a-zA-Z0-9_.:-]{1,80})""",
    re.VERBOSE | re.IGNORECASE,
)

_CLAIM_PATTERN = re.compile(
    r"""(?:claims?|jwt\.claims?)\s*[.:=(\[][\s\[\]'"]*
        (?P<name>[a-zA-Z][a-zA-Z0-9_.-]{1,64})""",
    re.VERBOSE | re.IGNORECASE,
)

_TENANT_CLAIM_PATTERN = re.compile(
    r"""(?:tenantId|organizationId|workspaceId|accountId|tenant)\s*[.:=(\[]\s*
        (?:[\"'\[]\s*)?(?P<name>[a-zA-Z0-9_.:-]{1,64})""",
    re.VERBOSE | re.IGNORECASE,
)

_OWNERSHIP_PATTERN = re.compile(
    r"""(?:ownerId|owner_id|createdBy|created_by|updatedBy|author|creator|userId|user_id|accountId|account_id)\s*[.:=]""",
    re.IGNORECASE,
)

#: Ownership field names matched against HTML and JS context.
_OWNERSHIP_FIELDS = (
    "owner_id",
    "user_id",
    "account_id",
    "tenant_id",
    "organization_id",
    "created_by",
    "updated_by",
    "author",
    "creator",
    "principal",
    "subject",
    "owner",
    "member",
    "manager",
    "administrator",
)

_TENANT_HEADERS = (
    "x-tenant-id",
    "x-tenant",
    "x-organization-id",
    "x-org-id",
    "x-account-id",
    "x-workspace-id",
    "x-project-id",
    "x-client-id",
)

_TENANT_QUERY_PARAMS = ("tenant_id", "organization_id", "workspace_id", "account_id", "project_id", "org_id")

#: Restricted fields that indicate field-level access control.
_RESTRICTED_FIELDS = (
    "role",
    "roles",
    "permissions",
    "owner_id",
    "tenant_id",
    "billing",
    "is_admin",
    "security_settings",
    "api_keys",
    "tokens",
    "internal_id",
    "audit",
    "privileged_configuration",
    "account_type",
    "privilege",
)

#: Mass-assignment sensitive fields.
_MASS_ASSIGNMENT_FIELDS = (
    "role",
    "roles",
    "permissions",
    "owner",
    "owner_id",
    "tenant",
    "tenant_id",
    "is_admin",
    "status",
    "account_type",
    "privilege",
)

_MODEL_DEFINITION_PATTERN = re.compile(
    r"""(?:class|type|interface|model|schema)\s+(?P<model>[A-Za-z_][A-Za-z0-9_]{1,64})|(?:const|let|var)\s+(?P<assigned>[A-Za-z_][A-Za-z0-9_]{1,64})\s*=\s*class\b""",
    re.IGNORECASE,
)

_FIELD_LEVEL_PATTERN = re.compile(
    r"""(?P<name>is_admin|isAdmin|account_type|security_settings|privileged_configuration|internal_id)\b""",
    re.IGNORECASE,
)

_ADMIN_ROUTE_PATTERN = re.compile(
    r"""(?:path|route)\s*[:=]\s*[\"'](?P<route>[^\"']*(?:admin|manage|console|backoffice|internal)[^\"']*)[\"']""",
    re.IGNORECASE,
)

_ACTION_VERB_PATTERN = re.compile(
    r"""/(?P<verb>create|update|delete|disable|enable|rotate|invite|assign|revoke|export|import|approve|publish|deploy|execute|configure|administer)(?:/|$|\?)""",
    re.IGNORECASE,
)

_RESOURCE_NAME_PATTERN = re.compile(
    r"""(?:manage|list|view|my)\s+([a-z][a-z-]{2,30})(?:s|es)\b|/api/(?:v\d/)?([a-z][a-z-]{2,30})(?:s|es)""",
    re.IGNORECASE,
)

_GRAPHQL_DIRECTIVE_PATTERN = re.compile(
    r"@(?P<directive>auth|authorized|hasRole|hasPermission|hasScope|authz|requires)",
    re.IGNORECASE,
)

_SERVICE_PATTERN = re.compile(
    r"""(?:serviceAccount|service_account|apiClient|api_client|clientCredentials|client_credentials|machineIdentity|machine_identity)\s*[.:=\[](?:[\"'\[]\s*)?(?P<name>[A-Za-z0-9_.-]{2,64})""",
    re.VERBOSE | re.IGNORECASE,
)

_FRONTEND_CHECKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("isAdmin", re.compile(r"\bisAdmin\b", re.IGNORECASE)),
    ("hasPermission", re.compile(r"\bhasPermission\s*\(", re.IGNORECASE)),
    ("hasRole", re.compile(r"\bhasRole\s*\(", re.IGNORECASE)),
    ("can", re.compile(r"\bcan\s*\(\s*['\"]", re.IGNORECASE)),
    ("authorize", re.compile(r"\bauthorize\s*\(", re.IGNORECASE)),
    ("checkAccess", re.compile(r"\bcheckAccess\s*\(", re.IGNORECASE)),
    ("featureFlag", re.compile(r"\bfeatureFlag\b|feature_flags?\b", re.IGNORECASE)),
)

_ROUTE_GUARD_PATTERN = re.compile(
    r"""(?:path|route)\s*[:=]\s*[\"'](?P<route>[^\"']+)[\"'][\s\S]{0,160}
        (?:meta|guard|roles|permissions|requires)\s*[:=]\s*[\"'(](?P<guard>[A-Za-z0-9_.-]{1,64})""",
    re.VERBOSE | re.IGNORECASE,
)

_BACKEND_SIGNALS: tuple[tuple[str, str], ...] = (
    ("@requires_role", "decorator"),
    ("@requires_permission", "decorator"),
    ("@permission_required", "decorator"),
    ("@roles_required", "decorator"),
    ("@admin_required", "decorator"),
    ("authorize(", "middleware"),
    ("require_permission", "middleware"),
    ("require_role", "middleware"),
    ("check_permissions", "middleware"),
    ("casbin", "policy-engine"),
    ("open-policy-agent", "policy-engine"),
    ("opa", "policy-engine"),
    ("keycloak", "policy-engine"),
    ("authz", "policy-engine"),
    ("policymiddleware", "middleware"),
    ("permissionmiddleware", "middleware"),
    ("authorizationmiddleware", "middleware"),
    ("role_guard", "guard"),
    ("permission_guard", "guard"),
)

#: Policy model signals: keyword -> model kind.
_POLICY_MODEL_SIGNALS: tuple[tuple[str, PolicyModelKind], ...] = (
    ("rbac", PolicyModelKind.RBAC),
    ("role-based", PolicyModelKind.RBAC),
    ("rolebased", PolicyModelKind.RBAC),
    ("abac", PolicyModelKind.ABAC),
    ("attribute-based", PolicyModelKind.ABAC),
    ("acl", PolicyModelKind.ACL),
    ("access control list", PolicyModelKind.ACL),
    ("pbac", PolicyModelKind.PBAC),
    ("policy-based", PolicyModelKind.PBAC),
    ("rebac", PolicyModelKind.REBAC),
    ("relationship-based", PolicyModelKind.REBAC),
    ("casbin", PolicyModelKind.CUSTOM),
    ("open-policy-agent", PolicyModelKind.CUSTOM),
    ("opa", PolicyModelKind.CUSTOM),
    ("cerbos", PolicyModelKind.CUSTOM),
    ("permit.io", PolicyModelKind.CUSTOM),
)

#: Privileged function indicators: keyword -> function label.
_PRIVILEGED_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("/admin", "administer"),
    ("/manage", "manage"),
    ("/internal", "manage"),
    ("/backoffice", "manage"),
    ("/console", "manage"),
    ("roles", "role-assignment"),
    ("/permissions", "permission-management"),
    ("users/", "user-management"),
    ("/user-management", "user-management"),
    ("/members", "user-management"),
    ("/invite", "invite"),
    ("/configuration", "configuration-change"),
    ("/config", "configuration-change"),
    ("/deploy", "deploy"),
    ("/billing", "billing"),
    ("/invoices", "billing"),
    ("/security", "security-settings"),
    ("/credentials", "credential-management"),
    ("/secrets", "credential-management"),
    ("/api-keys", "credential-management"),
    ("/apikeys", "credential-management"),
    ("/integrations", "integration-management"),
    ("/webhooks", "webhook-management"),
    ("/export", "export"),
    ("/import", "import"),
    ("/audit", "audit-access"),
    ("/audit-logs", "audit-access"),
)

#: Admin-surface URL tokens -> kind.
_ADMIN_SURFACE_TOKENS: tuple[tuple[str, AdminSurfaceKind], ...] = (
    ("/admin/login", AdminSurfaceKind.ADMIN_LOGIN),
    ("/admin/api", AdminSurfaceKind.ADMIN_API),
    ("/api/admin", AdminSurfaceKind.ADMIN_API),
    ("/api/v1/admin", AdminSurfaceKind.ADMIN_API),
    ("/management-api", AdminSurfaceKind.MANAGEMENT_API),
    ("/manage-api", AdminSurfaceKind.MANAGEMENT_API),
    ("/admin", AdminSurfaceKind.ADMIN_UI),
    ("/manage", AdminSurfaceKind.ADMIN_UI),
    ("/backoffice", AdminSurfaceKind.ADMIN_UI),
    ("/console", AdminSurfaceKind.ADMIN_UI),
    ("/internal", AdminSurfaceKind.ADMIN_UI),
    ("/roles", AdminSurfaceKind.ROLE_MANAGEMENT),
    ("/role-management", AdminSurfaceKind.ROLE_MANAGEMENT),
    ("/permissions", AdminSurfaceKind.PERMISSION_MANAGEMENT),
    ("/permission-management", AdminSurfaceKind.PERMISSION_MANAGEMENT),
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
)

#: Static resource-kind keywords -> kind.
_RESOURCE_KIND_KEYWORDS: tuple[tuple[str, ResourceKind], ...] = (
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
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _resources_from_url(url: str) -> list[tuple[str, ResourceKind]]:
    """Return ``(name, kind)`` resource candidates from a URL path."""
    results: list[tuple[str, ResourceKind]] = []
    for segment in _path_segments(url):
        lowered = segment.lower()
        for keyword, kind in _RESOURCE_KIND_KEYWORDS:
            if lowered == keyword or lowered == f"{keyword}s":
                results.append((lowered, kind))
                break
    return results


def _admin_surface_kinds(url: str) -> list[AdminSurfaceKind]:
    lowered = url.lower()
    kinds: list[AdminSurfaceKind] = []
    for token, kind in _ADMIN_SURFACE_TOKENS:
        if token in lowered:
            kinds.append(kind)
    return kinds


def _subject_kind(name: str) -> SubjectKind:
    lowered = name.lower()
    if any(token in lowered for token in ("service_account", "service-account", "svc_")):
        return SubjectKind.SERVICE_ACCOUNT
    if any(token in lowered for token in ("api_client", "api-client", "client_id")):
        return SubjectKind.API_CLIENT
    if lowered in ("anonymous", "guest", "public"):
        return SubjectKind.ANONYMOUS
    if "application" in lowered:
        return SubjectKind.APPLICATION
    return SubjectKind.USER


def _role_custom(name: str) -> bool:
    lowered = name.lower()
    default = {
        "admin",
        "administrator",
        "superuser",
        "owner",
        "manager",
        "editor",
        "developer",
        "analyst",
        "viewer",
        "guest",
        "member",
        "operator",
        "auditor",
        "service",
    }
    return lowered not in default


def _permission_parts(name: str) -> tuple[str, str]:
    if "." in name:
        parts = name.split(".")
        action = parts[0] if len(parts) >= 2 else ""
        resource = ".".join(parts[1:])
        return action, resource
    return "", ""


def _normalize_action(verb: str) -> str:
    lowered = verb.lower()
    for action in ActionKind:
        if action.value == lowered:
            return action.value
    return ActionKind.OTHER.value


def _method_action(method: str) -> str:
    mapping = {
        "GET": ActionKind.READ.value,
        "POST": ActionKind.CREATE.value,
        "PUT": ActionKind.UPDATE.value,
        "PATCH": ActionKind.UPDATE.value,
        "DELETE": ActionKind.DELETE.value,
        "HEAD": ActionKind.READ.value,
    }
    return mapping.get(method.upper(), ActionKind.EXECUTE.value)


def _operation_resource_action(endpoint: str, method: str) -> tuple[str, str]:
    segments = _path_segments(endpoint)
    resource = ""
    for segment in segments:
        if not _looks_like_identifier(segment):
            resource = segment
            break
    return resource, _method_action(method)


def _identifier_kind(value: str) -> IdentifierKind:
    lowered = value.lower()
    if _looks_like_uuid(lowered):
        return IdentifierKind.UUID
    if lowered.startswith("01") and len(lowered) == 26 and lowered.isalnum():
        return IdentifierKind.ULID
    if re.fullmatch(r"[0-9a-f]{8,128}", lowered):
        return IdentifierKind.HASH
    if re.fullmatch(r"\d{1,20}", lowered):
        return IdentifierKind.NUMERIC
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", lowered):
        return IdentifierKind.SLUG
    if "{" in value or "}" in value or ":" in value:
        return IdentifierKind.COMPOSITE
    return IdentifierKind.OPAQUE


def _looks_like_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _looks_like_identifier(value: str) -> bool:
    if not value or len(value) > 128:
        return False
    lowered = value.lower()
    if lowered in ("api", "v1", "v2", "assets", "static", "public", "health", "status", "admin", "login"):
        return False
    if re.fullmatch(r"[a-z0-9-]{1,20}", lowered) and not re.search(r"\d", lowered):
        return False
    return bool(
        re.search(r"\d", lowered)
        or _looks_like_uuid(value)
        or "{" in value
        or ":" in value
        or len(value) >= 16
    )


def _path_segments(url: str) -> list[str]:
    import urllib.parse

    try:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path
    except ValueError:
        path = url
    return [segment for segment in path.split("/") if segment and segment not in ("api", "v1", "v2", "v3")]


def _query_parameters(url: str) -> list[tuple[str, str]]:
    import urllib.parse

    try:
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        query = ""
    return list(urllib.parse.parse_qsl(query))


def _html_text(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html or "")


def _context_around(content: str, position: int, radius: int = 48) -> str:
    start = max(0, position - radius)
    end = min(len(content), position + radius)
    return content[start:end]


def _mask(value: str) -> str:
    return mask_value(_scrub_token(value), reveal_head=8, reveal_tail=8)


def _scrub_token(value: str) -> str:
    return _TOKEN_LITERAL.sub("[MASKED]", value)


def _security_from_operation(operation: dict[str, object]) -> str:
    security = operation.get("security") or operation.get("authentication") or operation.get("scheme")
    if isinstance(security, str):
        return security
    if isinstance(security, (list, tuple)):
        return ",".join(str(item) for item in security if item)
    return ""


def _requirements_from_operation(operation: dict[str, object]) -> tuple[list[str], list[str], list[str]]:
    roles = _as_str_list(operation.get("roles"))
    scopes = _as_str_list(operation.get("scopes") or operation.get("scope"))
    permissions = _as_str_list(operation.get("permissions") or operation.get("permission"))
    return roles, scopes, permissions


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if item]
    return []


def _scheme_scopes(scheme: dict[str, object]) -> list[str]:
    flow = scheme.get("flows") or {}
    scopes: list[str] = []
    if isinstance(flow, dict):
        for _flow_name, flow_value in flow.items():
            if isinstance(flow_value, dict):
                flow_scopes = flow_value.get("scopes")
                if isinstance(flow_scopes, dict):
                    scopes.extend(str(key) for key in flow_scopes)
                elif isinstance(flow_scopes, (list, tuple)):
                    scopes.extend(str(item) for item in flow_scopes)
    return sorted(set(scopes))


def _ownership_kind(name: str) -> OwnershipKind:
    lowered = name.lower()
    mapping: dict[str, OwnershipKind] = {
        "owner_id": OwnershipKind.OWNER_ID,
        "owner": OwnershipKind.OWNER,
        "user_id": OwnershipKind.USER_ID,
        "account_id": OwnershipKind.ACCOUNT_ID,
        "tenant_id": OwnershipKind.TENANT_ID,
        "organization_id": OwnershipKind.ORGANIZATION_ID,
        "created_by": OwnershipKind.CREATED_BY,
        "updated_by": OwnershipKind.UPDATED_BY,
        "author": OwnershipKind.AUTHOR,
        "creator": OwnershipKind.CREATOR,
        "principal": OwnershipKind.PRINCIPAL,
        "subject": OwnershipKind.SUBJECT,
        "member": OwnershipKind.MEMBER,
        "manager": OwnershipKind.MANAGER,
        "administrator": OwnershipKind.ADMINISTRATOR,
    }
    return mapping.get(lowered, OwnershipKind.UNKNOWN)


def _service_kind(name: str, content: str, position: int) -> tuple[str, str]:
    lowered = content.lower()
    window = lowered[max(0, position - 40) : position + 40]
    if "client_credentials" in window or "client-credentials" in window or "client credentials" in window:
        return "api-client", "client-credentials"
    if "mtls" in window or "mutual_tls" in window:
        return "machine-identity", "mtls"
    if "service_account" in window or "service-account" in window:
        return "service-account", "service-account"
    return "machine-identity", "unknown"


# ---------------------------------------------------------------------------
# document / scheme / operation sub-detectors
# ---------------------------------------------------------------------------


def _subjects_from_document(
    analysis: AuthorizationAnalysis,
    document: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    for key in ("subjects", "principals", "service_accounts", "service_account"):
        value = document.get(key)
        for name in _as_str_list(value):
            if name in seen:
                continue
            seen.add(name)
            analysis.subjects.append(
                AuthzSubjectObservation(
                    origin=ctx.origin,
                    name=name,
                    subject_kind=SubjectKind.UNKNOWN,
                    indicators=(f"documentation:subject:{name}",),
                    confidence=_CONF_WEAK,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.DOCUMENTATION,
                            name,
                            source="authorization",
                            strength=_WEAK,
                            tool_id=ctx.bundle.tool_id,
                            detail="subject declared in policy documentation",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )


def _subjects_from_scheme(
    analysis: AuthorizationAnalysis,
    scheme: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    name = str(scheme.get("name") or scheme.get("scheme_name") or "")
    if not name or name in seen:
        return
    if "client" in str(scheme.get("type") or "").lower() or "client" in name.lower():
        seen.add(name)
        analysis.subjects.append(
            AuthzSubjectObservation(
                origin=ctx.origin,
                name=name,
                subject_kind=SubjectKind.API_CLIENT,
                indicators=(f"openapi-security:client:{name}",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        AuthzEvidenceType.OPENAPI_SECURITY,
                        name,
                        source="authorization",
                        strength=_MODERATE,
                        tool_id=ctx.bundle.tool_id,
                        detail="API client identity declared in OpenAPI security scheme",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )


def _roles_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    roles, _scopes, _permissions = _requirements_from_operation(operation)
    for name in roles:
        if name in seen:
            continue
        seen.add(name)
        analysis.roles.append(
            AuthzRoleObservation(
                origin=ctx.origin,
                name=name,
                custom=_role_custom(name),
                indicators=(f"api-operation:role:{name}",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        AuthzEvidenceType.API_OPERATION,
                        name,
                        source="authorization",
                        strength=_MODERATE,
                        tool_id=ctx.bundle.tool_id,
                        detail="role requirement declared on API operation",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )


def _permissions_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    _roles, _scopes, permissions = _requirements_from_operation(operation)
    for name in permissions:
        if name in seen:
            continue
        seen.add(name)
        action, resource = _permission_parts(name)
        analysis.permissions.append(
            AuthzPermissionObservation(
                origin=ctx.origin,
                name=name,
                action=action,
                resource=resource,
                indicators=(f"api-operation:permission:{name}",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        AuthzEvidenceType.API_OPERATION,
                        name,
                        source="authorization",
                        strength=_MODERATE,
                        tool_id=ctx.bundle.tool_id,
                        detail="permission requirement declared on API operation",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )


def _scopes_from_scheme(
    analysis: AuthorizationAnalysis,
    scheme: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    for name in _scheme_scopes(scheme):
        if name in seen:
            continue
        seen.add(name)
        analysis.scopes.append(
            AuthzScopeObservation(
                origin=ctx.origin,
                name=name,
                indicators=(f"openapi-security:scope:{name}",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        AuthzEvidenceType.OPENAPI_SECURITY,
                        name,
                        source="authorization",
                        strength=_MODERATE,
                        tool_id=ctx.bundle.tool_id,
                        detail="scope declared in OpenAPI security scheme",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )


def _scopes_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    _roles, scopes, _permissions = _requirements_from_operation(operation)
    for name in scopes:
        if name in seen:
            continue
        seen.add(name)
        analysis.scopes.append(
            AuthzScopeObservation(
                origin=ctx.origin,
                name=name,
                indicators=(f"api-operation:scope:{name}",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        AuthzEvidenceType.API_OPERATION,
                        name,
                        source="authorization",
                        strength=_MODERATE,
                        tool_id=ctx.bundle.tool_id,
                        detail="scope requirement declared on API operation",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )


def _claims_from_document(
    analysis: AuthorizationAnalysis,
    document: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    for key in ("claims", "required_claims", "role_claims", "permission_claims"):
        for name in _as_str_list(document.get(key)):
            if name in seen:
                continue
            seen.add(name)
            analysis.claims.append(
                AuthzClaimObservation(
                    origin=ctx.origin,
                    name=name,
                    indicators=(f"documentation:claim:{name}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.DOCUMENTATION,
                            name,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="authorization claim declared in policy documentation",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )


def _policies_from_document(
    analysis: AuthorizationAnalysis,
    document: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    policy_model = str(document.get("policy_model") or document.get("model") or "").lower()
    if not policy_model:
        return
    try:
        model_kind = PolicyModelKind(policy_model)
    except ValueError:
        model_kind = PolicyModelKind.CUSTOM
    name = str(document.get("name") or policy_model)
    key = (model_kind.value, name)
    if key in seen:
        return
    seen.add(key)
    analysis.policies.append(
        AuthzPolicyObservation(
            origin=ctx.origin,
            name=name,
            model_kind=model_kind,
            mechanism="documentation",
            indicators=(f"documentation:policy-model:{policy_model}",),
            confidence=_CONF_MODERATE,
            evidence=(
                make_evidence(
                    AuthzEvidenceType.DOCUMENTATION,
                    policy_model,
                    source="authorization",
                    strength=_MODERATE,
                    tool_id=ctx.bundle.tool_id,
                    detail="policy model declared in documentation",
                ),
            ),
            source=ctx.bundle.source,
            tool_id=ctx.bundle.tool_id,
            target_key=ctx.bundle.target,
        )
    )


def _policies_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    policy_model = str(operation.get("policy") or operation.get("policy_model") or "").lower()
    if not policy_model:
        return
    try:
        model_kind = PolicyModelKind(policy_model)
    except ValueError:
        model_kind = PolicyModelKind.CUSTOM
    key = (model_kind.value, policy_model)
    if key in seen:
        return
    seen.add(key)
    analysis.policies.append(
        AuthzPolicyObservation(
            origin=ctx.origin,
            name=policy_model,
            model_kind=model_kind,
            mechanism="api-operation",
            indicators=(f"api-operation:policy:{policy_model}",),
            confidence=_CONF_MODERATE,
            evidence=(
                make_evidence(
                    AuthzEvidenceType.API_OPERATION,
                    policy_model,
                    source="authorization",
                    strength=_MODERATE,
                    tool_id=ctx.bundle.tool_id,
                    detail="policy model declared on API operation",
                ),
            ),
            source=ctx.bundle.source,
            tool_id=ctx.bundle.tool_id,
            target_key=ctx.bundle.target,
        )
    )


def _resources_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    endpoint = str(operation.get("path") or operation.get("endpoint") or "")
    resource, _action = _operation_resource_action(endpoint, "GET")
    if not resource:
        return
    name = resource.lower()
    key = (ResourceKind.UNKNOWN.value, name)
    if key in seen:
        return
    seen.add(key)
    analysis.resources.append(
        AuthzResourceObservation(
            origin=ctx.origin,
            name=name,
            resource_kind=ResourceKind.OTHER,
            indicators=(f"api-operation:resource:{name}",),
            confidence=_CONF_MODERATE,
            evidence=(
                make_evidence(
                    AuthzEvidenceType.API_OPERATION,
                    name,
                    source="authorization",
                    strength=_MODERATE,
                    tool_id=ctx.bundle.tool_id,
                    detail="resource declared on API operation",
                ),
            ),
            source=ctx.bundle.source,
            tool_id=ctx.bundle.tool_id,
            target_key=ctx.bundle.target,
        )
    )


def _identifiers_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    endpoint = str(operation.get("path") or operation.get("endpoint") or "")
    for segment in _path_segments(endpoint):
        placeholder = segment.strip("{}")
        if (
            "{" in segment
            or placeholder.endswith("_id")
            or placeholder.endswith("-id")
            or placeholder in ("id", "uid", "uuid")
        ):
            kind = IdentifierKind.PATH
            key = (kind.value, endpoint, segment)
            if key in seen:
                continue
            seen.add(key)
            analysis.identifiers.append(
                AuthzResourceIdentifierObservation(
                    origin=ctx.origin,
                    identifier=segment,
                    identifier_kind=kind,
                    location="path",
                    endpoint=endpoint,
                    indicators=(f"api-operation:identifier:{segment}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.API_OPERATION,
                            segment,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="path identifier declared on API operation",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )


def _ownership_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    for key_name in ("owner_fields", "ownership", "ownership_fields"):
        for name in _as_str_list(operation.get(key_name)):
            if name in seen:
                continue
            seen.add(name)
            analysis.ownership.append(
                AuthzOwnershipObservation(
                    origin=ctx.origin,
                    name=name,
                    ownership_kind=_ownership_kind(name),
                    resource=str(operation.get("path") or operation.get("resource") or ""),
                    indicators=(f"api-operation:ownership:{name}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.API_OPERATION,
                            name,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="ownership indicator declared on API operation",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )


def _function_level_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    endpoint = str(operation.get("path") or operation.get("endpoint") or "")
    lowered = endpoint.lower()
    privileged = operation.get("privileged")
    if privileged not in (True, "true", "yes") and not any(
        keyword in lowered for keyword, _ in _PRIVILEGED_FUNCTIONS
    ):
        return
    function = str(operation.get("function") or "privileged-function")
    key = (endpoint, function)
    if key in seen:
        return
    seen.add(key)
    roles, _scopes, _permissions = _requirements_from_operation(operation)
    analysis.function_level.append(
        AuthzFunctionLevelObservation(
            origin=ctx.origin,
            function=function,
            endpoint=endpoint,
            method=str(operation.get("method", "GET")).upper(),
            required_role=",".join(roles),
            indicators=(f"api-operation:privileged:{function}",),
            confidence=_CONF_MODERATE,
            evidence=(
                make_evidence(
                    AuthzEvidenceType.API_OPERATION,
                    endpoint,
                    source="authorization",
                    strength=_MODERATE,
                    tool_id=ctx.bundle.tool_id,
                    detail="privileged function declared on API operation",
                ),
            ),
            source=ctx.bundle.source,
            tool_id=ctx.bundle.tool_id,
            target_key=ctx.bundle.target,
        )
    )


def _object_level_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    endpoint = str(operation.get("path") or operation.get("endpoint") or "")
    segments = _path_segments(endpoint)
    resource = ""
    identifier = ""
    for index, segment in enumerate(segments):
        placeholder = segment.strip("{}")
        if "{" in segment or placeholder in ("id", "uid", "uuid") or placeholder.endswith("_id"):
            resource = segments[index - 1] if index > 0 else ""
            identifier = segment
            break
    if not resource:
        return
    method = str(operation.get("method", "GET")).upper()
    key = (endpoint, resource)
    if key in seen:
        return
    seen.add(key)
    analysis.object_level.append(
        AuthzObjectLevelObservation(
            origin=ctx.origin,
            resource=resource,
            identifier=identifier,
            action=_method_action(method),
            endpoint=endpoint,
            method=method,
            indicators=(f"api-operation:object-level:{resource}",),
            confidence=_CONF_MODERATE,
            evidence=(
                make_evidence(
                    AuthzEvidenceType.API_OPERATION,
                    endpoint,
                    source="authorization",
                    strength=_MODERATE,
                    tool_id=ctx.bundle.tool_id,
                    detail="object-level endpoint declared on API operation",
                ),
            ),
            source=ctx.bundle.source,
            tool_id=ctx.bundle.tool_id,
            target_key=ctx.bundle.target,
        )
    )


def _field_level_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    for key_name in ("restricted_fields", "fields"):
        for name in _as_str_list(operation.get(key_name)):
            if name not in _RESTRICTED_FIELDS:
                continue
            if name in seen:
                continue
            seen.add(name)
            analysis.field_level.append(
                AuthzFieldLevelObservation(
                    origin=ctx.origin,
                    field=name,
                    resource=str(operation.get("path") or operation.get("resource") or ""),
                    endpoint=str(operation.get("path") or operation.get("endpoint") or ""),
                    indicators=(f"api-operation:field-level:{name}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.API_OPERATION,
                            name,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="restricted field declared on API operation",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )


def _field_level_from_graphql(
    analysis: AuthorizationAnalysis,
    record: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    for name in _as_str_list(record.get("restricted_fields")):
        if name not in _RESTRICTED_FIELDS:
            continue
        if name in seen:
            continue
        seen.add(name)
        analysis.field_level.append(
            AuthzFieldLevelObservation(
                origin=ctx.origin,
                field=name,
                resource=str(record.get("type") or ""),
                endpoint=str(record.get("name") or ""),
                indicators=(f"graphql:field-level:{name}",),
                confidence=_CONF_MODERATE,
                evidence=(
                    make_evidence(
                        AuthzEvidenceType.GRAPHQL,
                        name,
                        source="authorization",
                        strength=_MODERATE,
                        tool_id=ctx.bundle.tool_id,
                        detail="restricted field declared in GraphQL metadata",
                    ),
                ),
                source=ctx.bundle.source,
                tool_id=ctx.bundle.tool_id,
                target_key=ctx.bundle.target,
            )
        )


def _backend_from_operation(
    analysis: AuthorizationAnalysis,
    operation: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    mechanism = str(operation.get("authorization_mechanism") or operation.get("mechanism") or "").lower()
    if not mechanism:
        return
    name = str(operation.get("path") or operation.get("endpoint") or "")
    key = (mechanism, name)
    if key in seen:
        return
    seen.add(key)
    analysis.backend.append(
        AuthzBackendObservation(
            origin=ctx.origin,
            mechanism=mechanism,
            name=name,
            target=name,
            indicators=(f"api-operation:backend:{mechanism}",),
            confidence=_CONF_MODERATE,
            evidence=(
                make_evidence(
                    AuthzEvidenceType.API_OPERATION,
                    mechanism,
                    source="authorization",
                    strength=_MODERATE,
                    tool_id=ctx.bundle.tool_id,
                    detail="backend authorization mechanism declared on API operation",
                ),
            ),
            source=ctx.bundle.source,
            tool_id=ctx.bundle.tool_id,
            target_key=ctx.bundle.target,
        )
    )


def _services_from_document(
    analysis: AuthorizationAnalysis,
    document: dict[str, object],
    ctx: _Context,
    seen: set[Any],
) -> None:
    for key in ("service_accounts", "service_account", "api_clients", "machine_identities"):
        for name in _as_str_list(document.get(key)):
            if name in seen:
                continue
            seen.add(name)
            analysis.services.append(
                AuthzServiceObservation(
                    origin=ctx.origin,
                    name=name,
                    service_kind="service-account" if "service" in key else "api-client",
                    mechanism="unknown",
                    indicators=(f"documentation:service:{name}",),
                    confidence=_CONF_MODERATE,
                    evidence=(
                        make_evidence(
                            AuthzEvidenceType.DOCUMENTATION,
                            name,
                            source="authorization",
                            strength=_MODERATE,
                            tool_id=ctx.bundle.tool_id,
                            detail="service identity declared in policy documentation",
                        ),
                    ),
                    source=ctx.bundle.source,
                    tool_id=ctx.bundle.tool_id,
                    target_key=ctx.bundle.target,
                )
            )
