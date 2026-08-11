# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization & access-control intelligence TIDB entities.

System-of-record entities for the Wave 10 authorization intelligence
capability (Sprint 016). They carry the canonical, evidence-backed
authorization inventory of an authorized target: subjects, roles, groups,
permissions, scopes, claims, policies, resources, actions, resource-identifier
metadata, ownership relationships, tenant boundaries, administrative surfaces,
function/object/field-level access-control indicators, frontend/backend
authorization logic, API authorization correlation, GraphQL/WebSocket/service
authorization, decision indicators, mass-assignment fields and the derived
intelligence (observations, evidence, changes and run records).

Security boundary: intelligence only. These entities store metadata and
masked/derived values — never raw passwords, access/refresh tokens, session
cookie values, API secrets, authorization-header values, JWT claims or PII.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class AuthorizationRun(TidbEntity):
    """Observability record for an authorization intelligence run.

    Attributes:
        mission_id: owning mission id.
        target_key: canonical target the run covered.
        target_id: owning target record id.
        status: terminal run status.
        mode: execution posture (passive/active/hybrid).
        subjects / roles / permissions / resources / actions / admin_surfaces /
            function_level / object_level / field_level / changes / conflicts:
            artifact counts.
        started_at / completed_at / duration_ms: timing.
        summary: free-form run summary (tools, stats).
        correlation_id: correlation id of the run.

    """

    mission_id: str = ""
    target_key: str = ""
    target_id: str | None = None
    status: str = "running"
    mode: str = "hybrid"
    subjects: int = 0
    roles: int = 0
    permissions: int = 0
    resources: int = 0
    actions: int = 0
    admin_surfaces: int = 0
    function_level: int = 0
    object_level: int = 0
    field_level: int = 0
    changes: int = 0
    conflicts: int = 0
    started_at: str = ""
    completed_at: str | None = None
    duration_ms: int = 0
    summary: dict[str, object] = dc_field(default_factory=dict)
    correlation_id: str = ""


@dataclass(slots=True)
class AuthorizationSubject(TidbEntity):
    """A discovered authorization subject (evidence-backed, never fabricated)."""

    origin: str = ""
    name: str = ""
    subject_kind: str = "unknown"
    context: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationRole(TidbEntity):
    """A discovered role identifier."""

    origin: str = ""
    name: str = ""
    context: str = ""
    default: bool = False
    custom: bool = False
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationGroup(TidbEntity):
    """A discovered authorization group."""

    origin: str = ""
    name: str = ""
    context: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationPermission(TidbEntity):
    """A discovered permission identifier."""

    origin: str = ""
    name: str = ""
    action: str = ""
    resource: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationScope(TidbEntity):
    """A discovered OAuth/OIDC/API scope identifier."""

    origin: str = ""
    name: str = ""
    description: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationClaim(TidbEntity):
    """A discovered authorization claim reference (never the claim value)."""

    origin: str = ""
    name: str = ""
    value: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationPolicy(TidbEntity):
    """A discovered authorization policy model/mechanism."""

    origin: str = ""
    name: str = ""
    model_kind: str = "unknown"
    mechanism: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationResource(TidbEntity):
    """A discovered authorization resource."""

    origin: str = ""
    name: str = ""
    resource_kind: str = "unknown"
    identifier: str = ""
    parent: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationAction(TidbEntity):
    """A discovered authorization action (original terminology preserved)."""

    origin: str = ""
    name: str = ""
    original: str = ""
    resource: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationIdentifier(TidbEntity):
    """Resource-identifier metadata (identifiers never modified or accessed)."""

    origin: str = ""
    identifier: str = ""
    identifier_kind: str = "unknown"
    location: str = ""
    endpoint: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationOwnership(TidbEntity):
    """A discovered ownership indicator."""

    origin: str = ""
    name: str = ""
    ownership_kind: str = "unknown"
    resource: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationTenant(TidbEntity):
    """A discovered tenant-boundary indicator."""

    origin: str = ""
    name: str = ""
    tenant_kind: str = "unknown"
    location: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationAdminSurface(TidbEntity):
    """A discovered administrative surface."""

    url: str = ""
    origin: str = ""
    surface_kind: str = "unknown"
    method: str = "GET"
    api_id: str | None = None
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.5
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationFunctionLevel(TidbEntity):
    """A function-level access-control indicator."""

    origin: str = ""
    function: str = ""
    endpoint: str = ""
    method: str = "GET"
    required_role: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.5
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationObjectLevel(TidbEntity):
    """An object-level access-control indicator."""

    origin: str = ""
    resource: str = ""
    identifier: str = ""
    action: str = ""
    endpoint: str = ""
    method: str = "GET"
    parent_resource: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.5
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationFieldLevel(TidbEntity):
    """A field-level access-control indicator."""

    origin: str = ""
    field: str = ""
    resource: str = ""
    endpoint: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationFrontend(TidbEntity):
    """A frontend authorization-logic indicator."""

    origin: str = ""
    check_type: str = "unknown"
    target: str = ""
    js_asset: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationBackend(TidbEntity):
    """A backend authorization-logic indicator."""

    origin: str = ""
    mechanism: str = "unknown"
    name: str = ""
    target: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationApiCorrelation(TidbEntity):
    """API authorization correlation for one operation."""

    origin: str = ""
    endpoint: str = ""
    method: str = "GET"
    authentication: str = ""
    role: str = ""
    scope: str = ""
    permission: str = ""
    resource: str = ""
    action: str = ""
    tenant: str = ""
    policy: str = ""
    documented: bool = False
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationGraphQL(TidbEntity):
    """A GraphQL authorization indicator."""

    origin: str = ""
    subject: str = "field"
    name: str = ""
    directive: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationWebSocket(TidbEntity):
    """A WebSocket authorization indicator."""

    origin: str = ""
    endpoint: str = ""
    channel: str = ""
    mechanism: str = "unknown"
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationService(TidbEntity):
    """A service-to-service authorization indicator."""

    origin: str = ""
    name: str = ""
    service_kind: str = "unknown"
    mechanism: str = "unknown"
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationDecision(TidbEntity):
    """An observed/documented authorization decision indicator."""

    origin: str = ""
    decision: str = "unknown"
    endpoint: str = ""
    method: str = "GET"
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.5
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationMassAssignment(TidbEntity):
    """A model exposing authorization-sensitive fields (structural only)."""

    origin: str = ""
    model: str = ""
    fields: list[str] = dc_field(default_factory=list)
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationAccessControl(TidbEntity):
    """An access-control relationship (subject -> role/permission/scope)."""

    origin: str = ""
    subject: str = ""
    relationship_type: str = "role"
    target: str = ""
    resource: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.3
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationObservation(TidbEntity):
    """A generic authorization-adjacent observation."""

    origin: str = ""
    kind: str = "unknown"
    name: str = ""
    value: str = ""
    detail: str = ""
    indicators: list[str] = dc_field(default_factory=list)
    confidence: float = 0.4
    source: str = "authorization"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationEvidence(TidbEntity):
    """One piece of evidence backing authorization intelligence."""

    subject_type: str = "resource"
    subject_id: str = ""
    evidence_type: str = "other"
    value: str = ""
    source: str = "authorization"
    strength: str = "moderate"
    tool_id: str = ""
    detail: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthorizationChange(TidbEntity):
    """A detected temporal change in the authorization surface."""

    subject_type: str = "resource"
    subject: str = ""
    change_type: str = "changed"
    previous: str = ""
    current: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""
