# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack-surface data model.

Phase 1 generic capability model. Every concept here is target-agnostic: a
surface is any discovered, probeable or schedulable thing; a target-specific
business object (a user, an order, a product, ...) is represented *dynamically*
as a :class:`DynamicObject` whose ``object_type`` is an arbitrary string —
never a hardcoded class. The orchestration logic keys off ``SurfaceKind`` and
``SurfaceLayer`` values, so new target shapes never require new code paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.attack_surface.enums import (
    AssessmentStatus,
    AuthContextState,
    CompletionVerdict,
    SurfaceKind,
    SurfaceLayer,
    VerificationState,
)
from hunterx.shared.ids import generate_content_id, generate_id
from hunterx.shared.time import utcnow_iso

#: Surface kinds that represent scheduler work targets rather than structure.
_SURFACE_LAYERS: dict[SurfaceKind, SurfaceLayer] = {
    SurfaceKind.TARGET: SurfaceLayer.TARGET,
    SurfaceKind.HOST: SurfaceLayer.ASSET,
    SurfaceKind.SUBDOMAIN: SurfaceLayer.ASSET,
    SurfaceKind.PORT: SurfaceLayer.SERVICE,
    SurfaceKind.SERVICE: SurfaceLayer.SERVICE,
    SurfaceKind.TECHNOLOGY: SurfaceLayer.APPLICATION,
    SurfaceKind.URL: SurfaceLayer.SURFACE,
    SurfaceKind.ROUTE: SurfaceLayer.SURFACE,
    SurfaceKind.ENDPOINT: SurfaceLayer.SURFACE,
    SurfaceKind.METHOD: SurfaceLayer.SURFACE,
    SurfaceKind.API_ENDPOINT: SurfaceLayer.SURFACE,
    SurfaceKind.GRAPHQL_OPERATION: SurfaceLayer.SURFACE,
    SurfaceKind.WEBSOCKET: SurfaceLayer.SURFACE,
    SurfaceKind.REDIRECT: SurfaceLayer.SURFACE,
    SurfaceKind.CLIENT_ROUTE: SurfaceLayer.SURFACE,
    SurfaceKind.JAVASCRIPT_ENDPOINT: SurfaceLayer.SURFACE,
    SurfaceKind.CLOUD_RESOURCE: SurfaceLayer.SURFACE,
    SurfaceKind.PARAMETER: SurfaceLayer.INPUT,
    SurfaceKind.PATH_VARIABLE: SurfaceLayer.INPUT,
    SurfaceKind.JSON_FIELD: SurfaceLayer.INPUT,
    SurfaceKind.FORM_FIELD: SurfaceLayer.INPUT,
    SurfaceKind.HEADER: SurfaceLayer.INPUT,
    SurfaceKind.COOKIE: SurfaceLayer.INPUT,
    SurfaceKind.FILE: SurfaceLayer.INPUT,
    SurfaceKind.UPLOAD: SurfaceLayer.INPUT,
    SurfaceKind.DOWNLOAD: SurfaceLayer.INPUT,
    SurfaceKind.OBJECT: SurfaceLayer.OBJECT,
    SurfaceKind.OBJECT_IDENTIFIER: SurfaceLayer.OBJECT,
    SurfaceKind.SINK: SurfaceLayer.OBJECT,
    SurfaceKind.SOURCE: SurfaceLayer.OBJECT,
    SurfaceKind.AUTH_SURFACE: SurfaceLayer.STATE,
    SurfaceKind.AUTH_STATE: SurfaceLayer.STATE,
    SurfaceKind.AUTHORIZATION_CONTEXT: SurfaceLayer.STATE,
    SurfaceKind.WORKFLOW: SurfaceLayer.WORKFLOW,
    SurfaceKind.STATE_TRANSITION: SurfaceLayer.WORKFLOW,
    SurfaceKind.UNKNOWN: SurfaceLayer.SURFACE,
}


def layer_for(kind: SurfaceKind | str) -> SurfaceLayer:
    """Return the canonical layer for a surface kind (``SURFACE`` fallback)."""
    normalized = kind.value if isinstance(kind, SurfaceKind) else str(kind)
    try:
        return _SURFACE_LAYERS[SurfaceKind(normalized)]
    except ValueError:
        return SurfaceLayer.SURFACE


def surface_key(kind: SurfaceKind | str, name: str) -> str:
    """Return the canonical ``kind:name`` node key for a surface."""
    normalized = kind.value if isinstance(kind, SurfaceKind) else str(kind)
    return f"{normalized}:{name or '?'}"


@dataclass(frozen=True, slots=True)
class SurfaceContext:
    """Authentication/authorization/technology context of a surface.

    The context is what makes a ``Capability × Surface`` mapping a *triple*:
    the same surface kind may map to different capabilities depending on the
    observed authentication state, authorization scope, technology or transport
    behaviour.

    Attributes:
        auth_state: observed authentication context.
        authorization_state: observed authorization/tenancy context labels.
        technologies: observed technologies on the owning application.
        method: HTTP method the surface is exercised with.
        content_type: observed request/response content type.
        fetch_hint: surface plausibly fetches remote URLs (SSRF-relevant).
        object_hint: surface exposes object identifiers (IDOR/BOLA-relevant).
        multi_tenant: target observed as multi-user/multi-tenant.
        session_label: established session label when authenticated.
        notes: free-form context notes.

    """

    auth_state: AuthContextState = AuthContextState.UNKNOWN
    authorization_state: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    method: str = ""
    content_type: str = ""
    fetch_hint: bool = False
    object_hint: bool = False
    multi_tenant: bool = False
    session_label: str = ""
    notes: str = ""

    def context_key(self) -> str:
        """Return a stable identity hash for capability assignment dedup."""
        return str(
            generate_content_id(
                self.auth_state.value,
                sorted(self.authorization_state),
                sorted(self.technologies),
                self.method,
                self.content_type,
                self.fetch_hint,
                self.object_hint,
                self.multi_tenant,
                self.session_label,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "auth_state": self.auth_state.value,
            "authorization_state": list(self.authorization_state),
            "technologies": list(self.technologies),
            "method": self.method,
            "content_type": self.content_type,
            "fetch_hint": self.fetch_hint,
            "object_hint": self.object_hint,
            "multi_tenant": self.multi_tenant,
            "session_label": self.session_label,
            "notes": self.notes,
        }


@dataclass(slots=True)
class SurfaceNode:
    """A node in the attack-surface graph.

    Attributes:
        surface_id: stable surface identifier.
        mission_id: owning mission.
        target_key: owning target key (root of the graph).
        layer: canonical :class:`SurfaceLayer`.
        kind: :class:`SurfaceKind` (or a registry-registered string kind).
        name: canonical surface value.
        key: canonical node key (``kind:name``).
        parent_key: parent node key (``""`` for the target root).
        dynamic_type: target-specific object type (e.g. ``user``, ``order``,
            ``product``) — an arbitrary string, never a hardcoded class.
        attributes: free-form surface attributes.
        context: :class:`SurfaceContext` observed for the surface.
        confidence: surface confidence in ``[0, 1]``.
        source: provenance label (tool/capability that observed it).
        observed_by: capabilities that observed the surface.
        first_seen / last_seen: state-time stamps.

    """

    surface_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    target_key: str = ""
    layer: SurfaceLayer = SurfaceLayer.SURFACE
    kind: SurfaceKind | str = SurfaceKind.UNKNOWN
    name: str = ""
    key: str = ""
    parent_key: str = ""
    dynamic_type: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    context: SurfaceContext = field(default_factory=SurfaceContext)
    confidence: float = 1.0
    source: str = ""
    observed_by: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        if not self.key:
            self.key = surface_key(self.kind, self.name)

    def touch(self, *, observed_by: str = "") -> None:
        """Refresh the last-seen stamp and record the observer."""
        self.last_seen = utcnow_iso()
        if observed_by and observed_by not in self.observed_by:
            self.observed_by.append(observed_by)

    def kind_value(self) -> str:
        """Return the canonical kind string."""
        return self.kind.value if isinstance(self.kind, SurfaceKind) else str(self.kind)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "surface_id": self.surface_id,
            "mission_id": self.mission_id,
            "target_key": self.target_key,
            "layer": self.layer.value,
            "kind": self.kind_value(),
            "name": self.name,
            "key": self.key,
            "parent_key": self.parent_key,
            "dynamic_type": self.dynamic_type,
            "attributes": dict(self.attributes),
            "context": self.context.to_dict(),
            "confidence": self.confidence,
            "source": self.source,
            "observed_by": list(self.observed_by),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(frozen=True, slots=True)
class SurfaceEdge:
    """A typed relationship between two surface nodes.

    Attributes:
        edge_id: stable edge identifier.
        source_key / target_key: canonical node keys.
        rel_type: relationship type (generic string, extensible).
        rationale: why the relationship exists.
        confidence: edge confidence in ``[0, 1]``.
        first_seen: UTC ISO-8601 creation stamp.

    """

    edge_id: str = field(default_factory=generate_id)
    source_key: str = ""
    target_key: str = ""
    rel_type: str = "contains"
    rationale: str = ""
    confidence: float = 1.0
    first_seen: str = field(default_factory=utcnow_iso)

    def key(self) -> str:
        """Return the stable edge identity key."""
        return str(generate_content_id(self.source_key, self.target_key, self.rel_type))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "edge_id": self.edge_id,
            "source_key": self.source_key,
            "target_key": self.target_key,
            "rel_type": self.rel_type,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "first_seen": self.first_seen,
        }


@dataclass(slots=True)
class DynamicObject:
    """A target-specific object discovered on the surface.

    Business objects (users, orders, products, documents, tenants, ...) are
    represented dynamically: ``object_type`` is the discovered type string and
    ``identifiers`` carries the observed object identifiers (ids, keys, slugs)
    with their locations. No target-specific class or route is ever assumed.

    Attributes:
        object_id: stable object identifier.
        mission_id: owning mission.
        target_key: owning target key.
        object_type: discovered object type (``""`` = unclassified).
        name: object label.
        key: canonical surface key of the object node.
        identifiers: tuple of observed identifier values.
        identifier_kinds: tuple of identifier location kinds.
        attributes: free-form object attributes.
        parent_key: containing surface key.
        source: provenance label.
        first_seen / last_seen: state-time stamps.

    """

    object_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    target_key: str = ""
    object_type: str = ""
    name: str = ""
    key: str = ""
    identifiers: tuple[str, ...] = ()
    identifier_kinds: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)
    parent_key: str = ""
    source: str = ""
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        if not self.key:
            kind = "object" if not self.object_type else f"object:{self.object_type}"
            self.key = f"{kind}:{self.name or self.object_type or self.object_id}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "object_id": self.object_id,
            "mission_id": self.mission_id,
            "target_key": self.target_key,
            "object_type": self.object_type,
            "name": self.name,
            "key": self.key,
            "identifiers": list(self.identifiers),
            "identifier_kinds": list(self.identifier_kinds),
            "attributes": dict(self.attributes),
            "parent_key": self.parent_key,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class CapabilityAssignment:
    """A ``Capability × Surface × Context`` applicability record.

    Produced by the capability mapper for every applicable combination. The
    assignment is the unit the completion gate counts: exhaustion requires every
    applicable assignment to be terminal (or marked ``NOT_APPLICABLE``).

    Attributes:
        assignment_id: stable assignment identifier.
        surface_key: the surface the capability applies to.
        capability_id: canonical capability id (from the platform catalog).
        context: the :class:`SurfaceContext` the mapping was made under.
        applicable: whether the capability genuinely applies here.
        rationale: explainable mapping reason.
        priority: importance in ``[0, 1]`` (higher = more important).
        status: :class:`AssessmentStatus` of the assignment.
        verification_state: :class:`VerificationState`.
        strategy: scheduling strategy label.
        attempts: execution attempt counter.
        evidence: evidence records attached to the assignment.
        first_seen / last_seen: state-time stamps.

    """

    assignment_id: str = field(default_factory=generate_id)
    surface_key: str = ""
    capability_id: str = ""
    context: SurfaceContext = field(default_factory=SurfaceContext)
    applicable: bool = True
    rationale: str = ""
    priority: float = 0.5
    status: AssessmentStatus = AssessmentStatus.PENDING
    verification_state: VerificationState = VerificationState.UNVERIFIED
    strategy: str = ""
    attempts: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)

    def identity_key(self) -> str:
        """Return the stable ``surface×capability×context`` identity."""
        return str(generate_content_id(self.surface_key, self.capability_id, self.context.context_key()))

    def mark(self, status: AssessmentStatus) -> None:
        """Transition this assignment's runtime status."""
        self.status = status
        self.last_seen = utcnow_iso()

    def record_evidence(self, evidence: dict[str, Any]) -> None:
        """Attach an evidence record and refresh the state stamp."""
        self.evidence.append(dict(evidence))
        self.attempts += 1
        self.last_seen = utcnow_iso()

    def settle(self, verification_state: VerificationState) -> None:
        """Record the verification verdict for this assignment."""
        self.verification_state = verification_state
        self.last_seen = utcnow_iso()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "assignment_id": self.assignment_id,
            "surface_key": self.surface_key,
            "capability_id": self.capability_id,
            "context": self.context.to_dict(),
            "applicable": self.applicable,
            "rationale": self.rationale,
            "priority": self.priority,
            "status": self.status.value,
            "verification_state": self.verification_state.value,
            "strategy": self.strategy,
            "attempts": self.attempts,
            "evidence": list(self.evidence),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass(slots=True)
class AssessmentTask:
    """A universal assessment-queue item.

    The queue item bundles everything a scheduler needs for one probe without
    any target-specific assumption:

        surface · capability · context · authentication state ·
        authorization state · strategy · priority · status · attempts ·
        evidence · verification state

    Attributes:
        task_id: stable task identifier.
        mission_id: owning mission.
        surface_key: the surface to assess.
        capability_id: the capability to run.
        context: :class:`SurfaceContext` of the assessment.
        strategy: scheduling strategy label.
        priority: scheduling priority (lower = sooner).
        status: :class:`AssessmentStatus`.
        attempts: execution attempt counter.
        evidence: evidence records attached to the task.
        verification_state: :class:`VerificationState`.
        assignment_id: owning capability assignment (``""`` = none).
        created_at / updated_at: state-time stamps.

    """

    task_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    surface_key: str = ""
    capability_id: str = ""
    context: SurfaceContext = field(default_factory=SurfaceContext)
    strategy: str = ""
    priority: float = 50.0
    status: AssessmentStatus = AssessmentStatus.PENDING
    attempts: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    verification_state: VerificationState = VerificationState.UNVERIFIED
    assignment_id: str = ""
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    def dedup_key(self) -> str:
        """Return the stable dedup identity (surface × capability × context)."""
        return str(generate_content_id(self.surface_key, self.capability_id, self.context.context_key()))

    @property
    def auth_state(self) -> AuthContextState:
        """Convenience accessor for the context authentication state."""
        return self.context.auth_state

    @property
    def authorization_state(self) -> tuple[str, ...]:
        """Convenience accessor for the context authorization labels."""
        return self.context.authorization_state

    def mark(self, status: AssessmentStatus) -> None:
        """Transition this task's runtime status."""
        self.status = status
        self.updated_at = utcnow_iso()

    def record_attempt(self) -> None:
        """Increment the attempt counter and refresh the stamp."""
        self.attempts += 1
        self.updated_at = utcnow_iso()

    def record_evidence(self, evidence: dict[str, Any]) -> None:
        """Attach an evidence record."""
        self.evidence.append(dict(evidence))
        self.updated_at = utcnow_iso()

    def settle(self, verification_state: VerificationState) -> None:
        """Record the verification verdict for this task."""
        self.verification_state = verification_state
        self.updated_at = utcnow_iso()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "task_id": self.task_id,
            "mission_id": self.mission_id,
            "surface_key": self.surface_key,
            "capability_id": self.capability_id,
            "context": self.context.to_dict(),
            "strategy": self.strategy,
            "priority": self.priority,
            "status": self.status.value,
            "attempts": self.attempts,
            "evidence": list(self.evidence),
            "verification_state": self.verification_state.value,
            "assignment_id": self.assignment_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class ExhaustionReport:
    """Outcome of the attack-surface completion gate.

    Attributes:
        verdict: :class:`CompletionVerdict`.
        criteria: criterion → satisfied flag.
        reason: human explanation of the verdict.
        surfaced: number of surfaces discovered.
        applicable_combinations: applicable capability×surface×context records.
        evaluated_combinations: terminal applicable records.
        pending_tasks: actionable assessment-queue tasks remaining.
        stale_observations: observations since the last genuinely new surface.
        unavailable_reason: explicit target-unavailability reason (``""`` = n/a).
        blocked_reason: explicit blocking reason (``""`` = n/a).

    """

    verdict: CompletionVerdict = CompletionVerdict.NOT_EXHAUSTED
    criteria: dict[str, bool] = field(default_factory=dict)
    reason: str = ""
    surfaced: int = 0
    applicable_combinations: int = 0
    evaluated_combinations: int = 0
    pending_tasks: int = 0
    stale_observations: int = 0
    unavailable_reason: str = ""
    blocked_reason: str = ""

    def satisfied(self) -> bool:
        """Return ``True`` when every exhaustion criterion holds."""
        return bool(self.criteria) and all(self.criteria.values())

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "verdict": self.verdict.value,
            "criteria": {str(key): value for key, value in self.criteria.items()},
            "reason": self.reason,
            "surfaced": self.surfaced,
            "applicable_combinations": self.applicable_combinations,
            "evaluated_combinations": self.evaluated_combinations,
            "pending_tasks": self.pending_tasks,
            "stale_observations": self.stale_observations,
            "unavailable_reason": self.unavailable_reason,
            "blocked_reason": self.blocked_reason,
        }


__all__ = [
    "AssessmentTask",
    "CapabilityAssignment",
    "DynamicObject",
    "ExhaustionReport",
    "SurfaceContext",
    "SurfaceEdge",
    "SurfaceNode",
    "layer_for",
    "surface_key",
]
