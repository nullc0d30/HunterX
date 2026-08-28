# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack-surface enums.

Phase 1 target-agnostic vocabulary for representing and scheduling arbitrary
discovered attack surfaces. The values are generic capability-model categories,
never a specific target's routes, objects or technologies: a business object
discovered on a target is modelled dynamically (its type is a string, not an
enum member), so a new target never requires touching this module.

Layering (Target → Asset → Service → Application → Surface → Input/Object/State
→ Workflow → Capability) mirrors the attack-surface graph the orchestration
walks. Kinds are strings and therefore extensible through the
:class:`SurfaceKindRegistry` without modifying core orchestration logic.
"""

from __future__ import annotations

from enum import StrEnum


class SurfaceLayer(StrEnum):
    """Canonical layer of a node in the attack-surface graph.

    The graph is walked top-down from the target toward inputs, objects, states
    and workflows, then across to the applicable security capabilities.
    """

    TARGET = "target"
    ASSET = "asset"
    SERVICE = "service"
    APPLICATION = "application"
    SURFACE = "surface"
    INPUT = "input"
    OBJECT = "object"
    STATE = "state"
    WORKFLOW = "workflow"
    CAPABILITY = "capability"


class SurfaceKind(StrEnum):
    """Canonical generic surface kinds.

    These are capability-model categories a target may expose *when discovered*.
    No target is assumed to expose all of them; a kind is only present when an
    observation proves it. Kinds remain strings so adapters can register new
    ones dynamically (see ``SurfaceKindRegistry``).
    """

    TARGET = "target"
    HOST = "host"
    SUBDOMAIN = "subdomain"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    URL = "url"
    ROUTE = "route"
    ENDPOINT = "endpoint"
    METHOD = "method"
    PARAMETER = "parameter"
    PATH_VARIABLE = "path_variable"
    JSON_FIELD = "json_field"
    FORM_FIELD = "form_field"
    HEADER = "header"
    COOKIE = "cookie"
    FILE = "file"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    OBJECT = "object"
    OBJECT_IDENTIFIER = "object_identifier"
    API_ENDPOINT = "api_endpoint"
    GRAPHQL_OPERATION = "graphql_operation"
    WEBSOCKET = "websocket"
    REDIRECT = "redirect"
    CLIENT_ROUTE = "client_route"
    JAVASCRIPT_ENDPOINT = "javascript_endpoint"
    SINK = "sink"
    SOURCE = "source"
    AUTH_SURFACE = "auth_surface"
    AUTH_STATE = "auth_state"
    AUTHORIZATION_CONTEXT = "authorization_context"
    WORKFLOW = "workflow"
    STATE_TRANSITION = "state_transition"
    CLOUD_RESOURCE = "cloud_resource"
    UNKNOWN = "unknown"


class AuthContextState(StrEnum):
    """Authentication context observed for a surface.

    ``ANONYMOUS`` means no credentials were used; ``AUTHENTICATED`` means a
    session is established; ``MULTI_USER`` means the target exposes multiple
    distinct identities (multi-user / multi-tenant behaviour); ``UNKNOWN`` is
    the honest state when authentication state was never observed.
    """

    ANONYMOUS = "anonymous"
    AUTH_INITIATED = "auth_initiated"
    AUTHENTICATED = "authenticated"
    MULTI_USER = "multi_user"
    SESSION_EXPIRED = "session_expired"
    UNKNOWN = "unknown"


class AssessmentStatus(StrEnum):
    """Lifecycle state of an assessment task / capability assignment.

    ``READY`` items are schedulable; ``SCHEDULED``/``RUNNING`` are in flight;
    the five terminal states end an item's contribution to exhaustion.
    """

    PENDING = "pending"
    READY = "ready"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    SUPERSEDED = "superseded"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for states that end active assessment work."""
        return self in (
            AssessmentStatus.COMPLETED,
            AssessmentStatus.FAILED,
            AssessmentStatus.BLOCKED,
            AssessmentStatus.SKIPPED,
            AssessmentStatus.SUPERSEDED,
            AssessmentStatus.CANCELLED,
        )

    @property
    def is_actionable(self) -> bool:
        """Return ``True`` when the item still needs scheduler attention."""
        return self in (
            AssessmentStatus.PENDING,
            AssessmentStatus.READY,
            AssessmentStatus.SCHEDULED,
            AssessmentStatus.RUNNING,
        )


class VerificationState(StrEnum):
    """Verification state of a scheduled capability against a surface.

    ``NOT_APPLICABLE`` records a genuine "capability does not apply here"
    verdict (a differential probe honestly refuted, or a surface kind the
    capability cannot target), so exhaustion is never gated on impossible work.
    """

    UNVERIFIED = "unverified"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    CONFIRMED = "confirmed"
    NOT_APPLICABLE = "not_applicable"
    INCONCLUSIVE = "inconclusive"

    @property
    def is_settled(self) -> bool:
        """Return ``True`` when verification will not change on its own."""
        return self in (
            VerificationState.VERIFIED,
            VerificationState.CONFIRMED,
            VerificationState.NOT_APPLICABLE,
            VerificationState.INCONCLUSIVE,
        )


class CompletionVerdict(StrEnum):
    """Verdict of the attack-surface completion gate.

    ``EXHAUSTED`` is the only success verdict: it requires discovery, dynamic
    discovery, capability/surface combinations, the assessment queue, the
    verification queue and attack-path discovery all to be exhausted. Failure
    is never converted into completion: ``BLOCKED`` and ``TARGET_UNAVAILABLE``
    are honest non-complete verdicts.
    """

    EXHAUSTED = "exhausted"
    NOT_EXHAUSTED = "not_exhausted"
    BLOCKED = "blocked"
    TARGET_UNAVAILABLE = "target_unavailable"


class ExhaustionCriterion(StrEnum):
    """Criteria every one of which must hold for the surface to be exhausted."""

    DISCOVERY_EXHAUSTED = "discovery_exhausted"
    DYNAMIC_DISCOVERY_EXHAUSTED = "dynamic_discovery_exhausted"
    COMBINATIONS_EVALUATED = "combinations_evaluated"
    ASSESSMENT_QUEUE_EXHAUSTED = "assessment_queue_exhausted"
    VERIFICATION_QUEUE_EXHAUSTED = "verification_queue_exhausted"
    NO_ATTACK_PATHS_REMAIN = "no_attack_paths_remain"


__all__ = [
    "AssessmentStatus",
    "AuthContextState",
    "CompletionVerdict",
    "ExhaustionCriterion",
    "SurfaceKind",
    "SurfaceLayer",
    "VerificationState",
]
