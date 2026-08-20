# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive attack-engine enums.

Phase 2. Generic vocabulary for the aggressive-but-bounded adaptive attack
engine: attack states, target-feedback signals, attack vectors, aggression
levels and attack outcomes. All values are capability-model categories — never
a specific target's routes, objects or technologies.
"""

from __future__ import annotations

from enum import StrEnum


class AttackState(StrEnum):
    """Canonical states of the adaptive attack state machine.

    Transitions are driven by observed target behavior (feedback signals),
    never by a fixed tool sequence:

        NORMAL → AGGRESSIVE (healthy escalation)
        NORMAL/AGGRESSIVE → THROTTLED (defensive response)
        THROTTLED → BACKING_OFF (hard defensive response)
        THROTTLED/BACKING_OFF → RECOVERING (target recovered)
        RECOVERING → RESUMING → NORMAL (gradual restore)
        THROTTLED/BACKING_OFF → BLOCKED (persistent hard blocking)
        BLOCKED → RESUMING (target unblocked)

    ``BLOCKED`` is never completion: the mission keeps a reduced presence and
    resumes only when the target stops defending.
    """

    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    THROTTLED = "throttled"
    BACKING_OFF = "backing_off"
    RECOVERING = "recovering"
    BLOCKED = "blocked"
    RESUMING = "resuming"


class FeedbackSignal(StrEnum):
    """Canonical target-feedback signals classified from execution outcomes."""

    NORMAL = "normal"
    RATE_LIMITED = "rate_limited"
    ACCESS_DENIED = "access_denied"
    SERVER_ERROR = "server_error"
    TIMEOUT = "timeout"
    CONNECTION_FAILURE = "connection_failure"
    HIGH_LATENCY = "high_latency"
    RESPONSE_ANOMALY = "response_anomaly"
    WAF_BLOCKED = "waf_blocked"

    @property
    def is_defensive(self) -> bool:
        """Return ``True`` when the signal indicates the target pushed back."""
        return self in (
            FeedbackSignal.RATE_LIMITED,
            FeedbackSignal.ACCESS_DENIED,
            FeedbackSignal.SERVER_ERROR,
            FeedbackSignal.TIMEOUT,
            FeedbackSignal.CONNECTION_FAILURE,
            FeedbackSignal.HIGH_LATENCY,
            FeedbackSignal.RESPONSE_ANOMALY,
            FeedbackSignal.WAF_BLOCKED,
        )

    @property
    def is_hard_defensive(self) -> bool:
        """Return ``True`` for signals that strongly indicate blocking."""
        return self in (
            FeedbackSignal.RATE_LIMITED,
            FeedbackSignal.WAF_BLOCKED,
            FeedbackSignal.CONNECTION_FAILURE,
            FeedbackSignal.TIMEOUT,
        )

    @property
    def is_retryable(self) -> bool:
        """Return ``True`` when a strategic retry may be attempted (bounded)."""
        return self in (
            FeedbackSignal.RATE_LIMITED,
            FeedbackSignal.TIMEOUT,
            FeedbackSignal.CONNECTION_FAILURE,
            FeedbackSignal.SERVER_ERROR,
        )


class AggressionLevel(StrEnum):
    """Bounded aggression tiers for a probe plan.

    Escalation is bounded: ``MAXIMUM`` is a hard ceiling, and the adaptive
    controller only raises the tier while the target stays healthy.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAXIMUM = "maximum"

    @property
    def rank(self) -> int:
        """Return the escalation rank (higher = more aggressive, still bounded)."""
        return {
            AggressionLevel.LOW: 0,
            AggressionLevel.MEDIUM: 1,
            AggressionLevel.HIGH: 2,
            AggressionLevel.MAXIMUM: 3,
        }[self]

    def escalate(self) -> AggressionLevel:
        """Return the next tier (``MAXIMUM`` stays at the ceiling)."""
        return {
            AggressionLevel.LOW: AggressionLevel.MEDIUM,
            AggressionLevel.MEDIUM: AggressionLevel.HIGH,
            AggressionLevel.HIGH: AggressionLevel.MAXIMUM,
            AggressionLevel.MAXIMUM: AggressionLevel.MAXIMUM,
        }[self]

    def deescalate(self) -> AggressionLevel:
        """Return the previous tier (``LOW`` stays the floor)."""
        return {
            AggressionLevel.LOW: AggressionLevel.LOW,
            AggressionLevel.MEDIUM: AggressionLevel.LOW,
            AggressionLevel.HIGH: AggressionLevel.MEDIUM,
            AggressionLevel.MAXIMUM: AggressionLevel.HIGH,
        }[self]


class AttackVector(StrEnum):
    """Canonical attack vectors an applicable surface may be tested through.

    Only vectors that apply to a discovered surface are scheduled — a plain
    query parameter never triggers multipart or GraphQL testing.
    """

    QUERY = "query"
    PATH = "path"
    HEADERS = "headers"
    COOKIES = "cookies"
    JSON = "json"
    FORM = "form"
    MULTIPART = "multipart"
    XML = "xml"
    GRAPHQL = "graphql"
    API_BODY = "api_body"
    OBJECT_IDENTIFIER = "object_identifier"
    URL = "url"
    FILE = "file"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    REDIRECT = "redirect"
    AUTH_STATE = "auth_state"
    AUTHORIZATION_CONTEXT = "authorization_context"
    WORKFLOW_STATE = "workflow_state"
    CLIENT_SIDE = "client_side"


class AttackOutcome(StrEnum):
    """Canonical outcomes of a probe/attack step.

    ``SUPPORTED``/``CONTRADICTED``/``UNINFORMATIVE`` mirror the differential
    verdict vocabulary; the defensive outcomes are target-feedback, never
    evidence about the application.
    """

    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    UNINFORMATIVE = "uninformative"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    DEFERRED = "deferred"
    ERROR = "error"


__all__ = [
    "AggressionLevel",
    "AttackOutcome",
    "AttackState",
    "AttackVector",
    "FeedbackSignal",
]
