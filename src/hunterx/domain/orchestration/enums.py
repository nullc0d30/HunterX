# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission orchestration enums.

The canonical mission lifecycle and orchestration vocabulary: mission types,
mission states, phase kinds, scope classification, failure classes,
failure management strategies, execution-policy levels and coverage kinds.
"""

from __future__ import annotations

from enum import Enum


class MissionType(Enum):
    """Canonical offensive mission types supported by the orchestration engine.

    These map onto the mission-profiles registry where applicable and gate the
    planner's phase selection and the tool-selection capability set.
    """

    BUG_BOUNTY = "bug-bounty"
    WEB_PENTEST = "web-pentest"
    API_PENTEST = "api-pentest"
    EXTERNAL_ASSESSMENT = "external-assessment"
    INTERNAL_ASSESSMENT = "internal-assessment"
    RED_TEAM_RECON = "red-team-recon"
    CLOUD_ASSESSMENT = "cloud-assessment"
    CONTINUOUS_ATTACK_SURFACE_MONITORING = "continuous-attack-surface-monitoring"
    VULNERABILITY_ASSESSMENT = "vulnerability-assessment"


class MissionState(Enum):
    """The mission lifecycle state machine.

    Terminal states are ``COMPLETED``, ``PARTIAL``, ``FAILED`` and
    ``CANCELLED``. Active states may transition between one another through the
    validated transitions owned by the lifecycle engine.
    """

    CREATED = "created"
    SCOPING = "scoping"
    PLANNING = "planning"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING = "waiting"
    REPLANNING = "replanning"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for terminal mission states."""
        return self in (
            MissionState.COMPLETED,
            MissionState.PARTIAL,
            MissionState.FAILED,
            MissionState.CANCELLED,
        )

    @property
    def is_active(self) -> bool:
        """Return ``True`` for states that are still in progress."""
        return not self.is_terminal


class MissionPhaseKind(Enum):
    """Reusable mission phases (PHASE 0 … PHASE 12).

    The planner may skip phases when a phase is unnecessary for the mission.
    """

    SCOPE = "scope"
    RECONNAISSANCE = "reconnaissance"
    ASSET_DISCOVERY = "asset-discovery"
    SERVICE_DISCOVERY = "service-discovery"
    TECHNOLOGY_DISCOVERY = "technology-discovery"
    ATTACK_SURFACE_MAPPING = "attack-surface-mapping"
    VULNERABILITY_INTELLIGENCE = "vulnerability-intelligence"
    VULNERABILITY_HYPOTHESIS = "vulnerability-hypothesis"
    SAFE_VALIDATION = "safe-validation"
    CORRELATION = "correlation"
    RISK_PRIORITIZATION = "risk-prioritization"
    EVIDENCE_CONSOLIDATION = "evidence-consolidation"
    REPORTING = "reporting"


class ScopeClassification(Enum):
    """Classification of a discovered asset with respect to the mission scope.

    Only :attr:`IN_SCOPE` assets may be acted upon automatically. Assets
    classified ``REQUIRES_AUTHORIZATION`` or ``UNKNOWN`` are never touched
    without explicit authorization.
    """

    IN_SCOPE = "in-scope"
    OUT_OF_SCOPE = "out-of-scope"
    REQUIRES_AUTHORIZATION = "requires-authorization"
    UNKNOWN = "unknown"


class FailureClass(Enum):
    """Classification of a failed tool execution, driving retry policy.

    Only the retryable classes (transient, rate-limit, timeout, network,
    tool-crash, parser-failure) may be retried. Scope, safety and authorization
    failures are never retried.
    """

    TRANSIENT = "transient"
    RATE_LIMIT = "rate-limit"
    TIMEOUT = "timeout"
    NETWORK = "network"
    TOOL_CRASH = "tool-crash"
    PARSER_FAILURE = "parser-failure"
    INVALID_INPUT = "invalid-input"
    SCOPE_FAILURE = "scope-failure"
    SAFETY_FAILURE = "safety-failure"
    AUTHORIZATION_FAILURE = "authorization-failure"
    PERMANENT = "permanent"

    @property
    def retryable(self) -> bool:
        """Return ``True`` when the class may be retried."""
        return self in (
            FailureClass.TRANSIENT,
            FailureClass.RATE_LIMIT,
            FailureClass.TIMEOUT,
            FailureClass.NETWORK,
            FailureClass.TOOL_CRASH,
            FailureClass.PARSER_FAILURE,
        )


class FailureManagement(Enum):
    """How a failed tool execution is managed at the mission level."""

    RECOVERABLE = "recoverable"
    FALLBACK_AVAILABLE = "fallback-available"
    DEFERRED = "deferred"
    BLOCKED = "blocked"
    CRITICAL = "critical"
    MISSION_FATAL = "mission-fatal"


class ExecutionPolicyLevel(Enum):
    """Execution policy levels.

    The policy determines which tools and validation strategies are allowed.
    No policy may bypass scope enforcement. ``AUTHORIZED_RED_TEAM`` remains
    non-destructive by default unless a separate safety policy explicitly
    permits controlled behavior.
    """

    PASSIVE_ONLY = "passive-only"
    SAFE_ACTIVE = "safe-active"
    STANDARD_ASSESSMENT = "standard-assessment"
    AUTHORIZED_RED_TEAM = "authorized-red-team"

    @property
    def allows_active(self) -> bool:
        """Return ``True`` when active (non-passive) execution is allowed."""
        return self is not ExecutionPolicyLevel.PASSIVE_ONLY


class TaskState(Enum):
    """State of a single planned step within a mission."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for terminal task states."""
        return self in (
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.SKIPPED,
            TaskState.BLOCKED,
            TaskState.CANCELLED,
        )


class CoverageKind(Enum):
    """Kinds of coverage the coverage model reports."""

    SCOPE = "scope"
    ASSET = "asset"
    PORT = "port"
    PROTOCOL = "protocol"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"
    VALIDATION = "validation"
    TOOL = "tool"
    EVIDENCE = "evidence"
