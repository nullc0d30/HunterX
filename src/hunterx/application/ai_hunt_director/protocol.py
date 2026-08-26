# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director Protocol.

Defines the structured protocol between the AI Hunt Director and HunterX.
The AI Hunt Director is the autonomous decision-making authority for
security assessment missions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from hunterx.domain.mission_orchestration.enums import HypothesisState
from hunterx.domain.mission_orchestration.models import MissionHypothesis


class ActionType(str, Enum):
    """Type of action the AI Hunt Director can request."""

    EXECUTE_TOOL = "execute_tool"
    REASSESS = "reassess"
    VALIDATE_FINDING = "validate_finding"
    COLLECT_EVIDENCE = "collect_evidence"
    EXPLORE_ATTACK_PATH = "explore_attack_path"
    COMPLETE = "complete"
    DEFER_HYPOTHESIS = "defer_hypothesis"
    BLOCK_HYPOTHESIS = "block_hypothesis"
    REQUEST_EVIDENCE = "request_evidence"
    GENERATE_PROOF = "generate_proof"


class PolicyGateResult(str, Enum):
    """Result of the HunterX policy gate validation."""

    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"


class PolicyGateReason(str, Enum):
    """Reason for policy gate rejection."""

    OUT_OF_SCOPE = "out_of_scope"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN_TOOL = "unknown_tool"
    INVALID_ARGUMENTS = "invalid_arguments"
    RESOURCE_LIMIT = "resource_limit"
    POLICY_DENIED = "policy_denied"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    TOOL_UNAVAILABLE = "tool_unavailable"
    SCOPE_VIOLATION = "scope_violation"
    AUTHORIZATION_REQUIRED = "authorization_required"


@dataclass(frozen=True, slots=True)
class PolicyGateResultDetail:
    """Detailed result of the policy gate validation."""

    result: PolicyGateResult
    reason: Optional[PolicyGateReason] = None
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolCapability:
    """Machine-readable description of a tool/capability available to the AI."""

    tool_id: str
    name: str
    description: str
    purpose: str
    capability: str  # e.g., "port_discovery", "vulnerability_scanning", "javascript_analysis"
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    supported_target_types: list[str] = field(default_factory=list)
    scope_requirements: list[str] = field(default_factory=list)
    authorization_requirements: list[str] = field(default_factory=list)
    risk_level: str = "medium"
    side_effects: list[str] = field(default_factory=list)
    timeout: int = 300
    resource_cost: float = 1.0
    evidence_types: list[str] = field(default_factory=list)
    version: str = "1.0.0"


@dataclass(frozen=True, slots=True)
class ResourceState:
    """Current resource state available to the mission."""

    execution_remaining: int = 0
    time_remaining: int = 0
    available_capabilities: list[str] = field(default_factory=list)
    provider_status: dict[str, str] = field(default_factory=dict)
    concurrent_executions: int = 0
    max_concurrency: int = 4


@dataclass(frozen=True, slots=True)
class HypothesisSummary:
    """Summary of a hypothesis for AI context."""

    hypothesis_id: str
    statement: str
    state: HypothesisState
    category: str
    vulnerability_class: str
    priority: float
    confidence: float
    supporting_evidence: list[str]
    contradicting_evidence: list[str]
    tested_actions: list[str]
    created_at: str
    updated_at: str
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FindingSummary:
    """Summary of a finding for AI context."""

    finding_id: str
    vulnerability_class: str
    title: str
    target: str
    severity: str
    stage: str
    confidence: float
    evidence_refs: list[str]
    hypothesis_id: str


@dataclass(frozen=True, slots=True)
class ObservationSummary:
    """Summary of an observation for AI context."""

    observation_id: str
    observation_type: str
    tool_id: str
    asset_key: str
    content_summary: str
    evidence_ref: str
    confidence: float
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class HuntContext:
    """
    Complete context provided to the AI Hunt Director for decision making.

    This is the primary input to the AI Hunt Director's decision-making process.
    It contains all relevant mission state, observations, hypotheses, findings,
    available capabilities, and resource constraints.
    """

    mission_id: str
    target: str
    objective: str
    scope: dict[str, Any]
    authorization_context: dict[str, Any]

    # Current state
    current_phase: str
    current_strategy: str

    # Available capabilities and tools
    available_capabilities: list[ToolCapability]
    available_tools: list[str]

    # Current state
    observations: list[ObservationSummary] = field(default_factory=list)
    hypotheses: list[HypothesisSummary] = field(default_factory=list)
    findings: list[FindingSummary] = field(default_factory=list)

    # Discovered target model
    technologies: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)

    # Attack surface and attack paths
    attack_surface: dict[str, Any] = field(default_factory=dict)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)

    # Evidence and findings
    evidence: dict[str, Any] = field(default_factory=dict)
    negative_evidence: list[dict[str, Any]] = field(default_factory=list)

    # Security Test Matrix (the completion contract)
    security_matrix: dict[str, Any] = field(default_factory=dict)
    #: Compact per-capability execution history for the last cycles.
    previous_tool_results: list[dict[str, Any]] = field(default_factory=list)
    #: Capability+asset pairs already scheduled/pending in the plan.
    pending_actions: list[str] = field(default_factory=list)
    #: Aggregated coverage matrix (per-capability tested/not-assessed states).
    coverage_matrix: dict[str, Any] = field(default_factory=dict)

    # Resources and constraints
    resource_state: ResourceState = field(default_factory=ResourceState)

    # AI provider status
    ai_provider: str = ""
    ai_model: str = ""
    ai_status: str = "available"

    # Previous decisions for context
    previous_decisions: list[dict[str, Any]] = field(default_factory=list)
    previous_actions: list[str] = field(default_factory=list)

    # Timestamps
    mission_started_at: str = ""
    last_updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    # Completion gate status
    completion_gate_status: dict[str, Any] = field(default_factory=dict)


class AIHuntDirectorProtocol:
    """Protocol for the AI Hunt Director.

    The AI Hunt Director is the autonomous decision-making authority for
    security assessment missions. It receives mission context and decides
    the next action to take.
    """

    def decide_next_action(self, context: HuntContext) -> "AIHuntDecision":
        """
        Determine the next action based on the current mission context.

        This is the primary decision-making method. The AI Hunt Director
        must analyze the provided context and return a structured decision.
        """
        raise NotImplementedError

    def initialize_hunt(self, context: HuntContext) -> list[str]:
        """
        Initialize the hunt by returning initial hypotheses/priorities.

        Called once at the start of a mission to establish initial
        hypotheses and priorities based on the target and objective.
        """
        raise NotImplementedError

    def reassess(self, context: HuntContext) -> list[str]:
        """
        Reassess the current strategy based on new observations.

        Called when significant new information is available that may
        require strategy adjustment.
        """
        raise NotImplementedError

    def validate_finding(self, context: HuntContext, finding_id: str) -> "AIHuntDecision":
        """
        Validate a finding candidate and determine if it's report-ready.

        The AI determines if the evidence is sufficient for the finding
        to advance through the validation pipeline.
        """
        raise NotImplementedError

    def build_attack_path(self, context: HuntContext) -> list[str]:
        """
        Generate attack paths from current observations.

        Returns a list of attack path IDs that should be explored.
        """
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class AIHuntDecision:
    """
    Structured decision from the AI Hunt Director.

    This is the structured output from the AI Hunt Director that HunterX
    validates and executes.
    """

    decision_id: str
    action_type: ActionType
    tool_id: str = ""
    capability: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    objective: str = ""
    hypothesis_ids: list[str] = field(default_factory=list)
    expected_signal: str = ""
    evidence_required: list[str] = field(default_factory=list)
    validation_required: list[str] = field(default_factory=list)
    priority: float = 0.5
    rationale: str = ""
    rationale_summary: str = ""
    next_state_expectation: str = ""
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)

    # Structured hunt-director decision schema
    #: The security question being answered (question-first selection).
    question: str = ""
    #: Security Test Matrix domain this decision advances.
    security_domain: str = ""
    #: How the resulting evidence will be validated.
    validation_plan: str = ""

    # Control decisions
    decision_type: str = "EXECUTE_TOOL"  # EXECUTE_TOOL, REASSESS, VALIDATE_FINDING, COLLECT_EVIDENCE, EXPLORE_ATTACK_PATH, COMPLETE, DEFER_HYPOTHESIS, BLOCK_HYPOTHESIS, REQUEST_EVIDENCE, GENERATE_PROOF

    # Policy gate result (populated by HunterX after validation)
    policy_gate_result: Optional[PolicyGateResultDetail] = None


class AIHuntDirectorError(Exception):
    """Exception raised when the AI Hunt Director encounters an error."""

    def __init__(self, message: str, decision_id: str = "", context: Optional[dict] = None):
        super().__init__(message)
        self.decision_id = decision_id
        self.context = context or {}