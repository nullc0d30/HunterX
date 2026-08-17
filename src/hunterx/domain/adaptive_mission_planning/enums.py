# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Mission & Attack-Path Planning — canonical value vocabulary.

Sprint 027. Every enum consumed by the adaptive mission planning engine:
mission objectives, mission states, action node types, dynamic dependency
kinds, conditional branch constructs, replanning triggers, plan-delta kinds,
attack-path states, mission modes, failure classes and explainable decision
factors. These enums are the machine vocabulary of the machine-readable
contract ``capabilities/adaptive-mission-planning.json``.
"""

from __future__ import annotations

from enum import StrEnum


class MissionObjective(StrEnum):
    """Canonical mission objectives.

    The objective determines coverage priorities, allowed capabilities,
    validation depth, proof requirements, risk tolerance and completion
    criteria.
    """

    ATTACK_SURFACE_DISCOVERY = "attack_surface_discovery"
    WEB_SECURITY_ASSESSMENT = "web_security_assessment"
    API_SECURITY_ASSESSMENT = "api_security_assessment"
    CLOUD_SECURITY_ASSESSMENT = "cloud_security_assessment"
    NETWORK_SECURITY_ASSESSMENT = "network_security_assessment"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    BUG_BOUNTY_ASSESSMENT = "bug_bounty_assessment"
    PENTEST_ASSESSMENT = "pentest_assessment"
    RED_TEAM_SIMULATION = "red_team_simulation"
    TARGET_MONITORING = "target_monitoring"
    FINDING_VALIDATION = "finding_validation"
    PROOF_COLLECTION = "proof_collection"


class MissionState(StrEnum):
    """Lifecycle state of an adaptive mission.

    Transitions are explicit and event-driven; the state machine in
    ``hunterx.domain.adaptive_mission_planning.state`` enforces them.
    """

    CREATED = "created"
    SCOPING = "scoping"
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    MAPPING = "mapping"
    ANALYSIS = "analysis"
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    VALIDATION = "validation"
    PROOF = "proof"
    REASSESSMENT = "reassessment"
    REPORTING = "reporting"
    COMPLETED = "completed"
    PAUSED = "paused"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for states that end a mission."""
        return self in (
            MissionState.COMPLETED,
            MissionState.FAILED,
            MissionState.CANCELLED,
        )

    @property
    def is_active(self) -> bool:
        """Return ``True`` while the mission can still transition."""
        return not self.is_terminal


class MissionMode(StrEnum):
    """Configurable planning modes.

    Modes modify priorities and constraints; they NEVER override
    authorization or safety policies.
    """

    FAST = "fast"
    BALANCED = "balanced"
    DEEP = "deep"
    STEALTH = "stealth"
    COVERAGE_FIRST = "coverage_first"
    EVIDENCE_FIRST = "evidence_first"
    PROOF_FIRST = "proof_first"
    BUG_BOUNTY = "bug_bounty"
    PENTEST = "pentest"
    RED_TEAM_SIMULATION = "red_team_simulation"


class ActionType(StrEnum):
    """Canonical action node types.

    A node represents an *action* (not simply a tool invocation) so the same
    logical action can be satisfied by any compatible tool.
    """

    DISCOVER_SUBDOMAINS = "discover_subdomains"
    ENUMERATE_DNS = "enumerate_dns"
    IDENTIFY_SERVICES = "identify_services"
    ENUMERATE_HTTP = "enumerate_http"
    IDENTIFY_TECHNOLOGY = "identify_technology"
    DISCOVER_ENDPOINTS = "discover_endpoints"
    DISCOVER_PARAMETERS = "discover_parameters"
    MAP_API = "map_api"
    MAP_GRAPHQL = "map_graphql"
    ANALYZE_AUTHENTICATION = "analyze_authentication"
    TEST_AUTHORIZATION = "test_authorization"
    GENERATE_HYPOTHESIS = "generate_hypothesis"
    VALIDATE_HYPOTHESIS = "validate_hypothesis"
    COLLECT_PROOF = "collect_proof"
    REPLAY_PROOF = "replay_proof"
    GENERATE_FINDING = "generate_finding"
    INVESTIGATE_BEHAVIOR = "investigate_behavior"
    RESOLVE_CONFLICT = "resolve_conflict"
    REASSESS = "reassess"
    MONITOR_TARGET = "monitor_target"
    STOP = "stop"


class DependencyKind(StrEnum):
    """Dynamic dependency kinds between action nodes."""

    DEPENDS_ON = "depends_on"
    BLOCKS = "blocks"
    ENABLES = "enables"
    INVALIDATES = "invalidates"
    SUPERSEDES = "supersedes"
    ALTERNATIVE_TO = "alternative_to"
    REQUIRES_EVIDENCE = "requires_evidence"
    REQUIRES_OBSERVATION = "requires_observation"
    REQUIRES_PROOF = "requires_proof"


class BranchKind(StrEnum):
    """Conditional branching constructs supported by the execution graph."""

    IF = "if"
    THEN = "then"
    ELSE = "else"
    GOTO = "goto"
    FORK = "fork"
    JOIN = "join"
    WAIT_FOR_EVIDENCE = "wait_for_evidence"
    REPLAN = "replan"
    STOP = "stop"


class ActionStatus(StrEnum):
    """Runtime status of an action node."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    PAUSED = "paused"
    SUPERSEDED = "superseded"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for terminal action states."""
        return self in (
            ActionStatus.COMPLETED,
            ActionStatus.FAILED,
            ActionStatus.BLOCKED,
            ActionStatus.SKIPPED,
            ActionStatus.SUPERSEDED,
        )


class ReplanTrigger(StrEnum):
    """Events that may trigger a replan."""

    NEW_ASSET_DISCOVERED = "new_asset_discovered"
    NEW_TECHNOLOGY_DISCOVERED = "new_technology_discovered"
    NEW_ENDPOINT_DISCOVERED = "new_endpoint_discovered"
    NEW_PARAMETER_DISCOVERED = "new_parameter_discovered"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    NEW_HYPOTHESIS_CREATED = "new_hypothesis_created"
    HYPOTHESIS_CONFIDENCE_CHANGED = "hypothesis_confidence_changed"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    PROOF_BECOMES_POSSIBLE = "proof_becomes_possible"
    PROOF_FAILED = "proof_failed"
    TARGET_STATE_CHANGED = "target_state_changed"
    SCOPE_CHANGED = "scope_changed"
    TOOL_CAPABILITY_CHANGED = "tool_capability_changed"
    RISK_THRESHOLD_CHANGED = "risk_threshold_changed"
    MISSION_OBJECTIVE_CHANGED = "mission_objective_changed"
    CRITICAL_INFORMATION_GAP = "critical_information_gap"
    UNKNOWN_BEHAVIOR_OBSERVED = "unknown_behavior_observed"


class PlanDeltaKind(StrEnum):
    """Kinds of plan mutations a replan can emit.

    Replanning produces a :class:`PlanDelta` made of these changes; the full
    mission is never rebuilt unnecessarily.
    """

    ADD_ACTION = "add_action"
    REMOVE_ACTION = "remove_action"
    MODIFY_ACTION = "modify_action"
    REORDER_ACTION = "reorder_action"
    PAUSE_ACTION = "pause_action"
    RESUME_ACTION = "resume_action"
    REPLACE_TOOL = "replace_tool"
    CHANGE_PRIORITY = "change_priority"
    CREATE_BRANCH = "create_branch"
    MERGE_BRANCH = "merge_branch"
    INVALIDATE_BRANCH = "invalidate_branch"
    MARK_COMPLETE = "mark_complete"


class AttackPathState(StrEnum):
    """Validation state of an attack path.

    The states are intentionally not collapsed: a hypothetical path must never
    be reported as validated, and a validated path must never be reported as
    proved.
    """

    HYPOTHETICAL = "hypothetical"
    SUPPORTED = "supported"
    VALIDATED = "validated"
    PROVED = "proved"


class AttackPathStepKind(StrEnum):
    """Classification of a step inside an attack path."""

    EXPOSURE = "exposure"
    REACHABILITY = "reachability"
    SERVICE = "service"
    APPLICATION = "application"
    AUTHENTICATION_BOUNDARY = "authentication_boundary"
    AUTHORIZATION_WEAKNESS = "authorization_weakness"
    SENSITIVE_RESOURCE = "sensitive_resource"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    CONFIGURATION_EXPOSURE = "configuration_exposure"
    VALIDATED_WEAKNESS = "validated_weakness"


class FailureClass(StrEnum):
    """Canonical tool-failure classification."""

    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    NETWORK_ERROR = "network_error"
    AUTH_ERROR = "auth_error"
    INVALID_INPUT = "invalid_input"
    TARGET_CHANGED = "target_changed"
    TOOL_ERROR = "tool_error"
    PARSER_ERROR = "parser_error"
    RESOURCE_LIMIT = "resource_limit"
    POLICY_BLOCK = "policy_block"
    UNKNOWN = "unknown"


class FailureManagement(StrEnum):
    """Failure-management strategies the planner may select."""

    RETRY = "retry"
    RETRY_DIFFERENTLY = "retry_differently"
    REPLACE_TOOL = "replace_tool"
    CHANGE_STRATEGY = "change_strategy"
    PAUSE = "pause"
    MARK_UNAVAILABLE = "mark_unavailable"
    REPLAN = "replan"


class ValidationLevel(StrEnum):
    """Safe-validation escalation ladder.

    The planner must never automatically escalate from discovery to
    destructive exploitation; each level carries its own policy gates.
    """

    DISCOVERY = "discovery"
    VALIDATION = "validation"
    PROOF = "proof"
    IMPACT_DEMONSTRATION = "impact_demonstration"


class DecisionFactor(StrEnum):
    """Explainable action-ranking factors."""

    INFORMATION_GAIN = "information_gain"
    HYPOTHESIS_RELEVANCE = "hypothesis_relevance"
    COVERAGE_IMPROVEMENT = "coverage_improvement"
    EVIDENCE_VALUE = "evidence_value"
    PROOF_VALUE = "proof_value"
    ASSET_CRITICALITY = "asset_criticality"
    MISSION_PRIORITY = "mission_priority"
    TOOL_EFFECTIVENESS = "tool_effectiveness"
    EXECUTION_COST = "execution_cost"
    EXECUTION_RISK = "execution_risk"
    REDUNDANCY = "redundancy"
    DEPENDENCY_READINESS = "dependency_readiness"


class PathScoringDimension(StrEnum):
    """Explainable attack-path scoring dimensions."""

    REACHABILITY = "reachability"
    EVIDENCE_STRENGTH = "evidence_strength"
    ASSET_CRITICALITY = "asset_criticality"
    ASSUMPTION_COUNT = "assumption_count"
    VALIDATION_STATE = "validation_state"
    PROOF_AVAILABILITY = "proof_availability"
    RISK = "risk"
    MISSION_OBJECTIVE = "mission_objective"


class EvidenceGapKind(StrEnum):
    """Kinds of gaps the planner recognises.

    A candidate finding becomes reportable only when its evidence and proof
    requirements are met; gaps capture what is still missing.
    """

    EVIDENCE_GAP = "evidence_gap"
    PROOF_GAP = "proof_gap"


class ToolFailureAction(StrEnum):
    """Planner-level response to a tool failure."""

    RETRY = "retry"
    RETRY_DIFFERENTLY = "retry_differently"
    REPLACE_TOOL = "replace_tool"
    CHANGE_STRATEGY = "change_strategy"
    PAUSE = "pause"
    MARK_UNAVAILABLE = "mark_unavailable"
    REPLAN = "replan"
