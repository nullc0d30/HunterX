# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration — orchestration domain models.

Sprint 032. Data contracts for the orchestration layer: mission scope, policy,
budget, run, observation, decision, hypothesis, branch, outcome, coverage
snapshot, negative evidence, baseline observation, differential result, impact
analysis, reasoning-trace entry and telemetry snapshot.

The orchestration layer reuses the Sprint 027 planning aggregate
(:class:`AdaptiveMission`) and its ``ActionNode`` graph as the executable
mission; the models here carry the reasoning/evidence state that drives the
adaptive loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.mission_orchestration.enums import (
    BehaviorClass,
    DifferentialSignal,
    HypothesisState,
    MissionRunStatus,
    NegativeEvidenceKind,
    NovelPipelineStage,
    ReasoningTraceKind,
    StopCondition,
    StrategyKind,
)
from hunterx.domain.target_intelligence.enums import (
    CoverageState,
    HypothesisType,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class MissionScope:
    """Authorized scope of an orchestrated mission.

    Scope is immutable at mission creation: no AI proposal or tool output may
    expand it. Each action receives this scope plus the execution policy.
    """

    included_targets: tuple[str, ...] = ()
    excluded_assets: tuple[str, ...] = ()
    included_domains: tuple[str, ...] = ()
    authorization_contexts: tuple[str, ...] = ("anonymous",)

    def allows(self, target: str) -> bool:
        """Return ``True`` when ``target`` falls inside the authorized scope.

        A target is inside the scope when it equals an included target, is a
        subdomain of one, or lives under an included URL path. Excluded assets
        (and their subdomains) always block the target.
        """
        if self.excluded_assets and any(
            target == excluded
            or target.endswith("." + excluded)
            or target.startswith(excluded + "/")
            for excluded in self.excluded_assets
        ):
            return False
        if not self.included_targets:
            return True
        return any(
            target == included or target.endswith("." + included) or target.startswith(included + "/")
            for included in self.included_targets
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "included_targets": list(self.included_targets),
            "excluded_assets": list(self.excluded_assets),
            "included_domains": list(self.included_domains),
            "authorization_contexts": list(self.authorization_contexts),
        }


@dataclass(frozen=True, slots=True)
class MissionPolicy:
    """Mission intent configuration (mission configuration, never tool code).

    Attributes:
        policy_id: stable policy identifier.
        objective_name: canonical objective value.
        strategy: :class:`StrategyKind`.
        allowed_techniques: capabilities the mission may exercise.
        resource_budget: resource units (tool executions) the mission may use.
        time_budget_seconds: wall-clock budget.
        validation_depth: ``discovery``/``validation``/``proof``/``impact_demonstration``.
        proof_depth: ``none``/``minimal``/``full``.
        coverage_target: coverage ratio in ``[0, 1]`` the mission aims for.
        stop_conditions: :class:`StopCondition` values that may end the mission.
        max_concurrency: parallel action cap.
        rate_limit_per_minute: target-friendly rate limit.

    """

    policy_id: str = field(default_factory=generate_id)
    objective_name: str = "full_security_assessment"
    strategy: StrategyKind = StrategyKind.ADAPTIVE
    allowed_techniques: tuple[str, ...] = ()
    resource_budget: int = 1000
    time_budget_seconds: int = 0
    validation_depth: str = "proof"
    proof_depth: str = "minimal"
    coverage_target: float = 0.7
    stop_conditions: tuple[StopCondition, ...] = (
        StopCondition.OBJECTIVES_COMPLETE,
        StopCondition.COVERAGE_TARGET_ACHIEVED,
        StopCondition.HIGH_VALUE_HYPOTHESES_RESOLVED,
        StopCondition.FINDINGS_VALIDATED,
        StopCondition.RESOURCE_BUDGET_EXHAUSTED,
        StopCondition.TIME_BUDGET_EXHAUSTED,
    )
    max_concurrency: int = 4
    rate_limit_per_minute: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "policy_id": self.policy_id,
            "objective_name": self.objective_name,
            "strategy": self.strategy.value,
            "allowed_techniques": list(self.allowed_techniques),
            "resource_budget": self.resource_budget,
            "time_budget_seconds": self.time_budget_seconds,
            "validation_depth": self.validation_depth,
            "proof_depth": self.proof_depth,
            "coverage_target": self.coverage_target,
            "stop_conditions": [condition.value for condition in self.stop_conditions],
            "max_concurrency": self.max_concurrency,
            "rate_limit_per_minute": self.rate_limit_per_minute,
        }


@dataclass(slots=True)
class MissionBudget:
    """Tracked resource consumption of a mission.

    Resource awareness: CPU, memory, network, disk, execution count,
    concurrency, time and tool cost. The planner adapts when the budget is
    close to exhausted.
    """

    executions_used: int = 0
    executions_budget: int = 1000
    time_used_seconds: int = 0
    time_budget_seconds: int = 0
    max_concurrency: int = 4
    active_concurrency: int = 0
    tool_cost: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    disk_mb: float = 0.0
    network_kb: float = 0.0

    @property
    def execution_remaining(self) -> int:
        """Return the remaining execution budget."""
        return max(0, self.executions_budget - self.executions_used)

    @property
    def execution_exhausted(self) -> bool:
        """Return ``True`` when the execution budget is genuinely exhausted.

        ``executions_budget`` is a hard ceiling: exhaustion is defined as
        ``executions_used >= executions_budget``. A ``0`` budget means "no
        executions permitted" (immediately exhausted); ``None``/negative values
        are rejected at configuration time.
        """
        return self.executions_used >= self.executions_budget

    @property
    def time_exhausted(self) -> bool:
        """Return ``True`` when the wall-clock budget is exhausted.

        ``time_budget_seconds`` semantics: ``0`` means **unlimited** (never
        exhausted by time), any positive value is a hard ceiling. A negative
        value is rejected at configuration time.
        """
        return (
            self.time_budget_seconds > 0
            and self.time_used_seconds >= self.time_budget_seconds
        )

    @property
    def exhausted(self) -> bool:
        """Return ``True`` when any configured budget dimension is exhausted.

        This property intentionally only reflects *configured* ceilings: a
        ``0`` time budget is unlimited and never makes the mission "exhausted".
        It is used by the stop-condition policy as the source of truth for
        ``resource_budget_exhausted``.
        """
        return self.execution_exhausted or self.time_exhausted

    def exhausted_resource(self) -> str:
        """Return the canonical name of the resource that caused exhaustion.

        Identifies the exact budget dimension that fired so a stop condition
        names its resource (``executions`` / ``time`` / ``""`` when nothing is
        exhausted).
        """
        if self.execution_exhausted:
            return "executions"
        if self.time_exhausted:
            return "time"
        return ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "executions_used": self.executions_used,
            "executions_budget": self.executions_budget,
            "execution_remaining": self.execution_remaining,
            "time_used_seconds": self.time_used_seconds,
            "time_budget_seconds": self.time_budget_seconds,
            "max_concurrency": self.max_concurrency,
            "active_concurrency": self.active_concurrency,
            "tool_cost": self.tool_cost,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "disk_mb": self.disk_mb,
            "network_kb": self.network_kb,
            "execution_exhausted": self.execution_exhausted,
            "time_exhausted": self.time_exhausted,
        }


@dataclass(frozen=True, slots=True)
class MissionObservation:
    """A single normalized observation produced by an action.

    Observations are the atomic unit of the hypothesis loop: the orchestrator
    parses and normalizes every tool result into observations before updating
    the target state.
    """

    observation_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    action_id: str = ""
    tool_id: str = ""
    tool_version: str = ""
    asset_key: str = ""
    observation_type: str = ""
    content: dict[str, Any] = field(default_factory=dict)
    evidence_ref: str = ""
    confidence: float = 0.0
    raw_tool_id: str = ""
    created_at: str = field(default_factory=utcnow_iso)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "observation_id": self.observation_id,
            "mission_id": self.mission_id,
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "asset_key": self.asset_key,
            "observation_type": self.observation_type,
            "content": self.content,
            "evidence_ref": self.evidence_ref,
            "confidence": self.confidence,
            "raw_tool_id": self.raw_tool_id,
            "created_at": self.created_at,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class MissionHypothesis:
    """An orchestration-level hypothesis with evidence-driven state.

    Wraps the Sprint 026/027 hypothesis concept with the full status lifecycle
    (SUPPORTED / WEAKLY_SUPPORTED / REFUTED / INCONCLUSIVE / VALIDATED /
    DISPROVED / NOVEL_BEHAVIOR) and the classification of the observed behavior.
    """

    hypothesis_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    statement: str = ""
    category: HypothesisType = HypothesisType.UNKNOWN_BEHAVIOR
    state: HypothesisState = HypothesisState.PROPOSED
    behavior_class: BehaviorClass = BehaviorClass.NOVEL_CANDIDATE
    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    tested_actions: tuple[str, ...] = ()
    confidence: float = 0.0
    priority: float = 0.5
    validation_strategy: str = ""
    proof_strategy: str = ""
    proposed_by: str = "orchestrator"
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "mission_id": self.mission_id,
            "statement": self.statement,
            "category": self.category.value if isinstance(self.category, HypothesisType) else str(self.category),
            "state": self.state.value,
            "behavior_class": self.behavior_class.value,
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "tested_actions": list(self.tested_actions),
            "confidence": self.confidence,
            "priority": self.priority,
            "validation_strategy": self.validation_strategy,
            "proof_strategy": self.proof_strategy,
            "proposed_by": self.proposed_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class MissionDecision:
    """An explainable orchestration decision.

    The decision engine output contract: NEXT_ACTION, REASON, EXPECTED_RESULT,
    PRIORITY, DEPENDENCIES and ALTERNATIVES, plus the weighted rationale and
    the decision latency for telemetry.
    """

    decision_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    next_action: str = ""
    capability: str = ""
    tool_id: str = ""
    reason: str = ""
    expected_result: str = ""
    priority: float = 0.0
    dependencies: tuple[str, ...] = ()
    alternatives: tuple[tuple[str, str], ...] = ()  # (tool, why-not)
    information_gain: float = 0.0
    factors: dict[str, float] = field(default_factory=dict)
    ai_assisted: bool = False
    decided_at: str = field(default_factory=utcnow_iso)
    latency_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "decision_id": self.decision_id,
            "mission_id": self.mission_id,
            "next_action": self.next_action,
            "capability": self.capability,
            "tool_id": self.tool_id,
            "reason": self.reason,
            "expected_result": self.expected_result,
            "priority": self.priority,
            "dependencies": list(self.dependencies),
            "alternatives": [list(pair) for pair in self.alternatives],
            "information_gain": self.information_gain,
            "factors": self.factors,
            "ai_assisted": self.ai_assisted,
            "decided_at": self.decided_at,
            "latency_ms": self.latency_ms,
        }


@dataclass(slots=True)
class MissionBranch:
    """A mission branch opened by a fork in the observations.

    Each branch keeps its own hypothesis, state, evidence, actions, cost and
    outcome; the orchestrator ranks open branches and pursues the best one
    first without abandoning the others.
    """

    branch_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    parent_branch_id: str = ""
    hypothesis_id: str = ""
    rationale: str = ""
    state: str = "open"
    actions: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    cost: float = 0.0
    priority: float = 0.5
    outcome: str = ""
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "branch_id": self.branch_id,
            "mission_id": self.mission_id,
            "parent_branch_id": self.parent_branch_id,
            "hypothesis_id": self.hypothesis_id,
            "rationale": self.rationale,
            "state": self.state,
            "actions": list(self.actions),
            "evidence_refs": list(self.evidence_refs),
            "cost": self.cost,
            "priority": self.priority,
            "outcome": self.outcome,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class MissionOutcome:
    """Final outcome of an orchestrated mission.

    Captures the summary of what was discovered, validated, proved and
    reported, plus the final coverage and telemetry snapshot.
    """

    mission_id: str = ""
    phase: str = ""
    objectives_complete: bool = False
    findings_validated: int = 0
    findings_report_ready: int = 0
    hypotheses_resolved: int = 0
    hypotheses_open: int = 0
    probes_executed: int = 0
    attack_paths_discovered: int = 0
    coverage_ratio: float = 0.0
    executions_used: int = 0
    completed_at: str = field(default_factory=utcnow_iso)
    stop_condition: str = ""
    exhausted_resource: str = ""
    ai_unavailable: bool = False
    blocked_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "mission_id": self.mission_id,
            "phase": self.phase,
            "objectives_complete": self.objectives_complete,
            "findings_validated": self.findings_validated,
            "findings_report_ready": self.findings_report_ready,
            "hypotheses_resolved": self.hypotheses_resolved,
            "hypotheses_open": self.hypotheses_open,
            "probes_executed": self.probes_executed,
            "attack_paths_discovered": self.attack_paths_discovered,
            "coverage_ratio": self.coverage_ratio,
            "executions_used": self.executions_used,
            "completed_at": self.completed_at,
            "stop_condition": self.stop_condition,
            "exhausted_resource": self.exhausted_resource,
            "ai_unavailable": self.ai_unavailable,
            "blocked_reason": self.blocked_reason,
        }


@dataclass(slots=True)
class MissionRun:
    """A single execution run of a mission (supports stop/restart/continue)."""

    run_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    status: MissionRunStatus = MissionRunStatus.PENDING
    started_at: str = ""
    finished_at: str = ""
    resumed_from_run_id: str = ""
    checkpoint_id: str = ""
    last_action_id: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "run_id": self.run_id,
            "mission_id": self.mission_id,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "resumed_from_run_id": self.resumed_from_run_id,
            "checkpoint_id": self.checkpoint_id,
            "last_action_id": self.last_action_id,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class NegativeEvidenceRecord:
    """A bounded negative-evidence record.

    Remembers what was tested, with which tool/version/input, when, and what
    was (not) found. "Not found" never means "not vulnerable".
    """

    record_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    asset_key: str = ""
    capability: str = ""
    kind: NegativeEvidenceKind = NegativeEvidenceKind.TESTED
    tool_id: str = ""
    tool_version: str = ""
    input_hash: str = ""
    outcome: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)
    tested_at: str = field(default_factory=utcnow_iso)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "record_id": self.record_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "capability": self.capability,
            "kind": self.kind.value,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "input_hash": self.input_hash,
            "outcome": self.outcome,
            "conditions": self.conditions,
            "tested_at": self.tested_at,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class BaselineObservation:
    """A baseline behavior observation for differential reasoning.

    Baselines cover HTTP, DNS, TLS, authentication, response codes, headers,
    content, timing, parameters and application behavior. Differential tests
    compare a test request against a matching baseline.
    """

    baseline_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    asset_key: str = ""
    request_fingerprint: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    content_length: int = 0
    body_hash: str = ""
    timing_ms: int = 0
    parameters: dict[str, Any] = field(default_factory=dict)
    captured_at: str = field(default_factory=utcnow_iso)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "baseline_id": self.baseline_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "request_fingerprint": self.request_fingerprint,
            "status_code": self.status_code,
            "headers": self.headers,
            "content_length": self.content_length,
            "body_hash": self.body_hash,
            "timing_ms": self.timing_ms,
            "parameters": self.parameters,
            "captured_at": self.captured_at,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    """Result of comparing a test request against a baseline.

    A differential signal (status change, length change, header change,
    reflection, timing, callback, error behavior, content mutation) is the
    behavioral evidence that separates a real weakness from a false positive.
    """

    result_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    asset_key: str = ""
    baseline_id: str = ""
    signals: tuple[DifferentialSignal, ...] = ()
    delta_summary: dict[str, Any] = field(default_factory=dict)
    matched_baseline: bool = False
    evidence_classification: str = ""
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "result_id": self.result_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "baseline_id": self.baseline_id,
            "signals": [signal.value for signal in self.signals],
            "delta_summary": self.delta_summary,
            "matched_baseline": self.matched_baseline,
            "evidence_classification": self.evidence_classification,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class ImpactAnalysis:
    """Impact analysis for a validated finding.

    Computes technical impact, affected assets/users, data exposure potential,
    privilege boundary, business impact indicators, exploitability,
    reproducibility and confidence.
    """

    impact_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    mission_id: str = ""
    technical_impact: str = ""
    affected_assets: tuple[str, ...] = ()
    affected_users: str = ""
    data_exposure_potential: str = "none"
    privilege_boundary: str = ""
    business_impact_indicators: dict[str, Any] = field(default_factory=dict)
    exploitability: str = "low"
    reproducibility: bool = False
    confidence: float = 0.0
    analyzed_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "impact_id": self.impact_id,
            "finding_id": self.finding_id,
            "mission_id": self.mission_id,
            "technical_impact": self.technical_impact,
            "affected_assets": list(self.affected_assets),
            "affected_users": self.affected_users,
            "data_exposure_potential": self.data_exposure_potential,
            "privilege_boundary": self.privilege_boundary,
            "business_impact_indicators": self.business_impact_indicators,
            "exploitability": self.exploitability,
            "reproducibility": self.reproducibility,
            "confidence": self.confidence,
            "analyzed_at": self.analyzed_at,
        }


@dataclass(frozen=True, slots=True)
class ReasoningTraceEntry:
    """A single entry in the structured reasoning trace.

    The trace is an auditable reasoning graph: observation → hypothesis →
    decision → evidence → action → result. It never stores hidden
    chain-of-thought.
    """

    entry_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    kind: ReasoningTraceKind = ReasoningTraceKind.OBSERVATION
    node_id: str = ""
    content: dict[str, Any] = field(default_factory=dict)
    parent_entry_id: str = ""
    occurred_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "entry_id": self.entry_id,
            "mission_id": self.mission_id,
            "kind": self.kind.value,
            "node_id": self.node_id,
            "content": self.content,
            "parent_entry_id": self.parent_entry_id,
            "occurred_at": self.occurred_at,
        }


@dataclass(frozen=True, slots=True)
class TelemetrySnapshot:
    """A mission telemetry snapshot.

    Tracks decision latency, tool utilization, finding yield, validation yield,
    false-positive rate, coverage, evidence quality, branch efficiency,
    resource utilization, failed actions and fallback rate.
    """

    mission_id: str = ""
    decision_count: int = 0
    decision_latency_ms_avg: float = 0.0
    tool_executions: int = 0
    tool_utilization: float = 0.0
    finding_yield: float = 0.0
    validation_yield: float = 0.0
    false_positive_rate: float = 0.0
    coverage_ratio: float = 0.0
    evidence_quality: float = 0.0
    branch_efficiency: float = 0.0
    failed_actions: int = 0
    fallback_rate: float = 0.0
    resource_utilization: float = 0.0
    ai_enabled: bool = False
    ai_provider: str = ""
    ai_model: str = ""
    ai_requests_attempted: int = 0
    ai_requests_succeeded: int = 0
    ai_requests_failed: int = 0
    ai_http_429: int = 0
    ai_timeouts: int = 0
    ai_provider_errors: int = 0
    ai_fallbacks: int = 0
    ai_cooldown_events: int = 0
    ai_deterministic_decisions: int = 0
    ai_assisted_decisions: int = 0
    hypotheses_tested: int = 0
    hypotheses_deferred: int = 0
    hypotheses_blocked: int = 0
    active_tests_attempted: int = 0
    active_tests_completed: int = 0
    browser_tests_attempted: int = 0
    browser_tests_completed: int = 0
    attack_paths_generated: int = 0
    attack_paths_tested: int = 0
    attack_paths_validated: int = 0
    completion_gate_failures: int = 0
    recorded_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "mission_id": self.mission_id,
            "decision_count": self.decision_count,
            "decision_latency_ms_avg": self.decision_latency_ms_avg,
            "tool_executions": self.tool_executions,
            "tool_utilization": self.tool_utilization,
            "finding_yield": self.finding_yield,
            "validation_yield": self.validation_yield,
            "false_positive_rate": self.false_positive_rate,
            "coverage_ratio": self.coverage_ratio,
            "evidence_quality": self.evidence_quality,
            "branch_efficiency": self.branch_efficiency,
            "failed_actions": self.failed_actions,
            "fallback_rate": self.fallback_rate,
            "resource_utilization": self.resource_utilization,
            "ai_enabled": self.ai_enabled,
            "ai_provider": self.ai_provider,
            "ai_model": self.ai_model,
            "ai_requests_attempted": self.ai_requests_attempted,
            "ai_requests_succeeded": self.ai_requests_succeeded,
            "ai_requests_failed": self.ai_requests_failed,
            "ai_http_429": self.ai_http_429,
            "ai_timeouts": self.ai_timeouts,
            "ai_provider_errors": self.ai_provider_errors,
            "ai_fallbacks": self.ai_fallbacks,
            "ai_cooldown_events": self.ai_cooldown_events,
            "ai_deterministic_decisions": self.ai_deterministic_decisions,
            "ai_assisted_decisions": self.ai_assisted_decisions,
            "hypotheses_tested": self.hypotheses_tested,
            "hypotheses_deferred": self.hypotheses_deferred,
            "hypotheses_blocked": self.hypotheses_blocked,
            "active_tests_attempted": self.active_tests_attempted,
            "active_tests_completed": self.active_tests_completed,
            "browser_tests_attempted": self.browser_tests_attempted,
            "browser_tests_completed": self.browser_tests_completed,
            "attack_paths_generated": self.attack_paths_generated,
            "attack_paths_tested": self.attack_paths_tested,
            "attack_paths_validated": self.attack_paths_validated,
            "completion_gate_failures": self.completion_gate_failures,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True, slots=True)
class CoverageCell:
    """A mission coverage cell (asset × capability).

    Tracks the assessed state, the tool that produced it, evidence references
    and the classification of any behavior observed.
    """

    cell_key: str = ""
    asset_key: str = ""
    capability: str = ""
    state: CoverageState = CoverageState.NOT_ASSESSED
    tool_id: str = ""
    confidence: float = 0.0
    evidence_refs: tuple[str, ...] = ()
    tested_at: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "cell_key": self.cell_key,
            "asset_key": self.asset_key,
            "capability": self.capability,
            "state": self.state.value,
            "tool_id": self.tool_id,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "tested_at": self.tested_at,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class NovelBehaviorRecord:
    """A record of the novel-vulnerability discovery pipeline.

    When behavior does not match known knowledge, the mission advances it
    through the experiment loop (UNKNOWN_BEHAVIOR → BEHAVIORAL_MODEL →
    HYPOTHESIS → EXPERIMENT → OBSERVATION → NEW_HYPOTHESIS → MINIMAL_PROOF →
    VALIDATED_BEHAVIOR) and classifies the result.
    """

    record_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    asset_key: str = ""
    stage: NovelPipelineStage = NovelPipelineStage.UNKNOWN_BEHAVIOR
    behavior_summary: str = ""
    experiments: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    classification: BehaviorClass = BehaviorClass.NOVEL_CANDIDATE
    hypothesis_id: str = ""
    proof_ref: str = ""
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "record_id": self.record_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "stage": self.stage.value,
            "behavior_summary": self.behavior_summary,
            "experiments": list(self.experiments),
            "observations": list(self.observations),
            "classification": self.classification.value,
            "hypothesis_id": self.hypothesis_id,
            "proof_ref": self.proof_ref,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(slots=True)
class MissionContext:
    """The persistent, target-centric context of an orchestrated mission.

    Carries references to the mission, target, scope, assets, technologies,
    services, endpoints, parameters, credentials/contexts (where authorized),
    observations, findings, hypotheses, evidence, PoCs, tool executions, attack
    paths, previous decisions, current phase, current objectives, remaining
    objectives, resource state and mission history.
    """

    mission_id: str = ""
    target_id: str = ""
    scope: MissionScope = field(default_factory=MissionScope)
    assets: dict[str, Any] = field(default_factory=dict)
    technologies: dict[str, Any] = field(default_factory=dict)
    services: dict[str, Any] = field(default_factory=dict)
    endpoints: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    contexts: dict[str, Any] = field(default_factory=dict)
    observations: list[MissionObservation] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[MissionHypothesis] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    proofs: dict[str, Any] = field(default_factory=dict)
    tool_executions: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    surface_relationships: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[MissionDecision] = field(default_factory=list)
    current_phase: str = "target_modeling"
    current_objectives: list[str] = field(default_factory=list)
    remaining_objectives: list[str] = field(default_factory=list)
    resource_state: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    def touch(self) -> None:
        """Refresh the updated timestamp."""
        self.updated_at = utcnow_iso()

    def observation(self, observation_id: str) -> MissionObservation | None:
        """Return an observation by id or ``None``."""
        for observation in self.observations:
            if observation.observation_id == observation_id:
                return observation
        return None

    def add_observation(self, observation: MissionObservation) -> None:
        """Append a normalized observation and refresh the context."""
        self.observations.append(observation)
        self.touch()

    def hypothesis(self, hypothesis_id: str) -> MissionHypothesis | None:
        """Return a hypothesis by id or ``None``."""
        for hypothesis in self.hypotheses:
            if hypothesis.hypothesis_id == hypothesis_id:
                return hypothesis
        return None

    def decision(self, decision_id: str) -> MissionDecision | None:
        """Return a decision by id or ``None``."""
        for decision in self.decisions:
            if decision.decision_id == decision_id:
                return decision
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the context summary to a JSON-safe mapping."""
        return {
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "scope": self.scope.to_dict(),
            "asset_count": len(self.assets),
            "technology_count": len(self.technologies),
            "service_count": len(self.services),
            "endpoint_count": len(self.endpoints),
            "parameter_count": len(self.parameters),
            "context_count": len(self.contexts),
            "observation_count": len(self.observations),
            "finding_count": len(self.findings),
            "hypothesis_count": len(self.hypotheses),
            "evidence_count": len(self.evidence),
            "proof_count": len(self.proofs),
            "tool_execution_count": len(self.tool_executions),
            "attack_path_count": len(self.attack_paths),
            "surface_relationship_count": len(self.surface_relationships),
            "decision_count": len(self.decisions),
            "current_phase": self.current_phase,
            "current_objectives": list(self.current_objectives),
            "remaining_objectives": list(self.remaining_objectives),
            "resource_state": self.resource_state,
            "history_count": len(self.history),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


__all__ = [
    "BaselineObservation",
    "CoverageCell",
    "DifferentialResult",
    "ImpactAnalysis",
    "MissionBranch",
    "MissionBudget",
    "MissionContext",
    "MissionDecision",
    "MissionHypothesis",
    "MissionObservation",
    "MissionOutcome",
    "MissionPolicy",
    "MissionRun",
    "MissionScope",
    "NegativeEvidenceRecord",
    "NovelBehaviorRecord",
    "ReasoningTraceEntry",
    "TelemetrySnapshot",
]
