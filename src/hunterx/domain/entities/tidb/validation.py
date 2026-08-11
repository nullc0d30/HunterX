# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Safe vulnerability discovery & validation TIDB entities.

System-of-record entities for the Wave 13 safe vulnerability discovery &
validation capability: vulnerability hypotheses, validation rules, validation
plans and steps, validation executions, validation evidence (provenance-backed
canonical observations), verdicts, per-target validation history, temporal
differentials, tool usage observability and policy decisions. Every validation
fact that matters is persisted here — never only in memory, logs or reports.

Security boundary: these tables store safe-validation metadata, canonical
observations and redacted evidence only — never exploit payloads, never
credentials, never out-of-scope request material.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class VulnerabilityHypothesis(TidbEntity):
    """A persisted vulnerability hypothesis.

    Attributes:
        hypothesis_id: stable hypothesis identifier.
        mission_id / target_id / asset_id: scoping identifiers.
        finding_id: source finding that triggered the hypothesis.
        vulnerability_id: canonical vulnerability identifier (CVE id).
        technology_id: canonical technology identifier.
        class_name: canonical vulnerability class.
        description: hypothesis statement.
        preconditions: preconditions that must hold before validation.
        expected_behavior / unexpected_behavior: behavior expectations.
        confidence: hypothesis confidence in ``[0, 1]``.
        priority: risk priority.
        scope: scope context (JSON-safe).
        safety_class: allowed safety class.
        validation_strategy: strategy applied.
        state: canonical vulnerability state.
        created_by: producing component.
        analysis_version: analysis version.

    """

    hypothesis_id: str
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    finding_id: str = ""
    vulnerability_id: str = ""
    technology_id: str = ""
    class_name: str = "known_vulnerable_software"
    description: str = ""
    preconditions: list[str] = field(default_factory=list)
    expected_behavior: str = ""
    unexpected_behavior: str = ""
    confidence: float = 0.0
    priority: str = "unknown"
    scope: dict[str, object] = field(default_factory=dict)
    safety_class: str = "passive"
    validation_strategy: str = "version_validation"
    state: str = "suspected"
    created_by: str = "vulnerability.validation"
    analysis_version: str = "1.0.0"


@dataclass(slots=True)
class ValidationRule(TidbEntity):
    """A persisted validation rule."""

    rule_id: str
    vulnerability_class: str = "known_vulnerable_software"
    strategy: str = "version_validation"
    description: str = ""
    rule_version: str = "1.0.0"
    minimum_confidence: float = 0.0
    required_evidence: list[str] = field(default_factory=list)
    permits_confirmation: bool = False
    confirmation_evidence: list[str] = field(default_factory=list)
    safe_checks: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    expected_behavior: str = ""
    unexpected_behavior: str = ""
    inconclusive_conditions: list[str] = field(default_factory=list)
    false_positive_rules: list[str] = field(default_factory=list)
    risk_level: str = "medium"
    scope_requirements: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ValidationPlan(TidbEntity):
    """A persisted validation plan."""

    plan_id: str
    hypothesis_id: str = ""
    mission_id: str = ""
    strategy: str = "version_validation"
    status: str = "planned"
    dependencies: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    scope: dict[str, object] = field(default_factory=dict)
    safety_policy: str = "default"
    timeout: float = 120.0
    retry_policy: dict[str, object] = field(default_factory=dict)
    rate_limit: float = 0.0
    expected_observations: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    abort_conditions: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ValidationStep(TidbEntity):
    """A persisted validation step."""

    step_id: str
    plan_id: str = ""
    order: int = 0
    action: str = ""
    tool_id: str = ""
    strategy: str = "version_validation"
    parameters: dict[str, object] = field(default_factory=dict)
    expected_observations: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    abort_conditions: list[str] = field(default_factory=list)
    timeout: float = 30.0
    retryable: bool = False
    rate_limit: float = 0.0
    safety_class: str = "passive"


@dataclass(slots=True)
class ValidationExecution(TidbEntity):
    """A persisted validation execution."""

    validation_id: str
    plan_id: str = ""
    hypothesis_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    tool_id: str = ""
    execution_id: str = ""
    status: str = "pending"
    phase: str = "scope_validation"
    phases_completed: list[str] = field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int = 0
    correlation_id: str = ""
    analysis_version: str = "1.0.0"


@dataclass(slots=True)
class ValidationEvidence(TidbEntity):
    """A persisted provenance-backed validation evidence fragment."""

    evidence_id: str
    validation_id: str = ""
    hypothesis_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    tool_id: str = ""
    tool_version: str = ""
    request_metadata: dict[str, object] = field(default_factory=dict)
    timestamp: str = ""
    input_hash: str = ""
    output_hash: str = ""
    observation: dict[str, object] | None = None
    relevant_response: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    comparison: str = "no_comparison"
    confidence: float = 1.0
    provenance: dict[str, object] = field(default_factory=dict)
    integrity: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ValidationVerdict(TidbEntity):
    """A persisted validation verdict."""

    verdict_id: str
    validation_id: str = ""
    hypothesis_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    result: str = "inconclusive"
    reason: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    rule_ids: list[str] = field(default_factory=list)
    analysis_version: str = "1.0.0"


@dataclass(slots=True)
class ValidationHistory(TidbEntity):
    """A persisted per-target/hypothesis validation history entry.

    First/last-seen tracking uses the envelope ``first_seen``/``last_seen``
    columns (the state-time envelope fields of :class:`TidbEntity`).
    """

    history_id: str
    target_id: str = ""
    asset_id: str = ""
    hypothesis_id: str = ""
    vulnerability_id: str = ""
    state: str = "unknown"
    verdicts: list[str] = field(default_factory=list)
    confirmed: bool = False
    risk_history: list[dict[str, object]] = field(default_factory=list)


@dataclass(slots=True)
class ValidationDifferential(TidbEntity):
    """A persisted temporal validation differential."""

    differential_id: str
    target_id: str = ""
    asset_id: str = ""
    hypothesis_id: str = ""
    vulnerability_id: str = ""
    current_mission_id: str = ""
    previous_mission_id: str = ""
    changes: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ValidationToolUsage(TidbEntity):
    """A persisted tool-usage observability record."""

    usage_id: str
    mission_id: str = ""
    target_id: str = ""
    tool_id: str = ""
    requests: int = 0
    failures: int = 0
    retries: int = 0
    rate_limited: int = 0
    blocked: int = 0
    total_duration_ms: int = 0


@dataclass(slots=True)
class ValidationPolicyDecision(TidbEntity):
    """A persisted gate decision before a validation action."""

    decision_id: str
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    validation_id: str = ""
    kind: str = "scope"
    allowed: bool = False
    reason: str = ""
    detail: dict[str, object] = field(default_factory=dict)
