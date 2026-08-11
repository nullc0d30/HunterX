# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB vulnerability-validation entities.

System-of-record tables for the Wave 13 safe vulnerability discovery &
validation capability: vulnerability hypotheses, validation rules, validation
plans and steps, validation executions, provenance-backed validation evidence,
verdicts, per-target validation history, temporal differentials, tool-usage
observability and gate policy decisions.

Security boundary: these tables store safe-validation metadata, canonical
observations and redacted evidence only — never exploit payloads, never
credentials, never out-of-scope request material.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class VulnerabilityHypothesisModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.VulnerabilityHypothesis`."""

    __tablename__ = "tidb_vulnerability_hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    technology_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    class_name: Mapped[str] = mapped_column(String(64), nullable=False, default="known_vulnerable_software", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    unexpected_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")
    validation_strategy: Mapped[str] = mapped_column(String(64), nullable=False, default="version_validation")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="suspected", index=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="vulnerability.validation")
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    __table_args__ = (
        Index("ix_tidb_vuln_hypotheses_asset_vuln", "asset_id", "vulnerability_id"),
    )


class ValidationRuleModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationRule`."""

    __tablename__ = "tidb_validation_rules"

    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="known_vulnerable_software", index=True)
    strategy: Mapped[str] = mapped_column(String(64), nullable=False, default="version_validation")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    minimum_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    permits_confirmation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confirmation_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    safe_checks: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    forbidden_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    unexpected_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    inconclusive_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    false_positive_rules: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    scope_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class ValidationPlanModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationPlan`."""

    __tablename__ = "tidb_validation_plans"

    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    strategy: Mapped[str] = mapped_column(String(64), nullable=False, default="version_validation")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="planned", index=True)
    dependencies: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    safety_policy: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    timeout: Mapped[float] = mapped_column(Float, nullable=False, default=120.0)
    retry_policy: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    rate_limit: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    expected_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    stop_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    abort_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class ValidationStepModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationStep`."""

    __tablename__ = "tidb_validation_steps"

    step_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    action: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    strategy: Mapped[str] = mapped_column(String(64), nullable=False, default="version_validation")
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    expected_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    stop_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    abort_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    timeout: Mapped[float] = mapped_column(Float, nullable=False, default=30.0)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rate_limit: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")


class ValidationExecutionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationExecution`."""

    __tablename__ = "tidb_validation_executions"

    validation_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    phase: Mapped[str] = mapped_column(String(64), nullable=False, default="scope_validation")
    phases_completed: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    __table_args__ = (
        Index("ix_tidb_validation_execs_hypothesis", "hypothesis_id", "validation_id"),
    )


class ValidationEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationEvidence`."""

    __tablename__ = "tidb_validation_evidence"

    evidence_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    validation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    request_metadata: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    timestamp: Mapped[str] = mapped_column(String(32), nullable=False, default="", index=True)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    output_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    observation: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    relevant_response: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    observed_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    comparison: Mapped[str] = mapped_column(String(32), nullable=False, default="no_comparison")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    integrity: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    __table_args__ = (
        Index("ix_tidb_validation_evidence_hypothesis", "hypothesis_id", "validation_id"),
    )


class ValidationVerdictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationVerdict`."""

    __tablename__ = "tidb_validation_verdicts"

    verdict_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    validation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    result: Mapped[str] = mapped_column(String(32), nullable=False, default="inconclusive", index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    __table_args__ = (
        Index("ix_tidb_validation_verdicts_hypothesis", "hypothesis_id", "validation_id"),
    )


class ValidationHistoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationHistory`."""

    __tablename__ = "tidb_validation_history"

    history_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown", index=True)
    verdicts: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    risk_history: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    __table_args__ = (
        Index("ix_tidb_validation_history_target_hyp", "target_id", "hypothesis_id"),
    )


class ValidationDifferentialModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationDifferential`."""

    __tablename__ = "tidb_validation_differentials"

    differential_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    current_mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    previous_mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    changes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    details: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class ValidationToolUsageModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationToolUsage`."""

    __tablename__ = "tidb_validation_tool_usage"

    usage_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    requests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rate_limited: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ValidationPolicyDecisionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.validation.ValidationPolicyDecision`."""

    __tablename__ = "tidb_validation_policy_decisions"

    decision_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    validation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="scope", index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    detail: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
