# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB vulnerability-proof entities.

System-of-record tables for the Wave 15 vulnerability proof & PoC capability:
vulnerability proofs, proof contracts, proof plans and steps, proof executions,
structured PoCs, replays, proof-linked evidence, proof gate decisions, impact
assessments, confidence assessments, proof quality, finding lifecycle
transitions and temporal proof history.

Security boundary: these tables store safe-proof metadata, canonical observations
and redacted evidence only — never exploit payloads, never credentials, never
unrestricted executable PoC scripts and never out-of-scope request material.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class VulnerabilityProofModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.VulnerabilityProof`."""

    __tablename__ = "tidb_vulnerability_proofs"

    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    validation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    proof_type: Mapped[str] = mapped_column(String(64), nullable=False, default="behavioral_proof", index=True)
    proof_strategy: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    proof_status: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate", index=True)
    reproducibility_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_assessed")
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False, default="controlled")
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    steps: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    inputs: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    observed_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    impact_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    replay_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful_replays: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_replays: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    validated_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    proof_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="vulnerability.proof")
    __table_args__ = (
        Index("ix_tidb_proofs_hypothesis_proof", "hypothesis_id", "proof_id"),
    )


class ProofContractModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofContract`."""

    __tablename__ = "tidb_proof_contracts"

    contract_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="sql_injection", index=True)
    proof_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    poc_formats: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    forbidden_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    failure_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    inconclusive_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    replay_requirements: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    impact_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    minimum_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.6)
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False, default="controlled")
    scope_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    permits_confirmation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reportable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    contract_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")


class ProofPlanModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofPlan`."""

    __tablename__ = "tidb_proof_plans"

    proof_plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    safety_policy: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    expected_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    stop_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    abort_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    replay_requirements: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    impact_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)


class ProofStepModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofStep`."""

    __tablename__ = "tidb_proof_steps"

    step_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    action: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    expected_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    timeout: Mapped[float] = mapped_column(Float, nullable=False, default=30.0)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rate_limit: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False, default="controlled")


class ProofExecutionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofExecution`."""

    __tablename__ = "tidb_proof_executions"

    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    sdk_execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    phase: Mapped[str] = mapped_column(String(64), nullable=False, default="scope_validation")
    phases_completed: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")


class ProofOfConceptModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofOfConcept`."""

    __tablename__ = "tidb_proofs_of_concept"

    poc_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    format: Mapped[str] = mapped_column(String(64), nullable=False, default="request_response", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    steps: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    inputs: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    expected_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    observed_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    replay_policy: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    safety_policy: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    poc_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    parent_version: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    changes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate", index=True)
    validated_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ProofReplayModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofReplay`."""

    __tablename__ = "tidb_proof_replays"

    replay_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    poc_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    poc_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    proof_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    target_state: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    configuration_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    observed_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result: Mapped[str] = mapped_column(String(32), nullable=False, default="not_run", index=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="inconclusive")
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    __table_args__ = (
        Index("ix_tidb_proof_replays_proof_poc", "proof_id", "poc_id"),
    )


class ProofEvidenceModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofEvidence`."""

    __tablename__ = "tidb_proof_evidence"

    link_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    replay_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    evidence_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="proof")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="external", index=True)
    __table_args__ = (
        Index("ix_tidb_proof_evidence_proof_ev", "proof_id", "evidence_id"),
    )


class ProofPolicyDecisionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofPolicyDecision`."""

    __tablename__ = "tidb_proof_policy_decisions"

    decision_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="scope", index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    detail: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class ProofConfidenceAssessmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofConfidenceAssessment`."""

    __tablename__ = "tidb_proof_confidence_assessments"

    confidence_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="low", index=True)
    factor_scores: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    weights: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    confidence_policy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="confidence-policy/1.0.0")
    calculation_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class ProofImpactAssessmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofImpactAssessment`."""

    __tablename__ = "tidb_proof_impact_assessments"

    impact_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    impact_type: Mapped[str] = mapped_column(String(64), nullable=False, default="confidentiality", index=True)
    impact_level: Mapped[str] = mapped_column(String(16), nullable=False, default="none")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    assessment_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")


class ProofQualityModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofQuality`."""

    __tablename__ = "tidb_proof_quality"

    quality_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    factors: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")


class ProofFindingStateTransitionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofFindingStateTransition`."""

    __tablename__ = "tidb_finding_state_transitions"

    transition_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False, default="detected", index=True)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False, default="detected", index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class ProofHistoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof.ProofHistory`."""

    __tablename__ = "tidb_proof_history"

    history_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate", index=True)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    __table_args__ = (
        Index("ix_tidb_proof_history_proof_ts", "proof_id", "created_at"),
    )
