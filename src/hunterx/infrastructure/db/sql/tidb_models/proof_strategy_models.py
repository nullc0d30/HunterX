# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB proof-strategy entities.

System-of-record tables for the Sprint 022 strategy intelligence layer: proof
strategies and their versions, strategy requirements, evidence rules, tool
requirements, strategy candidates (novel), proof validation results and manual
proof instructions.

Security boundary: these tables store strategy contracts, canonical evidence
rules and validation results — never exploit payloads, never credentials,
never unrestricted executable PoC scripts and never out-of-scope request
material.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class ProofStrategyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofStrategy`."""

    __tablename__ = "tidb_proof_strategies"

    strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown_behavior", index=True)
    security_property: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_inputs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    forbidden_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    optional_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    negative_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    inconclusive_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confirmation_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    replay_requirements: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False, default=dict)
    impact_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    preferred_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    fallback_strategies: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False, default="benign_marker")
    scope_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence_policy: Mapped[str] = mapped_column(String(128), nullable=False, default="evidence-dominated")
    stop_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    abort_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    provenance: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    permits_confirmation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reportable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    execution: Mapped[str] = mapped_column(String(32), nullable=False, default="executable")


class ProofStrategyVersionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofStrategyVersion`."""

    __tablename__ = "tidb_proof_strategy_versions"

    strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown_behavior", index=True)
    strategy_checksum: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    previous_version: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    superseded_by: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    registered_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class ProofStrategyRequirementModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofStrategyRequirement`."""

    __tablename__ = "tidb_proof_strategy_requirements"

    strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    requirement_type: Mapped[str] = mapped_column(String(32), nullable=False, default="precondition", index=True)
    requirement: Mapped[str] = mapped_column(Text, nullable=False, default="")
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ProofStrategyEvidenceRuleModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofStrategyEvidenceRule`."""

    __tablename__ = "tidb_proof_strategy_evidence_rules"

    strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    rule_type: Mapped[str] = mapped_column(String(32), nullable=False, default="minimum_required", index=True)
    evidence_kind: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    confirmation_rule: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ProofStrategyToolRequirementModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofStrategyToolRequirement`."""

    __tablename__ = "tidb_proof_strategy_tool_requirements"

    strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    sdk_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    preferred_tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    optional: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ProofStrategyCandidateModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofStrategyCandidate`."""

    __tablename__ = "tidb_proof_strategy_candidates"

    candidate_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown_behavior", index=True)
    observed_behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    proposed_strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    proposed_strategy: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_findings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed", index=True)
    review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ProofValidationResultModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofValidationResult`."""

    __tablename__ = "tidb_proof_validation_results"

    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="insufficient_evidence", index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    proof_quality_level: Mapped[str] = mapped_column(String(32), nullable=False, default="p0_candidate")
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    present_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    missing_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradictory_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    disqualifying_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope_result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    safety_result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    replay_result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    impact_result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    reproducibility_result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_covered: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_contract_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reasoning: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    validator_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")


class ProofManualInstructionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.proof_strategy.ProofManualInstruction`."""

    __tablename__ = "tidb_proof_manual_instructions"

    instruction_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    proof_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    strategy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    objective: Mapped[str] = mapped_column(Text, nullable=False, default="")
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    steps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_observation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_to_capture: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    safety_notes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    completion_criteria: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
