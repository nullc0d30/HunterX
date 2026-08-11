# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB vulnerability-finding-orchestration entities.

System-of-record tables for the Sprint 028 autonomous vulnerability validation
& proof orchestration capability: the canonical finding record, evidence
requirements and gaps, validation attempts, PoC artifacts and replay records,
impact and confidence assessments, evidence conflicts, deduplication decisions,
root-cause records, unknown-behavior profiles, reproduction data,
report-readiness checklists, state transitions and consolidated report
packages.

Security boundary: these tables store canonical findings, redacted evidence
and lifecycle metadata only — never exploit payloads, never credentials,
never out-of-scope request material.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class FindingRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingRecord`."""

    __tablename__ = "tidb_finding_records"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    asset_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown_behavior", index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate", index=True)
    affected_assets: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    affected_endpoints: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    affected_parameters: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    validation_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    proof_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    impact_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reproduction_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    provenance: Mapped[str] = mapped_column(Text, nullable=False, default="")
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    __table_args__ = (
        Index("ix_tidb_finding_records_mission_status", "mission_id", "status"),
        Index("ix_tidb_finding_records_target_class", "target_id", "vulnerability_class"),
    )


class FindingEvidenceRequirementModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingEvidenceRequirement`."""

    __tablename__ = "tidb_finding_evidence_requirements"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, default="validation", index=True)
    required_kinds: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    present_kinds: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    missing_kinds: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradictory_kinds: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    sufficiency: Mapped[str] = mapped_column(String(32), nullable=False, default="insufficient", index=True)
    assessed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    __table_args__ = (
        Index("ix_tidb_finding_evidence_reqs_finding_purpose", "finding_id", "purpose"),
    )


class FindingEvidenceGapModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingEvidenceGap`."""

    __tablename__ = "tidb_finding_evidence_gaps"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, default="validation", index=True)
    requirement_kind: Mapped[str] = mapped_column(String(64), nullable=False, default="behavioral_differential")
    gap_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="missing", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class FindingValidationAttemptModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingValidationAttempt`."""

    __tablename__ = "tidb_finding_validation_attempts"

    validation_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    strategy_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    raw_output_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    executed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingPoCModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingPoC`."""

    __tablename__ = "tidb_finding_pocs"

    poc_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(64), nullable=False, default="http_request")
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False, default="generated", index=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deterministic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    scope_bound: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    minimal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    __table_args__ = (
        Index("ix_tidb_finding_pocs_finding_state", "finding_id", "lifecycle_state"),
    )


class FindingReplayRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingReplayRecord`."""

    __tablename__ = "tidb_finding_replay_records"

    replay_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    poc_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    scope_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hypothesis_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    behavior: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_class: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="not_reproducible", index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    captured_evidence_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    replayed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingImpactAssessmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingImpactAssessment`."""

    __tablename__ = "tidb_finding_impact_assessments"

    assessment_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    dimensions: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_refs: Mapped[dict[str, list[str]]] = mapped_column(JSON, nullable=False, default=dict)
    reasoning: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    assessed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingConfidenceAssessmentModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingConfidenceAssessment`."""

    __tablename__ = "tidb_finding_confidence_assessments"

    assessment_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="low", index=True)
    factors: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    calculated_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingConflictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingConflict`."""

    __tablename__ = "tidb_finding_conflicts"

    conflict_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    evidence_a: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    evidence_b: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="contradictory_evidence", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    resolution: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    resolution_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    observed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingDedupDecisionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingDedupDecision`."""

    __tablename__ = "tidb_finding_dedup_decisions"

    decision_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    matched_finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    relation: Mapped[str] = mapped_column(String(48), nullable=False, default="independent_finding", index=True)
    key: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    decided_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingRootCauseModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingRootCause`."""

    __tablename__ = "tidb_finding_root_causes"

    root_cause_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    related_finding_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    affected_assets: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class FindingUnknownBehaviorModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingUnknownBehavior`."""

    __tablename__ = "tidb_finding_unknown_behaviors"

    profile_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    hypotheses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="unresolved", index=True)
    security_relevance: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    classification_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")


class FindingReproductionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingReproduction`."""

    __tablename__ = "tidb_finding_reproductions"

    reproduction_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    request: Mapped[str] = mapped_column(Text, nullable=False, default="")
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    headers: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    cookies: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    parameters: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    payload_reference: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    environment: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    response_characteristics: Mapped[str] = mapped_column(Text, nullable=False, default="")
    timing: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    callback_evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expected_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    actual_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class FindingReportChecklistModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingReportChecklist`."""

    __tablename__ = "tidb_finding_report_checklists"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    checks: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reportable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    assessed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingStateTransitionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingStateTransition`."""

    __tablename__ = "tidb_finding_state_transitions_v2"

    transition_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    to_state: Mapped[str] = mapped_column(String(32), nullable=False, default="", index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    missing_purposes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    transitioned_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class FindingPackageRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.finding_orchestration.FindingPackageRecord`."""

    __tablename__ = "tidb_finding_package_records"

    package_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_state: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate", index=True)
    package_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    checklist_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
