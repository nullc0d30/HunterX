# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for Autonomous Mission Orchestration TIDB entities.

Sprint 032. Mirrors ``hunterx.domain.entities.tidb.mission_orchestration``
one-to-one. Indexes cover the canonical query paths: mission scoping, runs,
hypotheses, decisions, coverage and timeline lookups.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class MissionOrchestrationRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionOrchestrationRecord`."""

    __tablename__ = "tidb_mission_orchestrations"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    objective: Mapped[str] = mapped_column(String(64), nullable=False, default="full_security_assessment", index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="balanced")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="created", index=True)
    strategy: Mapped[str] = mapped_column(String(32), nullable=False, default="adaptive")
    current_phase: Mapped[str] = mapped_column(String(64), nullable=False, default="target_modeling")
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    authorization_context: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    policy: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    budget: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    coverage_ratio: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    outcome: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)


class MissionRunRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionRunRecord`."""

    __tablename__ = "tidb_mission_runs"

    run_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    finished_at: Mapped[str] = mapped_column(String(32), nullable=True)
    resumed_from_run_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    checkpoint_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    last_action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")


class MissionPhaseLogRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionPhaseLogRecord`."""

    __tablename__ = "tidb_mission_phases"

    phase_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    phase: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str] = mapped_column(String(32), nullable=True)
    detail: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class MissionActionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionActionRecord`."""

    __tablename__ = "tidb_mission_actions"

    action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    asset_key: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed")
    started_at: Mapped[str] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str] = mapped_column(String(32), nullable=True)
    result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_mission_actions_mission_status", "mission_id", "status"),
    )


class MissionDecisionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionDecisionRecord`."""

    __tablename__ = "tidb_mission_decisions"

    decision_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    next_action: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expected_result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    dependencies: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    alternatives: Mapped[list[list[str]]] = mapped_column(JSON, nullable=False, default=list)
    information_gain: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    factors: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    ai_assisted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class MissionHypothesisRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionHypothesisRecord`."""

    __tablename__ = "tidb_mission_hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown_behavior")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed", index=True)
    behavior_class: Mapped[str] = mapped_column(String(32), nullable=False, default="novel_candidate")
    supporting_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradicting_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tested_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.5, index=True)
    validation_strategy: Mapped[str] = mapped_column(Text, nullable=False, default="")
    proof_strategy: Mapped[str] = mapped_column(Text, nullable=False, default="")
    proposed_by: Mapped[str] = mapped_column(String(64), nullable=False, default="orchestrator")
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class MissionBranchRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionBranchRecord`."""

    __tablename__ = "tidb_mission_branches"

    branch_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    parent_branch_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    outcome: Mapped[str] = mapped_column(Text, nullable=False, default="")


class MissionCheckpointRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionCheckpointRecord`."""

    __tablename__ = "tidb_mission_checkpoints"

    checkpoint_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    label: Mapped[str] = mapped_column(Text, nullable=False, default="")
    snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    created_at_iso: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class MissionPolicyRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionPolicyRecord`."""

    __tablename__ = "tidb_mission_policies"

    policy_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    objective_name: Mapped[str] = mapped_column(String(64), nullable=False, default="full_security_assessment")
    strategy: Mapped[str] = mapped_column(String(32), nullable=False, default="adaptive")
    allowed_techniques: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    resource_budget: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    time_budget_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    validation_depth: Mapped[str] = mapped_column(String(32), nullable=False, default="proof")
    proof_depth: Mapped[str] = mapped_column(String(32), nullable=False, default="minimal")
    coverage_target: Mapped[float] = mapped_column(Float, nullable=False, default=0.7)
    stop_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    max_concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class MissionObjectiveRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionObjectiveRecord`."""

    __tablename__ = "tidb_mission_objectives"

    record_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    objective: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="remaining")
    completed_at: Mapped[str] = mapped_column(String(32), nullable=True)


class MissionCoverageRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionCoverageRecord`."""

    __tablename__ = "tidb_mission_coverage"

    cell_key: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(Text, nullable=False, default="")
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="not_assessed")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tested_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_tidb_mission_coverage_mission_cap", "mission_id", "capability"),
    )


class MissionTimelineRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionTimelineRecord`."""

    __tablename__ = "tidb_mission_timelines"

    entry_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    occurred_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class MissionObservationRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionObservationRecord`."""

    __tablename__ = "tidb_mission_observations"

    observation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    asset_key: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    content: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_ref: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class MissionNegativeRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionNegativeRecord`."""

    __tablename__ = "tidb_mission_negative"

    record_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="tested")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    outcome: Mapped[str] = mapped_column(Text, nullable=False, default="")
    conditions: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")


class MissionBaselineRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionBaselineRecord`."""

    __tablename__ = "tidb_mission_baselines"

    baseline_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    request_fingerprint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    headers: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    content_length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    body_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    timing_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class MissionReasoningRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionReasoningRecord`."""

    __tablename__ = "tidb_mission_reasoning"

    entry_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="observation", index=True)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    content: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    parent_entry_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    occurred_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class MissionTelemetryRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionTelemetryRecord`."""

    __tablename__ = "tidb_mission_telemetry"

    snapshot_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    recorded_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class MissionImpactRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`MissionImpactRecord`."""

    __tablename__ = "tidb_mission_impact"

    impact_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    impact: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    analyzed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
