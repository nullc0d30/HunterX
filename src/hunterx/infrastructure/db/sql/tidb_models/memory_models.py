# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for Target Memory & Campaign Intelligence TIDB entities.

Sprint 030. Mirrors ``hunterx.domain.entities.tidb.memory`` one-to-one.
Indexes cover the canonical query paths: target scoping, campaign scoping,
observation type/state, first/last seen and mission/campaign attribution — so
large historical corpora stay queryable without full scans.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class MemoryObservationRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`MemoryObservationRecord`."""

    __tablename__ = "tidb_memory_observations"

    observation_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    observation_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    first_seen: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    last_seen: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_mission: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    last_mission: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    first_source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    last_source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    current_state: Mapped[str] = mapped_column(String(32), nullable=False, default="known_current", index=True)
    freshness: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source_reliability: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    corroboration_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    contradiction_state: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    validity: Mapped[str] = mapped_column(String(16), nullable=False, default="valid")
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provenance: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_memory_obs_target_type_state", "target_id", "observation_type", "current_state"),
        Index("ix_tidb_memory_obs_target_lastseen", "target_id", "last_seen"),
    )


class TargetSnapshotRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`TargetSnapshotRecord`."""

    __tablename__ = "tidb_target_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    state: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_snapshots_target_created", "target_id", "created_at"),
    )


class TargetDiffRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`TargetDiffRecord`."""

    __tablename__ = "tidb_target_diffs"

    diff_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    snapshot_a_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    snapshot_b_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    state_hash_a: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    state_hash_b: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    changes: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    deterministic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index("ix_tidb_diffs_target_snapshots", "target_id", "snapshot_a_id", "snapshot_b_id"),
    )


class MissionMemoryRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`MissionMemoryRecord`."""

    __tablename__ = "tidb_mission_memories"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    ended_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    tools_used: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    assets_discovered: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    findings_discovered: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    findings_validated: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    pocs_generated: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    hypotheses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    successful_hypotheses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    failed_hypotheses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    blocked_tests: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tool_failures: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    coverage_achieved: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    coverage_gaps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_mission_memories_target", "target_id", "mission_id"),
    )


class HypothesisMemoryRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`HypothesisMemoryRecord`."""

    __tablename__ = "tidb_hypothesis_memories"

    memory_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False, default="")
    hypothesis_type: Mapped[str] = mapped_column(String(48), nullable=False, default="")
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="inconclusive", index=True)
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    evidence_observed: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tested_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    conditions: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    vulnerability_type: Mapped[str] = mapped_column(String(48), nullable=False, default="")
    asset_type: Mapped[str] = mapped_column(String(48), nullable=False, default="")
    technology: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    endpoint_pattern: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    parameter_pattern: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    authentication_context: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    validation_strategy: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    poc_strategy: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    evidence_pattern: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_hyp_memories_target_outcome", "target_id", "outcome"),
    )


class ToolObservationRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`ToolObservationRecord`."""

    __tablename__ = "tidb_tool_observations"

    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    timestamp: Mapped[str] = mapped_column(String(32), nullable=False, default="", index=True)
    normalized_result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    derived_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    provenance: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_tool_obs_target_tool", "target_id", "tool"),
    )


class TargetRiskRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`TargetRiskRecord`."""

    __tablename__ = "tidb_target_risks"

    risk_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    campaign_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="low", index=True)
    previous_risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detected_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    driving_changes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    __table_args__ = (
        Index("ix_tidb_target_risks_target_detected", "target_id", "detected_at"),
    )


class FindingMemoryRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`FindingMemoryRecord`."""

    __tablename__ = "tidb_finding_memories"

    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate", index=True)
    first_detected: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    first_validated: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    last_validated: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    last_observed: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    remediation_state: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    retest_state: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    reopened_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    closed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    affected_assets: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    affected_endpoints: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_finding_memories_target_status", "target_id", "remediation_state"),
    )


class FindingRecurrenceRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`FindingRecurrenceRecord`."""

    __tablename__ = "tidb_finding_recurrences"

    recurrence_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    campaign_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    original_finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    new_finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    previous_location: Mapped[str] = mapped_column(Text, nullable=False, default="")
    new_location: Mapped[str] = mapped_column(Text, nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="new_location", index=True)
    detected_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)


class CampaignRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`CampaignRecord`."""

    __tablename__ = "tidb_campaigns"

    campaign_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    objective: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="planned", index=True)
    target_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    mission_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    ended_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    risk_history: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    findings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    coverage: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    changes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    attack_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_campaigns_tenant_status", "tenant", "status"),
    )


class CoverageGapRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`CoverageGapRecord`."""

    __tablename__ = "tidb_coverage_gaps"

    gap_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    campaign_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="discovered_untested", index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    significance: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    detected_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    resolved_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    candidate_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    __table_args__ = (
        Index("ix_tidb_gaps_target_status", "target_id", "status"),
    )


class RevalidationRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`RevalidationRecord`."""

    __tablename__ = "tidb_revalidations"

    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    observation_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    observation_type: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    freshness: Mapped[str] = mapped_column(String(16), nullable=False, default="stale", index=True)
    last_seen: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        Index("ix_tidb_revalidations_target_status", "target_id", "status"),
    )


class AttackPathMemoryRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`AttackPathMemoryRecord`."""

    __tablename__ = "tidb_attack_path_memories"

    path_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    campaign_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    nodes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    edges: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    first_seen: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    last_seen: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="theoretical", index=True)
    changes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_path_memories_target_status", "target_id", "status"),
    )


class MemoryContradictionRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`MemoryContradictionRecord`."""

    __tablename__ = "tidb_memory_contradictions"

    contradiction_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    observation_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    resolution: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detected_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    resolved_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class NextActionRecordModel(TidbModelMixin, Base):  # type: ignore[misc]
    """ORM view of :class:`NextActionRecord`."""

    __tablename__ = "tidb_next_actions"

    recommendation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    campaign_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False, default="", index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    required_tool_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_required: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_outcome: Mapped[str] = mapped_column(Text, nullable=False, default="")
    historical_context: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
