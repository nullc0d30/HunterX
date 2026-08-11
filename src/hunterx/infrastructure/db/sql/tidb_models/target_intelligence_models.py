# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for Adaptive Target Intelligence TIDB entities.

Sprint 026. Mirrors ``hunterx.domain.entities.tidb.target_intelligence``
one-to-one. Indexes cover the canonical query paths: target scoping, asset
keys, capabilities, states and dedup keys — so thousands of assets and millions
of observations stay queryable without full scans.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class IntelligenceTargetRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceTargetRecord`."""

    __tablename__ = "tidb_intelligence_targets"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    identity: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    classification: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    criticality: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="domain", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    phase: Mapped[str] = mapped_column(String(32), nullable=False, default="discovery", index=True)
    intelligence_state: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    coverage_state: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_intel_target_scope", "tenant", "mission_id", "target_id"),
    )


class IntelligenceAssetRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceAssetRecord`."""

    __tablename__ = "tidb_intelligence_assets"

    asset_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="asset", index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    label: Mapped[str] = mapped_column(Text, nullable=False, default="")
    properties: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    parent_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    observed_by: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    __table_args__ = (
        Index("ix_tidb_intel_asset_target_key", "target_id", "asset_key"),
    )


class ObservationRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`ObservationRecord`."""

    __tablename__ = "tidb_intelligence_observations"

    observation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    timestamp: Mapped[str] = mapped_column(String(32), nullable=False, default="", index=True)
    observation_type: Mapped[str] = mapped_column(String(32), nullable=False, default="other", index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    provenance: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    raw_artifact_ref: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    evidence_ref: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    dedup_key: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    supersedes: Mapped[str] = mapped_column(String(26), nullable=False, default="")

    __table_args__ = (
        Index("ix_tidb_intel_obs_target_type", "target_id", "observation_type"),
        Index("ix_tidb_intel_obs_asset_type", "asset_key", "observation_type"),
    )


class IntelligenceEvidenceRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceEvidenceRecord`."""

    __tablename__ = "tidb_intelligence_evidence"

    evidence_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    what: Mapped[str] = mapped_column(Text, nullable=False, default="")
    where: Mapped[str] = mapped_column(Text, nullable=False, default="")
    when: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    how: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    why_trust: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reproducibility: Mapped[str] = mapped_column(String(32), nullable=False, default="not_assessed")
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    command_configuration: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    raw_artifact_ref: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    normalizer_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class TargetHistoryRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`TargetHistoryRecord`."""

    __tablename__ = "tidb_intelligence_history"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    field: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="new", index=True)
    previous_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    new_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    changed_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class IntelligenceChangeRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceChangeRecord`."""

    __tablename__ = "tidb_intelligence_changes"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="new", index=True)
    previous: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    current: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    detected_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class CoverageRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`CoverageRecord`."""

    __tablename__ = "tidb_intelligence_coverage"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="not_assessed", index=True)
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tested_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_tidb_intel_coverage_cell", "target_id", "asset_key", "capability"),
    )


class InformationGapRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`InformationGapRecord`."""

    __tablename__ = "tidb_intelligence_gaps"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="asset_discovery", index=True)
    question: Mapped[str] = mapped_column(Text, nullable=False, default="")
    importance: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    required_capability: Mapped[str] = mapped_column(String(64), nullable=False, default="asset_discovery")
    candidate_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    estimated_cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")
    blocking: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class HypothesisRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`HypothesisRecord`."""

    __tablename__ = "tidb_intelligence_hypotheses"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    category: Mapped[str] = mapped_column(String(48), nullable=False, default="unknown_behavior", index=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False, default="")
    supporting_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradicting_observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    validation_strategy: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    proof_strategy: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed", index=True)


class IntelligenceActionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceActionRecord`."""

    __tablename__ = "tidb_intelligence_actions"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    objective: Mapped[str] = mapped_column(Text, nullable=False, default="")
    action_type: Mapped[str] = mapped_column(String(32), nullable=False, default="discover", index=True)
    required_capability: Mapped[str] = mapped_column(String(64), nullable=False, default="asset_discovery")
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expected_information_gain: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    expected_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    estimated_cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")
    scope_status: Mapped[str] = mapped_column(String(32), nullable=False, default="in_scope")
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    stop_conditions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    fallback: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed", index=True)
    decision_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    candidates: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class IntelligenceDecisionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceDecisionRecord`."""

    __tablename__ = "tidb_intelligence_decisions"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="next-action", index=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    rationale: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    alternatives: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    why_alternatives_rejected: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    policy_applied: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    ai_assisted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ai_overridden: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class NegativeResultRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`NegativeResultRecord`."""

    __tablename__ = "tidb_intelligence_negatives"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    tested_capability: Mapped[str] = mapped_column(String(64), nullable=False, default="vulnerability_scanning")
    tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    scope: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    conditions: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    coverage: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result: Mapped[str] = mapped_column(String(32), nullable=False, default="no_evidence")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    tested_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class IntelligenceConflictRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceConflictRecord`."""

    __tablename__ = "tidb_intelligence_conflicts"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    asset_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="vulnerability_scanning")
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open", index=True)
    resolution: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detected_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    resolved_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class IntelligenceScoreRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`IntelligenceScoreRecord`."""

    __tablename__ = "tidb_intelligence_scores"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    dimensions: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    aggregate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    weights: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False, default="target-intelligence/ranking/1.0.0")
