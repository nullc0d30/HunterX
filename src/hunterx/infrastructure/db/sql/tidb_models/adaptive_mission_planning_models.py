# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for Adaptive Mission & Attack-Path Planning TIDB entities.

Sprint 027. Mirrors ``hunterx.domain.entities.tidb.adaptive_mission_planning``
one-to-one. Indexes cover the canonical query paths: mission scoping, action
ids, plan versions and states — so thousands of actions and large plan
histories stay queryable without full scans.
"""

from __future__ import annotations

from sqlalchemy import JSON, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class AdaptiveMissionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveMissionRecord`."""

    __tablename__ = "tidb_adaptive_missions"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    objective: Mapped[str] = mapped_column(String(64), nullable=False, default="attack_surface_discovery")
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="balanced")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="created", index=True)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    authorization_context: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    safety_ceiling: Mapped[str] = mapped_column(String(64), nullable=False, default="low_impact_active")
    tenant: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_tidb_adaptive_mission_scope", "tenant", "mission_id"),
    )


class AdaptiveActionNodeRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveActionNodeRecord`."""

    __tablename__ = "tidb_adaptive_action_nodes"

    action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, default="discover_endpoints")
    asset: Mapped[str] = mapped_column(Text, nullable=False, default="")
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    selected_tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    tool_candidates: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    hypothesis_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    expected_information_gain: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    expected_proof_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    validation_level: Mapped[str] = mapped_column(String(32), nullable=False, default="discovery")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed", index=True)
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=100.0)
    depends_on: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_adaptive_action_mission_status", "mission_id", "status"),
        Index("ix_tidb_adaptive_action_mission_cap", "mission_id", "capability"),
    )


class AdaptiveDependencyRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveDependencyRecord`."""

    __tablename__ = "tidb_adaptive_dependencies"

    dependency_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    source_action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="depends_on")
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_tidb_adaptive_dep_mission_src", "mission_id", "source_action_id"),
    )


class AdaptiveBranchRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveBranchRecord`."""

    __tablename__ = "tidb_adaptive_branches"

    branch_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="if")
    condition: Mapped[str] = mapped_column(Text, nullable=False, default="")
    then_action_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    else_action_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    goto_action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    wait_for_evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")


class AdaptivePlanVersionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptivePlanVersionRecord`."""

    __tablename__ = "tidb_adaptive_plan_versions"

    version_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    parent_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    trigger: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    changed_nodes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    changed_dependencies: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="planner")
    decision_provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_adaptive_version_mission_version", "mission_id", "plan_version"),
    )


class AdaptivePlanDeltaRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptivePlanDeltaRecord`."""

    __tablename__ = "tidb_adaptive_plan_deltas"

    delta_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    parent_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    trigger: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    changes: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    decision_provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_adaptive_delta_mission_version", "mission_id", "plan_version"),
    )


class AdaptiveDecisionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveDecisionRecord`."""

    __tablename__ = "tidb_adaptive_decisions"

    decision_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    why_this_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    why_now: Mapped[str] = mapped_column(Text, nullable=False, default="")
    why_this_tool: Mapped[str] = mapped_column(Text, nullable=False, default="")
    information_provided: Mapped[str] = mapped_column(Text, nullable=False, default="")
    hypothesis_tested: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    evidence_expected: Mapped[str] = mapped_column(Text, nullable=False, default="")
    proof_enabled: Mapped[str] = mapped_column(Text, nullable=False, default="")
    alternatives: Mapped[list[list[str]]] = mapped_column(JSON, nullable=False, default=list)
    decision_provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class AdaptiveAttackPathRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveAttackPathRecord`."""

    __tablename__ = "tidb_adaptive_attack_paths"

    path_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    objective: Mapped[str] = mapped_column(String(64), nullable=False, default="attack_surface_discovery")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="hypothetical", index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    scores: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False, default=dict)
    steps: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    assumptions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class AdaptiveGapRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveGapRecord`."""

    __tablename__ = "tidb_adaptive_gaps"

    gap_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="evidence_gap")
    asset_key: Mapped[str] = mapped_column(Text, nullable=False, default="")
    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    minimum_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priority: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class AdaptivePlanCheckpointRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptivePlanCheckpointRecord`."""

    __tablename__ = "tidb_adaptive_checkpoints"

    checkpoint_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    mission_state: Mapped[str] = mapped_column(String(32), nullable=False, default="created")
    completed_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    pending_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    observations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    hypotheses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    proof_states: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    tool_state: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class AdaptiveFailureRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveFailureRecord`."""

    __tablename__ = "tidb_adaptive_failures"

    failure_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    failure_class: Mapped[str] = mapped_column(String(32), nullable=False, default="tool_error")
    management: Mapped[str] = mapped_column(String(32), nullable=False, default="retry")
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    retries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AdaptiveToolFallbackRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveToolFallbackRecord`."""

    __tablename__ = "tidb_adaptive_tool_fallbacks"

    fallback_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    primary_tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    fallback_tool: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")


class AdaptiveToolSelectionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`AdaptiveToolSelectionRecord`."""

    __tablename__ = "tidb_adaptive_tool_selections"

    selection_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    action_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    alternatives: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expected_proof_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cost: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
