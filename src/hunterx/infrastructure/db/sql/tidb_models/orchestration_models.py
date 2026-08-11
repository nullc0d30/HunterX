# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB orchestration entities.

System-of-record tables for the Wave 14 offensive tool orchestration
capability: execution plans, phases, steps, tool selections, execution
dependencies, checkpoints, policy decisions, replans, coverage, quality,
failures and task history.

Security boundary: these tables store orchestration metadata, canonical
targets, tool selections and redacted evidence references only.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class MissionPlanRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionPlanRecord`."""

    __tablename__ = "tidb_mission_plan_records"

    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, unique=True, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    objective: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="planned", index=True)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    policies: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_tidb_mission_plan_records_mission_version", "mission_id", "plan_version"),
    )


class MissionPhaseRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionPhaseRecord`."""

    __tablename__ = "tidb_mission_phase_records"

    phase_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, default="scope", index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    parallel: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    optional: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    depends_on: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    __table_args__ = (
        Index("ix_tidb_mission_phase_records_plan_kind", "plan_id", "kind"),
    )


class MissionStepRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionStepRecord`."""

    __tablename__ = "tidb_mission_step_records"

    step_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    phase_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    capability: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    depends_on: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    condition: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    timeout_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=60.0)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False, default="passive")
    evidence_requirements: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    success_criteria: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    fallback_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ExecutionDependencyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.ExecutionDependency`."""

    __tablename__ = "tidb_execution_dependencies"

    dependency_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    source_step_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_step_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="finish-to-start")

    __table_args__ = (
        Index("ix_tidb_execution_dependencies_plan_target", "plan_id", "target_step_id"),
    )


class ExecutionCheckpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.ExecutionCheckpoint`."""

    __tablename__ = "tidb_execution_checkpoints"

    checkpoint_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    checkpoint_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    state: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    completed_steps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class ExecutionPolicyDecisionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.ExecutionPolicyDecision`."""

    __tablename__ = "tidb_execution_policy_decisions"

    decision_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="scope", index=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class ToolSelectionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.ToolSelectionRecord`."""

    __tablename__ = "tidb_tool_selection_records"

    selection_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    capability: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    alternative_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    fallback_of: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class ToolFallbackModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.ToolFallback`."""

    __tablename__ = "tidb_tool_fallbacks"

    fallback_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    primary_tool: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    fallback_tool: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")


class MissionReplanModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionReplan`."""

    __tablename__ = "tidb_mission_replans"

    replan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    previous_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    new_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    added_steps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    removed_steps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    blocked_assets: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class MissionCoverageModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionCoverage`."""

    __tablename__ = "tidb_mission_coverages"

    coverage_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="asset", index=True)
    observed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    covered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fraction: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    __table_args__ = (
        Index("ix_tidb_mission_coverages_mission_kind", "mission_id", "kind"),
    )


class MissionQualityModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionQuality`."""

    __tablename__ = "tidb_mission_qualities"

    quality_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    factors: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    explainability: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class MissionFailureModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionFailure`."""

    __tablename__ = "tidb_mission_failures"

    failure_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    failure_class: Mapped[str] = mapped_column(String(32), nullable=False, default="permanent", index=True)
    management: Mapped[str] = mapped_column(String(32), nullable=False, default="blocked")
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    retries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class MissionTaskHistoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.orchestration.MissionTaskHistory`."""

    __tablename__ = "tidb_mission_task_history"

    history_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    tool_id: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="completed", index=True)
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
