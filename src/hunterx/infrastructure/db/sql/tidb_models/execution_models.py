# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB execution-layer entities (executions, checkpoints)."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class ExecutionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.execution.Execution`."""

    __tablename__ = "tidb_executions"

    execution_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    mission_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    plan_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    tool_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    profile: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    failure_kind: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class ExecutionStepModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.execution.ExecutionStep`."""

    __tablename__ = "tidb_execution_steps"

    execution_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tidb_executions.execution_id"), nullable=False, index=True
    )
    step_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detail: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class ExecutionEventModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.execution.ExecutionEvent`."""

    __tablename__ = "tidb_execution_events"

    execution_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tidb_executions.execution_id"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="execution")
    occurred_at: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)


class ExecutionLogModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.execution.ExecutionLog`."""

    __tablename__ = "tidb_execution_logs"

    execution_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tidb_executions.execution_id"), nullable=False, index=True
    )
    stream: Mapped[str] = mapped_column(String(16), nullable=False, default="log")
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    context: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ToolExecutionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.execution.ToolExecution`."""

    __tablename__ = "tidb_tool_executions"

    execution_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tidb_executions.execution_id"), nullable=False, index=True
    )
    tool_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    exit_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stdout: Mapped[str] = mapped_column(Text, nullable=False, default="")
    stderr: Mapped[str] = mapped_column(Text, nullable=False, default="")
    output_files: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    normalized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class MissionExecutionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.execution.MissionExecution`."""

    __tablename__ = "tidb_mission_executions"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    plan_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="created", index=True)
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    started_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class CheckpointRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.execution.CheckpointRecord`."""

    __tablename__ = "tidb_checkpoint_records"

    checkpoint_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    rerun_from: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_tidb_checkpoint_records_plan_mission", "plan_id", "mission_id"),
    )
