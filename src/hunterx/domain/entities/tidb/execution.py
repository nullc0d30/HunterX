# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution-layer Target Intelligence Database entities.

Persistent records of tool and mission executions. These are the durable
side of the runtime execution models in ``hunterx.domain.execution`` and
``hunterx.domain.mission_planning``: every pipeline run and mission attempt
is recorded here for audit, analytics and replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class Execution(TidbEntity):
    """A durable record of a single tool/plugin execution.

    Attributes:
        execution_id: stable execution identifier (matches ExecutionContext).
        mission_id: owning mission.
        plan_id: owning plan.
        tool_id: the executed tool.
        target: target identifier.
        target_type: canonical target kind.
        profile: mission profile name.
        status: lifecycle status (matches ExecutionStatus).
        failure_kind: failure classification.
        retry_count: retries performed.
        duration_ms: elapsed execution time.
        started_at / completed_at: UTC ISO-8601 timestamps.
        parameters: execution parameters snapshot.
        correlation_id: correlation identifier for a batch/mission.

    """

    execution_id: str
    mission_id: str | None = None
    plan_id: str | None = None
    tool_id: str = ""
    target: str = ""
    target_type: str = ""
    profile: str = ""
    status: str = "pending"
    failure_kind: str | None = None
    retry_count: int = 0
    duration_ms: int = 0
    started_at: str | None = None
    completed_at: str | None = None
    parameters: dict[str, object] = field(default_factory=dict)
    correlation_id: str | None = None


@dataclass(slots=True)
class ExecutionStep(TidbEntity):
    """A step within an execution pipeline.

    Attributes:
        execution_id: owning execution.
        step_index: position within the pipeline.
        name: step name (e.g. ``collecting``, ``validating``).
        status: step status.
        duration_ms: step duration.
        detail: step detail map.

    """

    execution_id: str
    step_index: int = 0
    name: str = ""
    status: str = "pending"
    duration_ms: int = 0
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ExecutionEvent(TidbEntity):
    """An event emitted during an execution lifecycle.

    Attributes:
        execution_id: owning execution.
        event_type: stable event name (e.g. ``execution.started``).
        payload: JSON-safe event data.
        source: originating component.
        occurred_at: UTC ISO-8601 timestamp.

    """

    execution_id: str
    event_type: str = ""
    payload: dict[str, object] = field(default_factory=dict)
    source: str = "execution"
    occurred_at: str | None = None


@dataclass(slots=True)
class ExecutionLog(TidbEntity):
    """A log line captured during an execution.

    Attributes:
        execution_id: owning execution.
        stream: ``stdout``, ``stderr`` or ``log``.
        level: log level (debug, info, warning, error).
        message: log message.
        context: structured context map.
        line_number: source line number when applicable.

    """

    execution_id: str
    stream: str = "log"
    level: str = "info"
    message: str = ""
    context: dict[str, object] = field(default_factory=dict)
    line_number: int | None = None


@dataclass(slots=True)
class ToolExecution(TidbEntity):
    """Result envelope of a completed tool execution.

    Bridges the durable ``Execution`` record with the outcome data produced by
    ``hunterx.domain.execution.ExecutionResult``.

    Attributes:
        execution_id: owning execution.
        tool_id: executed tool.
        status: terminal status.
        exit_code: process exit code.
        stdout: truncated standard output.
        stderr: truncated standard error.
        output_files: artifact paths produced.
        error: error message on failure.
        normalized: whether output normalization succeeded.
        stored: whether results were persisted.

    """

    execution_id: str
    tool_id: str = ""
    status: str = "pending"
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    output_files: list[str] = field(default_factory=list)
    error: str = ""
    normalized: bool = False
    stored: bool = False


@dataclass(slots=True)
class MissionExecution(TidbEntity):
    """A durable record of a mission's run.

    Attributes:
        mission_id: owning mission.
        plan_id: owning plan.
        status: mission lifecycle status (matches MissionPlanningStatus).
        progress: completion percentage in ``[0, 100]``.
        started_at / completed_at: UTC ISO-8601 timestamps.
        summary: run summary map.

    """

    mission_id: str
    plan_id: str | None = None
    status: str = "created"
    progress: float = 0.0
    started_at: str | None = None
    completed_at: str | None = None
    summary: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class CheckpointRecord(TidbEntity):
    """Durable snapshot of a mission plan checkpoint.

    Attributes:
        checkpoint_id: stable checkpoint identifier (matches Checkpoint).
        plan_id: owning plan.
        mission_id: owning mission.
        label: checkpoint label.
        snapshot: JSON-safe plan state.
        rerun_from: optional step id for partial rerun.

    """

    checkpoint_id: str
    plan_id: str
    mission_id: str
    label: str = ""
    snapshot: dict[str, object] = field(default_factory=dict)
    rerun_from: str | None = None
