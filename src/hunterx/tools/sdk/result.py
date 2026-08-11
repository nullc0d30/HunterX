# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution result helpers.

Constructs and mutates :class:`ExecutionResult` objects across the pipeline,
and bridges raw execution output into canonical tool output
(:class:`ToolExecutionEvidence`) for the correlation and reporting layers.
"""

from __future__ import annotations

from hunterx.domain.execution import (
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
    FailureKind,
    ToolExecutionEvidence,
)
from hunterx.plugins.sdk.results import FindingResult
from hunterx.shared.time import utcnow_iso


def new_result(context, *, status: ExecutionStatus = ExecutionStatus.PENDING) -> ExecutionResult:
    """Create a result for ``context`` with execution/tool ids pre-filled."""
    return ExecutionResult(
        execution_id=context.execution_id,
        tool_id=context.tool_id,
        status=status,
    )


def start_execution(result: ExecutionResult) -> ExecutionResult:
    """Mark an execution as started and record its start timestamp."""
    result.status = ExecutionStatus.RUNNING
    result.started_at = utcnow_iso()
    return result


def finish_success(result: ExecutionResult, output: ExecutionOutput) -> ExecutionResult:
    """Mark an execution as completed with its collected output."""
    result.status = ExecutionStatus.COMPLETED
    result.output = output
    result.error = ""
    result.failure_kind = None
    result.completed_at = utcnow_iso()
    return result


def finish_failure(
    result: ExecutionResult,
    *,
    error: str,
    kind: FailureKind,
    output: ExecutionOutput | None = None,
    status: ExecutionStatus = ExecutionStatus.FAILED,
) -> ExecutionResult:
    """Mark an execution as failed with a classified failure kind."""
    result.status = status
    result.error = error
    result.failure_kind = kind
    result.completed_at = utcnow_iso()
    if output is not None:
        result.output = output
    return result


def finish_timeout(result: ExecutionResult, *, timeout_seconds: float) -> ExecutionResult:
    """Mark an execution as timed out."""
    result.status = ExecutionStatus.TIMED_OUT
    result.error = f"execution exceeded {timeout_seconds:g}s timeout"
    result.failure_kind = FailureKind.TIMEOUT
    result.completed_at = utcnow_iso()
    return result


def finish_cancelled(result: ExecutionResult, *, reason: str = "cancelled") -> ExecutionResult:
    """Mark an execution as cancelled."""
    result.status = ExecutionStatus.CANCELLED
    result.error = reason
    result.failure_kind = FailureKind.CANCELLED
    result.completed_at = utcnow_iso()
    return result


def elapsed_ms(result: ExecutionResult) -> int:
    """Return elapsed execution time from start to completion."""
    if not result.started_at or not result.completed_at:
        return result.duration_ms
    return result.duration_ms


def mark_stored(result: ExecutionResult) -> ExecutionResult:
    """Record that the result was persisted."""
    result.stored = True
    return result


def mark_normalized(result: ExecutionResult) -> ExecutionResult:
    """Record that the output was normalized."""
    result.normalized = True
    return result


def mark_events(result: ExecutionResult) -> ExecutionResult:
    """Record that lifecycle events were published."""
    result.events_published = True
    return result


def to_evidence(result: ExecutionResult) -> ToolExecutionEvidence:
    """Bridge a completed result into :class:`ToolExecutionEvidence`.

    Findings are sourced from the normalized output when available.
    """
    evidence = ToolExecutionEvidence(
        tool_id=result.tool_id,
        duration_ms=result.duration_ms,
    )
    if result.output.json and isinstance(result.output.json, dict):
        records = result.output.json.get("findings", [])
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict):
                    evidence.findings.append(
                        FindingResult(
                            title=str(record.get("title", "")),
                            severity=str(record.get("severity", "medium")).lower(),
                            target=str(record.get("target", "")),
                            description=str(record.get("description", "")),
                            risk_score=_optional_float(record.get("risk_score")),
                            metadata=record.get("metadata", {}) if isinstance(record.get("metadata"), dict) else {},
                        )
                    )
    return evidence


def _optional_float(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None
