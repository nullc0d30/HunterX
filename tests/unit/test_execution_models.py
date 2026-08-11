# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the execution domain models."""

from __future__ import annotations

from hunterx.domain.execution import (
    ExecutionContext,
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
    FailureKind,
    OutputFormat,
    ResourceLimits,
    RetryPolicy,
    ToolExecutionEvidence,
)
from tests.framework.execution import make_context


class TestExecutionStatus:
    def test_terminal_and_success_properties(self) -> None:
        assert ExecutionStatus.COMPLETED.is_terminal
        assert ExecutionStatus.COMPLETED.is_success
        assert ExecutionStatus.FAILED.is_terminal
        assert not ExecutionStatus.FAILED.is_success
        assert ExecutionStatus.RUNNING.is_terminal is False

    def test_lifecycle_order(self) -> None:
        statuses = [s.value for s in ExecutionStatus]
        assert statuses.index("pending") < statuses.index("running") < statuses.index("completed")
        assert "timed-out" in statuses and "cancelled" in statuses


class TestRetryPolicy:
    def test_retries_is_max_attempts_minus_one(self) -> None:
        assert RetryPolicy().retries() == 0
        assert RetryPolicy(max_attempts=3).retries() == 2

    def test_default_retryable_kinds(self) -> None:
        policy = RetryPolicy()
        assert FailureKind.RETRYABLE in policy.retryable_kinds
        assert FailureKind.TIMEOUT in policy.retryable_kinds
        assert FailureKind.NOT_RETRYABLE not in policy.retryable_kinds


class TestResourceLimits:
    def test_zero_means_unlimited(self) -> None:
        assert ResourceLimits().capped() is False
        assert ResourceLimits(max_cpu_percent=50.0).capped() is True


class TestExecutionContext:
    def test_timeout_effective_prefers_explicit(self) -> None:
        context = make_context(timeout_seconds=30.0)
        context = _with_limits(context, ResourceLimits(timeout_seconds=60.0))
        assert context.timeout_effective == 30.0

    def test_timeout_effective_falls_back_to_limits(self) -> None:
        context = _with_limits(make_context(), ResourceLimits(timeout_seconds=60.0))
        assert context.timeout_effective == 60.0

    def test_builder_defaults(self) -> None:
        context = make_context()
        assert context.tool_id == "fake"
        assert context.target == "10.0.0.5"
        assert context.execution_id
        assert context.correlation_id == context.execution_id


class TestExecutionOutput:
    def test_ok_and_has_content(self) -> None:
        output = ExecutionOutput(exit_code=0, stdout="data")
        assert output.ok
        assert output.has_content

    def test_failed_exit_code(self) -> None:
        output = ExecutionOutput(exit_code=2)
        assert not output.ok

    def test_formats(self) -> None:
        output = ExecutionOutput()
        output.add_format(OutputFormat.JSON)
        output.add_format(OutputFormat.JSON)
        assert output.formats == {OutputFormat.JSON}


class TestExecutionResult:
    def test_ok_reflects_status(self) -> None:
        result = ExecutionResult(status=ExecutionStatus.COMPLETED)
        assert result.ok
        assert not result.retryable
        result = ExecutionResult(status=ExecutionStatus.FAILED, failure_kind=FailureKind.RETRYABLE)
        assert not result.ok
        assert result.retryable

    def test_summarize_is_json_safe(self) -> None:
        result = ExecutionResult(
            execution_id="ex-1",
            tool_id="nmap",
            status=ExecutionStatus.FAILED,
            failure_kind=FailureKind.TIMEOUT,
        )
        summary = result.summarize()
        assert summary["execution_id"] == "ex-1"
        assert summary["status"] == "failed"
        assert summary["failure_kind"] == "timeout"


class TestToolExecutionEvidence:
    def test_empty_evidence(self) -> None:
        evidence = ToolExecutionEvidence(tool_id="nmap")
        assert evidence.findings == []
        assert evidence.evidence == []
        assert evidence.assets == []


def _with_limits(context: ExecutionContext, limits: ResourceLimits) -> ExecutionContext:
    from dataclasses import replace

    return replace(context, resource_limits=limits)
