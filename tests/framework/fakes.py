# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared test doubles: fake tools, fake AI, fake secrets."""

from __future__ import annotations

from typing import Any

from hunterx.domain.execution import (
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
    FailureKind,
    OutputFormat,
)
from hunterx.domain.tools import ToolDescriptor
from hunterx.plugins.sdk.results import FindingResult
from hunterx.tools.adapter import BaseTool, ToolContext, ToolOutput
from hunterx.tools.sdk.pipeline import PipelineResult
from hunterx.tools.sdk.session import ExecutionSession


class StaticScanner(BaseTool):
    """A deterministic scanner returning one finding per target.

    Used to exercise the tool executor and workflow engine without touching
    the network.
    """

    descriptor = ToolDescriptor(
        name="static.scanner",
        version="0.1.0",
        description="Deterministic test scanner.",
        entrypoint="hunterx.tools:BaseTool",
        targets=("ip", "host", "domain"),
        capabilities=("scan",),
        permissions=("none",),
    )

    def execute(self, target: str, parameters: dict[str, Any], context: ToolContext) -> ToolOutput:
        severity = str(parameters.get("severity", "medium"))
        output = ToolOutput()
        output.findings.append(
            FindingResult(
                title=f"Test issue on {target}",
                severity=severity,
                target=target,
                description="Deterministic finding for tests.",
                risk_score=5.0,
            )
        )
        return output


class FailingTool(BaseTool):
    """A tool that always raises; used to test failure handling."""

    descriptor = ToolDescriptor(name="failing.tool", entrypoint="hunterx.tools:BaseTool")

    def execute(self, target: str, parameters: dict[str, Any], context: ToolContext) -> ToolOutput:
        raise RuntimeError("boom")


class FakeExecutionEngine:
    """A deterministic :class:`ExecutionEngine` double for mission tests.

    Maps ``tool_id`` → ``output.json`` so the mission execution runner and the
    observation ingestion / target-modeling path see deterministic content
    without touching the network or spawning external binaries.

    Args:
        outputs: ``tool_id`` → JSON output payload (the execution ``json``).
        fail_tools: tool ids whose executions fail (structured failure).
        error: failure message used for failing tools.
        not_found_output: payload returned for tool ids not in ``outputs``.

    """

    def __init__(
        self,
        outputs: dict[str, dict[str, Any]] | None = None,
        *,
        fail_tools: tuple[str, ...] = (),
        error: str = "tool execution failed (fake)",
        not_found_output: dict[str, Any] | None = None,
    ) -> None:
        self._outputs = dict(outputs or {})
        self._fail_tools = set(fail_tools)
        self._error = error
        self._not_found = not_found_output or {"value": "no content"}
        self.calls: list[Any] = []

    def execute(self, context: Any) -> PipelineResult:
        """Return a canned :class:`PipelineResult` for ``context``."""
        self.calls.append(context)
        tool_id = context.tool_id
        if tool_id in self._fail_tools:
            result = ExecutionResult(
                execution_id=context.execution_id,
                tool_id=tool_id,
                status=ExecutionStatus.FAILED,
                error=self._error,
                failure_kind=FailureKind.NOT_RETRYABLE,
                output=ExecutionOutput(exit_code=1, stderr=self._error, formats={OutputFormat.STDERR}),
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                duration_ms=10,
            )
        else:
            content = self._outputs.get(tool_id, self._not_found)
            result = ExecutionResult(
                execution_id=context.execution_id,
                tool_id=tool_id,
                status=ExecutionStatus.COMPLETED,
                output=ExecutionOutput(exit_code=0, json=content, formats={OutputFormat.JSON}),
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                duration_ms=10,
            )
        return PipelineResult(result=result, session=ExecutionSession(context), attempts=1)


class FakeAIClient:
    """A deterministic AI provider returning canned responses."""

    def __init__(self, response: str = "Canned summary.") -> None:
        self._response = response
        self.prompts: list[str] = []

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        self.prompts.append(prompt)
        return self._response

    def embed(self, text: str) -> list[float]:
        return [0.1, 0.2, 0.3]
