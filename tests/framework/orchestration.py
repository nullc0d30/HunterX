# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory orchestration test doubles and helpers.

Shared fixtures for the offensive orchestration layer: in-memory repositories,
a fake execution engine producing deterministic normalized output, and
planner/executor helper factories.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.execution import (
    ExecutionContext,
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
)
from hunterx.infrastructure.memory.orchestration import (
    InMemoryExecutionPlanRepository,
    InMemoryOffensiveMissionRepository,
    InMemoryToolSelectionRepository,
)
from hunterx.tools.sdk.pipeline import PipelineResult
from hunterx.tools.sdk.session import ExecutionSession


class _FakeCapabilityRegistry:
    """A fake capability registry returning a synthetic tool for every capability."""

    def providers_for(self, capability: str) -> list[str]:
        """Return a deterministic tool id for any capability."""
        return ["fake-tool"]


class FakeExecutionEngine:
    """A deterministic execution engine for orchestration tests.

    Every execution returns a completed result whose JSON output is the
    ``tool_output`` registered for the tool id (or an empty mapping).
    """

    def __init__(self) -> None:
        self.outputs: dict[str, dict[str, Any]] = {}
        self.executed: list[ExecutionContext] = []
        self.adapter_for = lambda tool_id: tool_id  # every tool "registered"
        self._capability_registry = _FakeCapabilityRegistry()

    def execute(self, context: ExecutionContext) -> PipelineResult:
        """Return a deterministic pipeline result for ``context``."""
        self.executed.append(context)
        output = ExecutionOutput(
            json=dict(self.outputs.get(context.tool_id, {})),
            exit_code=0,
            stdout="",
        )
        result = ExecutionResult(
            execution_id=context.execution_id,
            tool_id=context.tool_id,
            status=ExecutionStatus.COMPLETED,
            output=output,
            duration_ms=5,
            normalized=True,
            stored=False,
        )
        session = ExecutionSession(context)
        return PipelineResult(result=result, session=session, attempts=1)

    def set_output(self, tool_id: str, output: dict[str, Any]) -> None:
        """Register the normalized output produced by ``tool_id``."""
        self.outputs[tool_id] = output


def build_orchestration_repositories() -> dict[str, Any]:
    """Build in-memory orchestration repositories keyed by role name."""
    return {
        "offensive_missions": InMemoryOffensiveMissionRepository(),
        "execution_plans": InMemoryExecutionPlanRepository(),
        "tool_selections": InMemoryToolSelectionRepository(),
    }


def fake_engine() -> FakeExecutionEngine:
    """Return a fresh fake execution engine."""
    return FakeExecutionEngine()
