# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for the toolchain certification suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.output import OutputCollector

GOLDEN = Path(__file__).parent.parent / "golden" / "tools"


class FakeRunner(BinaryRunner):
    """Binary runner that returns a canned :class:`CommandResult`.

    Records every argv it receives so tests can assert on the generated
    command line without touching the filesystem or the network.
    """

    def __init__(self, result: CommandResult | None = None, *, stdout: str = "", exit_code: int = 0) -> None:
        super().__init__()
        self._result = result or CommandResult(returncode=exit_code, stdout=stdout)
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float = 0.0,
        tool_id: str = "",
    ) -> CommandResult:
        self.calls.append(tuple(argv))
        return self._result


class FailingRunner(BinaryRunner):
    """Runner that raises a :class:`ToolExecutionError` on launch."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self._error = error

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float = 0.0,
        tool_id: str = "",
    ) -> CommandResult:
        raise self._error


def make_context(tool_id: str, *, target: str = "example.com", params: dict[str, object] | None = None) -> ExecutionContext:
    """Build an execution context for a tool."""
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_permissions(("network",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


def collect(adapter: object, context: ExecutionContext) -> OutputCollector:
    """Run an adapter against a context and return its output collector."""
    collector = OutputCollector()
    adapter.run(context, collector)
    return collector


def payload_json(collector: OutputCollector) -> dict[str, object]:
    """Return the JSON payload attached to a collector."""
    output = collector.build()
    assert output.json is not None, "adapter produced no JSON payload"
    return output.json


@pytest.fixture
def golden() -> Path:
    """Path to the toolchain golden fixtures directory."""
    return GOLDEN


@pytest.fixture
def golden_text() -> callable:
    """Return a helper that reads a golden fixture as text."""

    def _read(relative: str) -> str:
        return (GOLDEN / relative).read_text(encoding="utf-8")

    return _read
