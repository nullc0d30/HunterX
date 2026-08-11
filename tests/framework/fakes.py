# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared test doubles: fake tools, fake AI, fake secrets."""

from __future__ import annotations

from typing import Any

from hunterx.domain.tools import ToolDescriptor
from hunterx.plugins.sdk.results import FindingResult
from hunterx.tools.adapter import BaseTool, ToolContext, ToolOutput


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
