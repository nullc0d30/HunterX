# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared SDK test fixtures: a configurable fake adapter and context builders.

The fake adapter models an SDK-integrated tool without integrating any real
external tool: it writes deterministic stdout/JSON output and can be told to
fail, time out or throw at runtime so pipeline failure paths are testable.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolRetryableError
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.output import OutputCollector


class FakeAdapter(ToolAdapter):
    """SDK adapter that produces deterministic output without running a tool."""

    descriptor = ToolDescriptor(
        name="fake",
        version="1.0.0",
        description="Fixture adapter.",
        entrypoint="tests.framework.execution:FakeAdapter",
        targets=("host", "url"),
        capabilities=("port-scanning",),
        permissions=(),
    )

    fail_with: Exception | None = None
    sleep_s: float = 0.0
    exit_code: int = 0
    fail_once: bool = False

    @classmethod
    def reset(cls) -> None:
        cls.fail_with = None
        cls.sleep_s = 0.0
        cls.exit_code = 0
        cls.fail_once = False

    def prepare(self, context: ExecutionContext) -> None:
        pass

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        import time

        if self.sleep_s:
            time.sleep(self.sleep_s)
        if self.fail_once:
            self.fail_once = False
            raise ToolRetryableError(context.tool_id, "transient failure")
        if self.fail_with is not None:
            raise self.fail_with
        collector.set_exit_code(self.exit_code)
        collector.attach_stdout("PORT STATE SERVICE\n80/tcp open http")
        collector.set_json(
            {
                "findings": [
                    {
                        "title": "Open port 80",
                        "severity": "info",
                        "target": context.target,
                        "description": "An open HTTP port was observed.",
                        "risk_score": 2.0,
                        "metadata": {"port": 80},
                    }
                ]
            }
        )

    def cleanup(self, context: ExecutionContext) -> None:
        pass

    @staticmethod
    def installer(tool_id: str, version: str | None = None) -> str:
        return version or "1.0.0"


def make_context(tool_id: str = "fake", target: str = "10.0.0.5", **overrides: object) -> ExecutionContext:
    """Build a ready execution context with defaults."""
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_target_type("host")
    if "timeout_seconds" in overrides:
        builder = builder.with_timeout(float(overrides.pop("timeout_seconds")))  # type: ignore[arg-type]
    if "permissions" in overrides:
        builder = builder.with_permissions(tuple(overrides.pop("permissions")))  # type: ignore[arg-type]
    if "retry_policy" in overrides:
        builder = builder.with_retry_policy(overrides.pop("retry_policy"))  # type: ignore[arg-type]
    if overrides:
        builder = builder.with_parameters({k: v for k, v in overrides.items()})
    return builder.build()
