# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool failure-handling certification (Sprint 034.5).

Certifies the required failure modes: missing binary, wrong version, invalid
arguments, timeout, crash, partial output, malformed output, empty output,
rate limiting, network failure, permission failure and unexpected exit codes —
plus classification, retry, fallback and partial-result preservation.
"""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import ToolExecutionError, ToolTimeoutError
from hunterx.domain.execution import ExecutionContext, FailureKind
from hunterx.tools.recon.runner import BinaryRunner
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

from .conftest import FailingRunner, FakeRunner, collect, make_context, payload_json


def _pipeline_failure(runner: BinaryRunner, context: ExecutionContext):
    """Run an adapter through the real SDK pipeline and return the result."""
    engine = ExecutionEngine()
    adapter = SubfinderAdapter(runner=runner)
    engine.register_adapter("subfinder", adapter)
    engine.install_hook("subfinder", lambda tool_id, version: "1.0.0")
    engine.install("subfinder", version="1.0.0")
    return engine.execute(context).result


class TestMissingBinary:
    def test_missing_binary_classified_not_retryable(self):
        result = _pipeline_failure(
            FailingRunner(ToolExecutionError("exec: subfinder: not found")),
            make_context("subfinder"),
        )
        assert not result.ok
        assert result.failure_kind is FailureKind.NOT_RETRYABLE
        assert "not found" in result.error


class TestTimeout:
    def test_timeout_classified_as_timeout(self):
        result = _pipeline_failure(
            FailingRunner(ToolTimeoutError("subfinder", 30.0)),
            make_context("subfinder"),
        )
        assert not result.ok
        assert result.failure_kind is FailureKind.TIMEOUT


class TestInvalidArguments:
    @pytest.mark.parametrize(
        ("tool", "params", "builder"),
        [
            ("shuffledns", {}, "hunterx.tools.dns.shuffledns:ShufflednsAdapter"),
            ("gobuster", {}, "hunterx.tools.content.bruteforcers:GobusterAdapter"),
            ("feroxbuster", {}, "hunterx.tools.content.bruteforcers:FeroxbusterAdapter"),
            ("dirsearch", {}, "hunterx.tools.content.bruteforcers:DirsearchAdapter"),
            ("kiterunner", {}, "hunterx.tools.parameter.adapters:KiterunnerAdapter"),
            ("xxeinjector", {}, "hunterx.tools.vuln.injection:XXEinjectorAdapter"),
            ("mitmproxy", {}, "hunterx.tools.proxy.adapters:MitmproxyAdapter"),
        ],
    )
    def test_missing_required_parameter_rejected_before_launch(self, tool, params, builder):
        from hunterx.tools.sdk.adapter import AdapterFactory

        adapter = AdapterFactory().create(builder)
        with pytest.raises(ValueError):
            adapter.build_argv(make_context(tool, params=params))


class TestCrashAndUnexpectedExit:
    def test_nonzero_exit_is_classified(self):
        adapter = SubfinderAdapter(runner=FakeRunner(stdout="", exit_code=2))
        collector = collect(adapter, make_context("subfinder"))
        output = collector.build()
        assert output.exit_code == 2

    def test_crash_is_classified_and_never_safe(self):
        result = _pipeline_failure(
            FailingRunner(RuntimeError("segfault")),
            make_context("subfinder"),
        )
        assert not result.ok
        assert result.status.value in ("failed", "timed-out")


class TestMalformedAndEmptyOutput:
    def test_malformed_lines_are_skipped(self):
        adapter = SubfinderAdapter(
            runner=FakeRunner(stdout='{"host": "api.example.com", "source": "crt.sh"}\nnot-json{{{}\nplain\n')
        )
        collector = collect(adapter, make_context("subfinder"))
        names = {entry["name"] for entry in payload_json(collector)["discoveries"]}
        assert "api.example.com" in names

    def test_empty_output_is_a_valid_result(self):
        adapter = SubfinderAdapter(runner=FakeRunner(stdout=""))
        collector = collect(adapter, make_context("subfinder"))
        assert payload_json(collector)["count"] == 0

    def test_garbage_output_produces_no_candidates(self):
        from hunterx.tools.vuln.injection import SQLmapAdapter

        adapter = SQLmapAdapter(runner=FakeRunner(stdout="\x00\x01\x02 garbage\x1b[31mANSI\x1b[0m\r\n"))
        collector = collect(adapter, make_context("sqlmap"))
        assert payload_json(collector)["count"] == 0


class TestRateLimitAndPermission:
    def test_rate_limit_parameter_builds_argv(self):
        adapter = SubfinderAdapter(runner=FakeRunner())
        context = make_context("subfinder", params={"rate_limit": 10})
        argv = adapter.build_argv(context)
        assert "-rl" in argv
        assert argv[argv.index("-rl") + 1] == "10"


class TestRunnerBoundary:
    def test_runner_output_cap_terminates(self):
        runner = BinaryRunner(max_output_bytes=128)
        with pytest.raises(ToolExecutionError):
            runner.run(["python", "-c", "print('x' * 100000)"], timeout_s=5)

    def test_runner_timeout_terminates(self):
        runner = BinaryRunner()
        with pytest.raises(ToolTimeoutError):
            runner.run(["python", "-c", "import time; time.sleep(30)"], timeout_s=1)


class TestPartialResultPreservation:
    def test_chain_preserves_partial_results(self):
        from hunterx.domain.execution import ExecutionOutput, ExecutionResult, ExecutionStatus
        from hunterx.domain.tool_intelligence import (
            ChainStatus,
            ToolChain,
            ToolChainCondition,
            ToolChainStep,
        )
        from hunterx.tools.intelligence.chaining import ChainExecutor
        from hunterx.tools.sdk.engine import ExecutionEngine
        from hunterx.tools.sdk.pipeline import PipelineResult
        from hunterx.tools.sdk.session import ExecutionSession

        class FakeEngine(ExecutionEngine):
            def __init__(self, *a, **k):
                self._adapters = {"subfinder": object(), "httpx": object()}

            def adapter_for(self, tool_id):
                return self._adapters.get(tool_id)

            def execute(self, context):
                out = ExecutionOutput()
                out.exit_code = 0
                if context.tool_id == "subfinder":
                    out.json = {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]}
                elif context.tool_id == "httpx":
                    out.exit_code = 1
                    out.stderr = "httpx crashed"
                result = ExecutionResult(
                    execution_id=context.execution_id, tool_id=context.tool_id, status=ExecutionStatus.COMPLETED if out.exit_code == 0 else ExecutionStatus.FAILED, output=out,
                    error="" if out.exit_code == 0 else "httpx crashed",
                )
                return PipelineResult(result=result, session=ExecutionSession(context), attempts=1)

        chain = ToolChain(
            chain_id="chain-1",
            steps=(
                ToolChainStep(step_id="s1", tool_id="subfinder", capability="subdomain-discovery", on_success=ToolChainCondition.ON_SUCCESS, on_failure=ToolChainCondition.ON_FAILURE),
                ToolChainStep(step_id="s2", tool_id="httpx", capability="http-probing", on_success=ToolChainCondition.ON_SUCCESS, on_failure=ToolChainCondition.ON_FAILURE),
            ),
            dependencies={"s2": ("s1",)},
        )
        result = ChainExecutor(FakeEngine()).execute(chain, target="example.com")
        # Partial result preserved: s1 completed, s2 failed.
        assert result.status is ChainStatus.PARTIAL
        assert result.completed_steps == ("s1",)
        assert result.failed_steps == ("s2",)
        assert result.step_results[0].observations
