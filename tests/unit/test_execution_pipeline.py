# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the execution pipeline and engine end-to-end lifecycle."""

from __future__ import annotations

from hunterx.domain.execution import ExecutionStatus, FailureKind, RetryPolicy
from hunterx.domain.tool_intelligence import ToolDependency
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolContext, ToolOutput
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.output import OutputCollector
from tests.framework.execution import FakeAdapter, make_context
from tests.framework.tip import make_knowledge, make_metadata, register_standard_tools


class NetworkTool(ToolAdapter):
    """Adapter that requests the network permission at runtime."""

    descriptor = ToolDescriptor(
        name="network-tool",
        entrypoint="tests.unit.test_execution_pipeline:NetworkTool",
        permissions=("network",),
    )

    def run(self, context, collector: OutputCollector) -> None:  # noqa: ANN001 - concrete param
        collector.attach_stdout("ok")


def _engine(tool_id: str = "fake", adapter: ToolAdapter | None = None) -> ExecutionEngine:
    tip = ToolIntelligenceAPI()
    register_standard_tools(tip)
    engine = ExecutionEngine(intelligence=tip.registry)
    engine.register_adapter(tool_id, adapter or FakeAdapter())
    return engine


def _install(engine: ExecutionEngine, tool_id: str) -> None:
    engine.install(tool_id, version="1.0.0")


class TestPipelineSuccess:
    def test_full_lifecycle_completes(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        context = make_context()
        outcome = engine.execute(context)
        result = outcome.result
        assert result.ok
        assert result.status is ExecutionStatus.COMPLETED
        assert result.normalized
        assert result.events_published
        assert result.output.json["findings"][0]["title"] == "Open port 80"
        assert "PORT STATE" in result.output.stdout

    def test_events_and_monitor_fire(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        context = make_context()
        engine.execute(context)
        events = [r.event_type.value for r in engine.events.events()]
        assert "execution.started" in events
        assert "execution.completed" in events
        assert "output.collected" in events
        assert "normalization.complete" in events
        timeline = engine.monitor.timeline(context.execution_id)
        assert timeline and timeline[-1].status is ExecutionStatus.COMPLETED

    def test_session_and_attempts(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        outcome = engine.execute(make_context())
        assert outcome.attempts == 1
        assert outcome.session.execution_id == outcome.result.execution_id
        assert outcome.session.completed_at


class TestPipelineFailures:
    def test_unhealthy_tool_fails_with_retryable_kind(self) -> None:
        engine = _engine()
        outcome = engine.execute(make_context())  # not installed -> unhealthy
        assert not outcome.result.ok
        assert outcome.result.failure_kind is FailureKind.RETRYABLE

    def test_non_retryable_execution_failure(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        FakeAdapter.fail_with = RuntimeError("boom")
        try:
            outcome = engine.execute(make_context())
            assert not outcome.result.ok
            assert outcome.result.failure_kind is FailureKind.NOT_RETRYABLE
            assert "boom" in outcome.result.error
        finally:
            FakeAdapter.reset()

    def test_permission_violation_fails_with_sandbox_kind(self) -> None:
        engine = _engine(tool_id="network-tool", adapter=NetworkTool())
        engine.install_hook("network-tool", lambda tool_id, version: "1.0.0")
        _install(engine, "network-tool")
        context = make_context(tool_id="network-tool")  # no network permission granted
        outcome = engine.execute(context)
        assert not outcome.result.ok
        assert outcome.result.failure_kind is FailureKind.SANDBOX_VIOLATION

    def test_missing_dependency_blocks_execution(self) -> None:
        tip = ToolIntelligenceAPI()
        register_standard_tools(tip)
        tip.register_tool(
            make_metadata("scanner-a", category="recon", subcategory="network"),
            knowledge=make_knowledge(
                "scanner-a",
                capabilities=("wrapper-scanning",),
                dependencies=(ToolDependency(capability="port-scanning"),),
            ),
            compatibility=None,
        )
        engine = ExecutionEngine(intelligence=tip.registry)
        engine.register_adapter("scanner-a", FakeAdapter())
        _install(engine, "scanner-a")
        context = make_context(tool_id="scanner-a")
        outcome = engine.execute(context)
        assert not outcome.result.ok
        assert outcome.result.failure_kind is FailureKind.MISSING_DEPENDENCY


class TestPipelineRetry:
    def test_retry_recovers(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        FakeAdapter.fail_once = True
        context = ExecutionContextBuilder.from_context(make_context()).with_retry_policy(
            RetryPolicy(max_attempts=2, base_delay_s=0.0)
        ).build()
        try:
            outcome = engine.execute(context)
            assert outcome.result.ok
            assert outcome.attempts == 2
        finally:
            FakeAdapter.reset()

    def test_retry_exhausted(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        FakeAdapter.fail_once = True
        FakeAdapter.fail_with = RuntimeError("boom")
        context = ExecutionContextBuilder.from_context(make_context()).with_retry_policy(
            RetryPolicy(max_attempts=2, base_delay_s=0.0)
        ).build()
        try:
            outcome = engine.execute(context)
            assert not outcome.result.ok
            assert outcome.attempts == 2
        finally:
            FakeAdapter.reset()


class TestPipelineTimeout:
    def test_timeout_produces_timed_out_status(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        FakeAdapter.sleep_s = 0.3
        context = make_context(timeout_seconds=0.05)
        try:
            outcome = engine.execute(context)
            assert outcome.result.status is ExecutionStatus.TIMED_OUT
            assert outcome.result.failure_kind is FailureKind.TIMEOUT
            assert any(
                r.event_type.value == "execution.timed_out" for r in engine.events.events()
            )
        finally:
            FakeAdapter.reset()


class TestEngineFeatures:
    def test_submit_and_drain(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        engine.submit(make_context(target="10.0.0.1"))
        engine.submit(make_context(target="10.0.0.2"))
        outcomes = engine.drain()
        assert len(outcomes) == 2
        assert all(o.result.ok for o in outcomes)

    def test_run_parallel(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        contexts = [make_context(target=f"10.0.0.{i}") for i in range(1, 4)]
        outcomes = engine.run_parallel(contexts)
        assert len(outcomes) == 3
        assert all(o.result.ok for o in outcomes)
        engine.shutdown()

    def test_unregistered_tool_raises(self) -> None:
        engine = _engine()
        try:
            engine.execute(make_context(tool_id="unregistered"))
        except LookupError:
            pass
        else:
            raise AssertionError("expected LookupError for unregistered tool")

    def test_cache_key_roundtrip(self) -> None:
        engine = _engine()
        _install(engine, "fake")
        context = make_context(target="10.0.0.5", parameters={"ports": "80"})
        key = engine.cache.key_for(context)
        engine.cache.set(key, object())  # type: ignore[arg-type]
        assert engine.cache.get(key) is not None

    def test_legacy_tool_bridge_runs(self) -> None:
        from tests.framework.fakes import StaticScanner

        tip = ToolIntelligenceAPI()
        register_standard_tools(tip)
        engine = ExecutionEngine(intelligence=tip.registry)
        bridge = engine.register_adapter("static.scanner", StaticScanner())
        from hunterx.tools.sdk.adapter import LegacyToolBridge

        assert isinstance(bridge, LegacyToolBridge)
        engine.install_hook("static.scanner", lambda tool_id, version: "0.1.0")
        _install(engine, "static.scanner")
        outcome = engine.execute(
            ExecutionContextBuilder(tool_id="static.scanner", target="example.com").build()
        )
        assert outcome.result.ok


def test_static_scanner_output_contract() -> None:
    from tests.framework.fakes import StaticScanner

    scanner = StaticScanner()
    output = scanner.run("example.com", {}, ToolContext())
    assert isinstance(output, ToolOutput)
    assert output.findings
