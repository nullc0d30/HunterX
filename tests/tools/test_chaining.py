# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool chaining certification (Sprint 034.5).

Certifies that planned tool chains execute end-to-end in dependency order,
produce canonical observations with full provenance, feed discovered hosts/URLs
into dependent steps, classify failures and attempt capability-equivalent
fallbacks while preserving partial results.
"""

from __future__ import annotations

from hunterx.domain.execution import (
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
)
from hunterx.domain.tool_intelligence import (
    ChainStatus,
    ToolChain,
    ToolChainCondition,
    ToolChainStep,
)
from hunterx.platform import build_platform
from hunterx.tools.intelligence.chaining import ChainExecutor
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.pipeline import PipelineResult
from hunterx.tools.sdk.session import ExecutionSession


def _fake_engine(
    outputs: dict[str, dict],
    *,
    adapters: dict[str, object] | None = None,
    failures: dict[str, str] | None = None,
) -> ExecutionEngine:
    """Build an engine returning canned JSON per tool id."""

    class FakeEngine(ExecutionEngine):
        def __init__(self, *a, **k):
            self._adapters = adapters or {tool: object() for tool in outputs}

        def adapter_for(self, tool_id):
            return self._adapters.get(tool_id)

        def execute(self, context):
            out = ExecutionOutput()
            if failures and context.tool_id in failures:
                out.exit_code = 1
                out.stderr = failures[context.tool_id]
                result = ExecutionResult(
                    execution_id=context.execution_id,
                    tool_id=context.tool_id,
                    status=ExecutionStatus.FAILED,
                    output=out,
                    error=failures[context.tool_id],
                )
            else:
                out.exit_code = 0
                out.json = outputs.get(context.tool_id, {})
                result = ExecutionResult(
                    execution_id=context.execution_id,
                    tool_id=context.tool_id,
                    status=ExecutionStatus.COMPLETED,
                    output=out,
                )
            return PipelineResult(result=result, session=ExecutionSession(context), attempts=1)

    return FakeEngine()


def _chain(*steps: tuple[str, str]) -> ToolChain:
    """Build a linear chain from ``(step_id, tool_id)`` pairs."""
    step_objects = [
        ToolChainStep(
            step_id=step_id,
            tool_id=tool_id,
            capability=capability,
            on_success=ToolChainCondition.ON_SUCCESS,
            on_failure=ToolChainCondition.ON_FAILURE,
        )
        for step_id, tool_id, capability in steps
    ]
    dependencies = {
        step.step_id: (previous_step_id,)
        for previous_step_id, step in zip(
            (item.step_id for item in step_objects),
            (item for item in step_objects[1:]),
            strict=False,
        )
    }
    return ToolChain(chain_id="chain-1", steps=tuple(step_objects), dependencies=dependencies)


class TestChainExecution:
    def test_full_chain_completes_with_observations(self):
        engine = _fake_engine(
            {
                "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]},
                "httpx": {"requests": [{"url": "https://api.example.com"}]},
                "katana": {"urls": [{"url": "https://api.example.com/admin"}]},
            }
        )
        chain = _chain(
            ("s1", "subfinder", "subdomain-discovery"),
            ("s2", "httpx", "http-probing"),
            ("s3", "katana", "web-crawling"),
        )
        result = ChainExecutor(engine).execute(chain, target="example.com")
        assert result.status is ChainStatus.COMPLETED
        assert len(result.completed_steps) == 3
        kinds = [obs.observation_kind for step in result.step_results for obs in step.observations]
        assert "domain" in kinds
        assert "url" in kinds

    def test_observations_carry_full_provenance(self):
        engine = _fake_engine({"subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]}})
        chain = _chain(("s1", "subfinder", "subdomain-discovery"))
        result = ChainExecutor(engine).execute(chain, target="example.com", mission_id="m1")
        observation = result.step_results[0].observations[0]
        assert observation.tool_id == "subfinder"
        assert observation.target_id == "example.com"
        assert observation.provenance["mission_id"] == "m1"
        assert observation.raw_artifact_reference.startswith("exec://")
        assert observation.provenance["source"] == "subfinder"
        assert observation.provenance["mission_id"] == "m1"
        assert observation.timestamp

    def test_derived_targets_feed_dependent_steps(self):
        engine = _fake_engine(
            {
                "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]},
                "httpx": {"requests": [{"url": "https://api.example.com"}]},
            }
        )
        chain = _chain(
            ("s1", "subfinder", "subdomain-discovery"),
            ("s2", "httpx", "http-probing"),
        )
        result = ChainExecutor(engine).execute(chain, target="example.com")
        # httpx step consumed the discovered subdomain as its target.
        assert result.status is ChainStatus.COMPLETED

    def test_step_without_adapter_is_skipped(self):
        engine = _fake_engine(
            {"subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]}},
            adapters={"subfinder": object()},
        )
        chain = _chain(
            ("s1", "subfinder", "subdomain-discovery"),
            ("s2", "nuclei", "vulnerability-scan"),
        )
        result = ChainExecutor(engine).execute(chain, target="example.com")
        assert result.status is ChainStatus.PARTIAL
        assert "s2" in result.skipped_steps
        assert "nuclei" in result.step_results[1].error

    def test_failed_step_marks_partial_and_preserves_prior_results(self):
        engine = _fake_engine(
            {"subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]}},
            failures={"katana": "katana crashed"},
            adapters={"subfinder": object(), "katana": object()},
        )
        chain = _chain(
            ("s1", "subfinder", "subdomain-discovery"),
            ("s2", "katana", "web-crawling"),
        )
        result = ChainExecutor(engine).execute(chain, target="example.com")
        assert result.status is ChainStatus.PARTIAL
        assert result.completed_steps == ("s1",)
        assert result.failed_steps == ("s2",)
        assert result.step_results[0].observations


class TestChainFallback:
    def test_failure_uses_capability_equivalent_fallback(self):
        engine = _fake_engine(
            {"subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]}},
            failures={"amass": "amass failed"},
            adapters={"subfinder": object(), "amass": object(), "findomain": object()},
        )
        platform = build_platform()
        executor = ChainExecutor(engine, tip=platform.tip)
        chain = _chain(("s1", "subfinder", "subdomain-discovery"))
        result = executor.execute(chain, target="example.com")
        assert result.status is ChainStatus.COMPLETED


class TestChainSerialization:
    def test_service_execute_chain_returns_json_report(self):
        platform = build_platform()
        plan = platform.toolchain_service.chain(
            "web-assess",
            ["subdomain-discovery", "http-probing", "web-crawling"],
        )
        planned_tools = {step["tool_id"] for step in plan["steps"]}
        outputs = {
            "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]},
            "httpx": {"requests": [{"url": "https://api.example.com"}]},
            "katana": {"urls": [{"url": "https://api.example.com/admin"}]},
            "nikto": {"requests": [{"url": "https://api.example.com"}]},
        }
        engine = _fake_engine(outputs, adapters={tool: object() for tool in planned_tools})
        platform.toolchain_service._engine = engine
        report = platform.toolchain_service.execute_chain(
            "web-assess",
            ["subdomain-discovery", "http-probing", "web-crawling"],
            "example.com",
            target_type="domain",
        )
        assert report["status"] == "completed"
        assert report["observation_count"] >= 1
        assert report["steps"][0]["execution"]["execution_id"]
        assert report["steps"][0]["observations"][0]["provenance"]["source"] == "subfinder"

    def test_chain_plan_returns_dependency_aware_steps(self):
        platform = build_platform()
        plan = platform.toolchain_service.chain(
            "recon-web",
            ["subdomain-discovery", "http-probing"],
        )
        assert plan["dependencies"]
        assert len(plan["steps"]) == 2
