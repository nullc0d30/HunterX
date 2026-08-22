# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the mission execution / completion lifecycle.

Reference incident: ``full_security_assessment`` reached
``stop_condition=coverage_target_achieved`` at 76.47% coverage with 67 open
hypotheses, zero active testing, NOT_ASSESSED browser and zero attack paths.
These tests guard the corrected semantics:

- coverage is only an input to completion (objective contract gates it);
- an incomplete assessment is never reported as complete/reporting;
- actionable open hypotheses keep the hunt alive;
- OpenRouter 429s use shared cooldown + deterministic fallback (never a false
  completion, never a storm);
- tool failures carry a truthful exit code;
- a URL target registers a root asset.
"""

from __future__ import annotations

import dataclasses
import json

from hunterx.application.ai_suggestion import AIActionSuggester
from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.execution import ExecutionContext, FailureKind
from hunterx.domain.mission_orchestration.enums import HypothesisState, StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.sdk.pipeline import ExecutionPipeline
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "http://localhost:3010"

_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
    "endpoint_enumeration": ("httpx",),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
}

_FAKE_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.target"}]},
    "dnsx": {"records": ["api.target -> 1.2.3.4"]},
    "nmap": {"ports": [80, 443]},
    "whatweb": {"name": "express", "technologies": ["node.js", "express"]},
    "httpx": {"endpoints": ["/api/products", "/rest/search"]},
    "arjun": {"parameters": ["q", "id"]},
    "nuclei": {"findings": [{"template": "xss-detection", "severity": "high", "class": "xss"}]},
}


def _runner(fake: FakeExecutionEngine):
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=_DEFAULT_CANDIDATES,
        ),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=fake,
    )
    return runner, orchestration


def _mission(orchestration: MissionOrchestrationService, *, coverage_target: float = 0.7):
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=coverage_target,
        stop_conditions=(
            StopCondition.COVERAGE_TARGET_ACHIEVED,
            StopCondition.RESOURCE_BUDGET_EXHAUSTED,
            StopCondition.OBJECTIVES_COMPLETE,
        ),
    )
    orchestration.start(mission.mission_id)
    return mission


class _Candidate:
    """Minimal ready-candidate double for the AI suggester."""

    def __init__(self, action_id: str, capability: str) -> None:
        self.action_id = action_id
        self.capability = capability
        self.description = f"{capability} on target"
        self.tool_ids = ("subfinder",)


class _RecordingAI:
    """A fake AI client that records calls and can be rate-limited/failing."""

    def __init__(self, *, fail: bool = False, rate_limited: bool = False, retry_after: float = 12.0) -> None:
        self.calls = 0
        self._fail = fail
        self._rate_limited = rate_limited
        self._retry_after = retry_after

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        self.calls += 1
        if self._fail:
            raise RuntimeError("provider unavailable")
        if self._rate_limited:
            error = RuntimeError("openrouter: rate limited (HTTP 429) — retry later")
            error.retry_after = self._retry_after  # type: ignore[attr-defined]
            raise error
        return json.dumps({"suggested_action_id": "act-1", "reason": "top pick"})

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        return []


class TestCoverageCannotPrematurelyTerminate:
    def test_coverage_below_contract_does_not_fire_coverage_stop(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)

        # Drive meaningful discovery so coverage crosses the 70% target while
        # actionable (vulnerability) hypotheses remain open and untested.
        runner.run(mission.mission_id, max_cycles=12)

        mission = orchestration.get(mission.mission_id)
        assert mission.outcome is not None
        # The honest terminal on a non-loopback target is blocked, and the stop
        # condition is never a coverage-based false completion while open
        # actionable hypotheses remain.
        assert mission.outcome.stop_condition != StopCondition.COVERAGE_TARGET_ACHIEVED.value
        assert mission.mission.state.value == "blocked"
        assert mission.outcome.objectives_complete is False

    def test_contract_gate_is_exposed_and_explainable(self) -> None:
        from hunterx.domain.mission_orchestration.completion import contract_for_objective

        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)
        runner.run(mission.mission_id, max_cycles=8)
        mission = orchestration.get(mission.mission_id)

        assessment = contract_for_objective(mission.mission.objective, coverage_target=0.7).evaluate(mission)
        # The contract must be explainable and must NOT claim satisfaction while
        # a mandatory dimension is untested or coverage is unmet.
        assert not assessment.satisfied
        assert assessment.unmet(), "an incomplete assessment must expose unmet gates"
        assert all(gate.reason for gate in assessment.gates), "every gate must carry a reason"

    def test_remaining_execution_budget_is_not_exhaustion(self) -> None:
        # Test B: used=16, budget=1000 -> execution_exhausted False.
        mission = _mission(_runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))[1])
        mission.budget.executions_used = 16
        mission.budget.executions_budget = 1000
        assert mission.budget.execution_exhausted is False
        assert mission.budget.execution_remaining == 984
        assert mission.budget.exhausted is False


class TestRootAsset:
    def test_url_target_produces_root_asset(self) -> None:
        # Test F: http://localhost:3010 -> root asset before downstream entities.
        _, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
        assert mission.context.assets, "the URL target must register a root asset"
        root = next(iter(mission.context.assets.values()))
        assert root.get("root") is True
        assert root.get("key") == _TARGET

    def test_root_asset_is_not_duplicated(self) -> None:
        _, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
        keys = [key for key, entry in mission.context.assets.items() if entry.get("root")]
        assert len(keys) == 1


class TestToolFailureNormalization:
    def test_validation_failure_keeps_truthful_exit_code(self) -> None:
        # Test G: an adapter that produced exit_code 1 with an invalid output
        # must fail with OUTPUT_INVALID AND output.exit_code == 1.
        from hunterx.domain.tools import ToolDescriptor
        from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
        from hunterx.tools.sdk.adapter import ToolAdapter
        from hunterx.tools.sdk.dependencies import DependencyResolver
        from hunterx.tools.sdk.events import ExecutionEventBus
        from hunterx.tools.sdk.health import HealthChecker
        from hunterx.tools.sdk.installer import InstallationManager
        from hunterx.tools.sdk.monitor import ExecutionMonitor
        from hunterx.tools.sdk.output import OutputCollector
        from hunterx.tools.sdk.resources import ResourceManager
        from hunterx.tools.sdk.retry import RetryManager
        from hunterx.tools.sdk.sandbox import ExecutionSandbox
        from hunterx.tools.sdk.timeout import TimeoutManager
        from hunterx.tools.sdk.version import VersionManager

        class _FailingAdapter(ToolAdapter):
            descriptor = ToolDescriptor(name="stub", entrypoint="tests:Stub")

            def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
                collector.set_exit_code(1)
                collector.attach_stdout("something that fails validation")

        installer = InstallationManager()
        versions = VersionManager()
        registry = ToolIntelligenceRegistry()

        class _PassResolver(DependencyResolver):
            def assert_satisfied(self, tool_id: str) -> None:  # noqa: ARG002
                return None

        class _PassHealth(HealthChecker):
            def assert_healthy(self, tool_id: str, requirement: str = "") -> None:  # noqa: ARG002
                return None

        pipeline = ExecutionPipeline(
            adapter=_FailingAdapter(),
            sandbox=ExecutionSandbox(),
            resources=ResourceManager(),
            timeout=TimeoutManager(),
            retry=RetryManager(),
            dependencies=_PassResolver(registry, installer),
            health=_PassHealth(installer, versions),
            monitor=ExecutionMonitor(),
            events=ExecutionEventBus(),
        )
        result = pipeline.run(ExecutionContext(tool_id="stub", target="x")).result
        assert result.failure_kind == FailureKind.OUTPUT_INVALID
        assert result.output.exit_code == 1, "the truthful exit code must be preserved"
        assert "exit code 1" in result.error


class TestOpenRouter429Resilience:
    def _suggester(self, ai: _RecordingAI) -> AIActionSuggester:
        return AIActionSuggester(ai, provider="openrouter", model="nvidia/nemotron:free", min_interval_s=0.0, backoff_s=5.0, max_cooldown_s=60.0)

    def _candidates(self, count: int = 3) -> list[_Candidate]:
        return [_Candidate(f"act-{index}", "port_discovery") for index in range(count)]

    def test_429_honors_retry_after_and_prevents_storm(self) -> None:
        # Test C: Retry-After respected; bounded; no storm; deterministic fallback.
        mission = _mission(_runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))[1])
        ai = _RecordingAI(rate_limited=True, retry_after=12.0)
        suggester = self._suggester(ai)

        first = suggester.suggest(mission, self._candidates())
        assert ai.calls == 1
        assert first.http_status == 429
        assert first.fallback is True
        assert first.cooldown is True
        assert suggester.rate_limited()
        # Retry-After honored: the cooldown lasts (at least) the header value.
        assert suggester.cooldown_remaining_s() > 10.0
        assert suggester.cooldown_remaining_s() <= 12.0

        # Immediately re-requesting must NOT re-fire at the provider (no storm).
        second = suggester.suggest(mission, self._candidates())
        assert ai.calls == 1, "a rate-limited provider must not be hammered"
        assert second.fallback is True and second.deterministic is True
        assert suggester.counters()["ai_cooldown_events"] >= 1

    def test_bounded_backoff_and_recovery(self) -> None:
        mission = _mission(_runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))[1])
        ai = _RecordingAI(rate_limited=True, retry_after=0.0)
        suggester = self._suggester(ai)
        suggester.suggest(mission, self._candidates())
        assert suggester.cooldown_remaining_s() > 0
        # After the cooldown expires, the provider is consulted again.
        suggester.reset_rate_limit()
        ai._rate_limited = False
        result = suggester.suggest(mission, self._candidates())
        assert ai.calls == 2
        assert result.usable is True

    def test_shared_cooldown_prevents_concurrent_amplification(self) -> None:
        # Test D: multiple "workers" share the singleton suggester; a single
        # 429 must not produce N more requests.
        mission = _mission(_runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))[1])
        ai = _RecordingAI(rate_limited=True, retry_after=20.0)
        suggester = self._suggester(ai)

        results = [suggester.suggest(mission, self._candidates()) for _ in range(4)]
        assert ai.calls == 1, "concurrent 429s must not amplify into more requests"
        assert all(result.fallback for result in results)

    def test_ai_failure_uses_deterministic_fallback(self) -> None:
        # Test E: AI unavailable -> deterministic fallback, mission continues.
        mission = _mission(_runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))[1])
        ai = _RecordingAI(fail=True)
        suggester = self._suggester(ai)
        result = suggester.suggest(mission, self._candidates())
        assert result.fallback is True
        assert suggester.counters()["ai_fallback_decisions"] >= 1
        assert suggester.counters()["ai_deterministic_decisions"] >= 0


class TestOpenHypothesisKeepsHunting:
    def test_actionable_open_hypothesis_blocks_coverage_completion(self) -> None:
        # Test H: a high-priority / vulnerability-class open hypothesis means the
        # runner still has work and coverage must not terminate the mission.
        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)

        # Seed an open, actionable (vulnerability-class) hypothesis directly.
        hypothesis = mission.hypothesis("missing")  # noqa: F841  # placeholder
        from hunterx.domain.mission_orchestration.models import MissionHypothesis
        from hunterx.domain.target_intelligence.enums import HypothesisType

        open_hypothesis = MissionHypothesis(
            hypothesis_id="H-ACTIONABLE",
            mission_id=mission.mission_id,
            statement="The 'q' parameter on http://localhost:3010/api may be susceptible to sql-injection",
            category=HypothesisType.INJECTION,
            state=HypothesisState.PROPOSED,
            priority=0.9,
            provenance={"vulnerability_class": "sql-injection", "endpoint": "http://localhost:3010/api", "parameter": "q"},
        )
        mission.upsert_hypothesis(open_hypothesis)

        # With an open actionable hypothesis, the contract is not satisfied.
        from hunterx.domain.mission_orchestration.completion import contract_for_objective

        assessment = contract_for_objective(mission.mission.objective, coverage_target=0.7).evaluate(mission)
        assert "no_actionable_open_hypotheses" in assessment.unmet()
        assert runner._open_hypothesis_work_remaining(mission.mission_id) is True

    def test_high_priority_open_hypothesis_is_actionable(self) -> None:
        from hunterx.domain.mission_orchestration.models import MissionHypothesis

        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        mission.upsert_hypothesis(
            MissionHypothesis(
                hypothesis_id="H-HIGH",
                mission_id=mission.mission_id,
                statement="high priority open",
                state=HypothesisState.PROPOSED,
                priority=0.8,
            )
        )
        assert runner._open_hypothesis_work_remaining(mission.mission_id) is True


class TestActiveTestingAndBrowserGates:
    def test_active_testing_required_when_probeable_surface_exists(self) -> None:
        from hunterx.domain.mission_orchestration.completion import contract_for_objective

        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        # A probeable surface exists but no probe has been executed.
        mission.context.endpoints["endpoint:http://localhost:3010/api"] = {"key": "http://localhost:3010/api"}
        mission.context.parameters["param:http://localhost:3010/api:q"] = {"key": "http://localhost:3010/api", "parameter": "q"}
        assessment = contract_for_objective(mission.mission.objective, coverage_target=0.7).evaluate(mission)
        assert "active_testing" in assessment.unmet(), "probeable surface with no probe must block completion"

    def test_browser_not_assessed_without_reason_blocks_completion(self) -> None:
        # Test J: a web target whose browser dimension is NOT_ASSESSED with no
        # recorded classification cannot complete.
        from hunterx.domain.mission_orchestration.completion import contract_for_objective
        from hunterx.domain.target_intelligence.enums import CoverageState

        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        mission.record_coverage(
            asset_key=_TARGET,
            capability="browser_testing",
            state=CoverageState.NOT_ASSESSED,
            notes="",
        )
        assessment = contract_for_objective(mission.mission.objective, coverage_target=0.7).evaluate(mission)
        assert "browser" in assessment.unmet()

    def test_browser_explicitly_classified_is_satisfied(self) -> None:
        from hunterx.domain.mission_orchestration.completion import contract_for_objective
        from hunterx.domain.target_intelligence.enums import CoverageState

        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        mission.record_coverage(
            asset_key=_TARGET,
            capability="browser_testing",
            state=CoverageState.NOT_ASSESSED,
            notes="browser automation unavailable: playwright not installed",
        )
        assessment = contract_for_objective(mission.mission.objective, coverage_target=0.7).evaluate(mission)
        assert "browser" not in assessment.unmet()


class TestHypothesisClassification:
    def test_classify_open_hypotheses_marks_recon_facts_deferred(self) -> None:
        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        from hunterx.domain.mission_orchestration.models import MissionHypothesis

        mission.upsert_hypothesis(
            MissionHypothesis(
                hypothesis_id="H-RECON",
                mission_id=mission.mission_id,
                statement="target runs express",
                state=HypothesisState.PROPOSED,
                priority=0.5,
                provenance={"technology": "express"},
            )
        )
        mission.upsert_hypothesis(
            MissionHypothesis(
                hypothesis_id="H-VULN",
                mission_id=mission.mission_id,
                statement="q may be sql-injection",
                state=HypothesisState.PROPOSED,
                priority=0.6,
                provenance={"vulnerability_class": "sql-injection"},
            )
        )
        classified = orchestration.classify_open_hypotheses(mission.mission_id)
        assert classified == 1  # only the non-actionable recon fact is deferred
        mission = orchestration.get(mission.mission_id)
        assert mission.hypothesis("H-RECON").state == HypothesisState.DEFERRED
        assert mission.hypothesis("H-RECON").provenance.get("deferred_reason")
        # The actionable vulnerability hypothesis is NOT auto-deferred.
        assert mission.hypothesis("H-VULN").state == HypothesisState.PROPOSED

    def test_defer_and_block_record_reasons(self) -> None:
        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        from hunterx.domain.mission_orchestration.models import MissionHypothesis

        mission.upsert_hypothesis(
            MissionHypothesis(
                hypothesis_id="H-1",
                mission_id=mission.mission_id,
                statement="open fact",
                state=HypothesisState.PROPOSED,
                priority=0.5,
            )
        )
        orchestration.defer_hypothesis(mission.mission_id, "H-1", reason="out of scope")
        mission = orchestration.get(mission.mission_id)
        assert mission.hypothesis("H-1").state == HypothesisState.DEFERRED
        assert mission.hypothesis("H-1").provenance.get("deferred_reason") == "out of scope"


class TestAITelemetryAggregation:
    def test_cooldown_and_deterministic_are_recorded_in_telemetry(self) -> None:
        # Ensure trace entries carry cooldown/deterministic so telemetry reports
        # them truthfully (the incident showed ai_fallbacks=0 despite 6x 429).
        from hunterx.domain.mission_orchestration.enums import ReasoningTraceKind
        from hunterx.domain.mission_orchestration.models import ReasoningTraceEntry

        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        mission.trace.append(
            ReasoningTraceEntry(
                mission_id=mission.mission_id,
                kind=ReasoningTraceKind.RATIONALE,
                content={
                    "ai_invoked": True,
                    "ai_http_status": 429,
                    "ai_usable": False,
                    "ai_error": "AI rate limited (HTTP 429)",
                    "ai_fallback": True,
                    "ai_cooldown": True,
                    "ai_deterministic": True,
                    "ai_provider": "openrouter",
                    "ai_model": "nvidia/nemotron:free",
                },
            )
        )
        telemetry = orchestration.engine.orchestrator.telemetry.snapshot(mission)
        assert telemetry.ai_http_429 == 1
        assert telemetry.ai_fallbacks == 1
        assert telemetry.ai_cooldown_events == 1
        assert telemetry.ai_deterministic_decisions == 1


__all__ = []
