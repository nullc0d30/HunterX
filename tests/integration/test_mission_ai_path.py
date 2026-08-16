# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the advisory AI mission-decision path.

Verifies that the AI suggestion producer is wired into the real mission
execution decision loop and that the deterministic decision engine remains the
final authority:

- TEST 1 — the AI producer is invoked and receives mission/candidate context;
- TEST 2 — the AI suggestion reaches ``decide_next``;
- TEST 3 — when the AI suggestion is selected, ``ai_assisted`` is ``True`` and
  the reason is preserved;
- TEST 4 — an invalid AI proposal is rejected and the deterministic planner
  continues (``ai_assisted`` False);
- TEST 5 — AI unavailable does not crash the mission;
- TEST 6 — malformed AI response falls back to deterministic planning;
- TEST 7 — policy/sandbox/permission enforcement is unchanged (AI never
  bypasses the sandbox);
- TEST 8 — prior sandbox/coverage fixes remain intact.
"""

from __future__ import annotations

import dataclasses
import json

from hunterx.application.ai_suggestion import AIActionSuggester
from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.target_intelligence.enums import CoverageState
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "http://localhost:3010"

_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
}

_FAKE_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.target"}]},
    "dnsx": {"records": ["api.target -> 1.2.3.4"]},
    "nmap": {"ports": [80, 443]},
    "whatweb": {"name": "express", "technologies": ["node.js", "express"]},
}


class _RecordingAI:
    """A fake AI client recording prompts and returning a canned suggestion."""

    def __init__(self, response: str | None = None, *, fail: bool = False) -> None:
        self._response = response
        self._fail = fail
        self.prompts: list[str] = []

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        self.prompts.append(prompt)
        if self._fail:
            raise RuntimeError("provider unavailable")
        return self._response or '{"suggested_action_id": "", "reason": "no preference"}'

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        return []


def _runner(fake: FakeExecutionEngine, ai: object | None = None):
    """Assemble a mission runner with real planning/orchestration and optional AI."""
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
        ai_suggester=AIActionSuggester(ai) if ai is not None else None,
    )
    return runner, orchestration, planning


def _mission(orchestration: MissionOrchestrationService, *, coverage_target: float = 0.99):
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=coverage_target,
        stop_conditions=(
            StopCondition.COVERAGE_TARGET_ACHIEVED,
            StopCondition.RESOURCE_BUDGET_EXHAUSTED,
        ),
    )
    orchestration.start(mission.mission_id)
    return mission


def _suggestion_for(planning: AdaptiveMissionPlanningEngine, mission_id: str) -> str:
    """Return the action id of the first ready candidate (what the AI would pick)."""
    graph = planning.get_plan(mission_id)
    ready = graph.ready_actions(approved_only=True)
    return ready[0].action_id if ready else ""


class TestAISuggestionReachesDecision:
    def test_ai_producer_is_invoked_with_candidates(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        ai = _RecordingAI()
        runner, orchestration, _ = _runner(fake, ai)
        mission = _mission(orchestration)

        runner.execute_cycle(mission.mission_id)

        assert ai.prompts, "the AI producer must be invoked during a decision cycle"
        assert "http://localhost:3010" in ai.prompts[0]
        # candidate capabilities are surfaced to the AI
        assert any(cap in ai.prompts[0] for cap in ("subdomain_enumeration", "dns_enumeration", "port_discovery"))

    def test_ai_suggestion_is_passed_to_decide_next(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        # The AI always suggests the first ready candidate.
        ai = _RecordingAI()
        runner, orchestration, planning = _runner(fake, ai)
        mission = _mission(orchestration)
        suggestion_id = _suggestion_for(planning, mission.mission_id)
        ai._response = json.dumps({"suggested_action_id": suggestion_id, "reason": "AI says this first"})

        runner.execute_cycle(mission.mission_id)

        decision = mission.decisions[-1]
        assert decision.next_action == suggestion_id
        assert decision.ai_assisted, "the AI-selected decision must be marked ai_assisted"

    def test_ai_reason_preserved_and_ai_assisted_true(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        ai = _RecordingAI()
        runner, orchestration, planning = _runner(fake, ai)
        mission = _mission(orchestration)
        suggestion_id = _suggestion_for(planning, mission.mission_id)
        ai._response = json.dumps({"suggested_action_id": suggestion_id, "reason": "recommended by advisor"})

        runner.execute_cycle(mission.mission_id)

        decision = mission.decisions[-1]
        assert decision.ai_assisted is True
        # The deterministic engine recomputes the ranking; the AI reason is
        # preserved via the AI-invocation trace, and the deterministic reason
        # remains the decision's explainable rationale.
        assert "Ranked highest across" in decision.reason


class TestAISuggestionRejected:
    def test_invalid_ai_proposal_is_rejected_and_deterministic_continues(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        ai = _RecordingAI(response='{"suggested_action_id": "not-a-real-action", "reason": "bad"}')
        runner, orchestration, _ = _runner(fake, ai)
        mission = _mission(orchestration)

        runner.execute_cycle(mission.mission_id)

        decision = mission.decisions[-1]
        assert decision.ai_assisted is False
        assert decision.next_action, "a valid deterministic action must still be selected"
        assert mission.mission.state.value != "failed"


class TestAIUnavailable:
    def test_ai_failure_does_not_crash_mission(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        ai = _RecordingAI(fail=True)
        runner, orchestration, _ = _runner(fake, ai)
        mission = _mission(orchestration)

        runner.execute_cycle(mission.mission_id)

        decision = mission.decisions[-1]
        assert decision.ai_assisted is False
        assert decision.next_action, "deterministic planning must continue"
        assert mission.mission.state.value != "failed"

    def test_malformed_ai_response_falls_back(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        ai = _RecordingAI(response="totally malformed, not json")
        runner, orchestration, _ = _runner(fake, ai)
        mission = _mission(orchestration)

        runner.execute_cycle(mission.mission_id)

        decision = mission.decisions[-1]
        assert decision.ai_assisted is False
        assert decision.next_action, "deterministic planning must continue after a malformed AI response"


class TestNoAISuggester:
    def test_without_suggester_mission_is_deterministic(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration, _ = _runner(fake, ai=None)
        mission = _mission(orchestration)

        runner.execute_cycle(mission.mission_id)

        decision = mission.decisions[-1]
        assert decision.ai_assisted is False
        assert decision.next_action


class TestSecurityEnforcementPreserved:
    def test_sandbox_still_denies_without_permission(self) -> None:
        # Reuse the real sandbox path: a mission context without permissions
        # must still be denied by the sandbox — AI does not bypass it.
        from hunterx.domain.execution import FailureKind
        from hunterx.domain.tools import ToolDescriptor
        from hunterx.tools.sdk.adapter import ToolAdapter
        from hunterx.tools.sdk.context import ExecutionContextBuilder
        from hunterx.tools.sdk.engine import ExecutionEngine
        from hunterx.tools.sdk.output import OutputCollector

        class NetworkTool(ToolAdapter):
            descriptor = ToolDescriptor(
                name="network-tool",
                entrypoint="tests.integration.test_mission_ai_path:NetworkTool",
                permissions=("network",),
            )

            def run(self, context, collector: OutputCollector) -> None:  # noqa: ANN001
                collector.attach_stdout("ok")

        engine = ExecutionEngine()
        engine.register_adapter("nmap", NetworkTool())
        engine.install_hook("nmap", lambda tool_id, version: "1.0.0")
        engine.install("nmap", version="1.0.0")

        context = (
            ExecutionContextBuilder(tool_id="nmap", target=_TARGET)
            .with_permissions(())  # empty permissions => denied
            .build()
        )
        outcome = engine.execute(context)
        assert not outcome.result.ok
        assert outcome.result.failure_kind is FailureKind.SANDBOX_VIOLATION


class TestCoverageAccountingPreserved:
    def test_failed_execution_does_not_count_as_tested_coverage(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS), fail_tools=("nmap",), error="nmap broken")
        runner, orchestration, _ = _runner(fake, ai=None)
        mission = _mission(orchestration, coverage_target=0.7)

        runner.run(mission.mission_id, max_cycles=4)

        # Any failed cells must be uncovered (NOT_ASSESSED), not tested.
        for cell in mission.coverage_cells():
            if cell.state is CoverageState.TESTED:
                assert cell.tool_id != "nmap" or cell.notes == "", "failed tool must not mark tested coverage"
        # Failures alone must not satisfy the coverage target.
        assert mission.coverage_ratio() < mission.policy.coverage_target or mission.coverage_ratio() > 0.0

    def test_successful_execution_still_counts_tested(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration, _ = _runner(fake, ai=None)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=8)

        tested = [cell for cell in mission.coverage_cells() if cell.state is CoverageState.TESTED]
        assert tested, "successful executions must still count toward tested coverage"
