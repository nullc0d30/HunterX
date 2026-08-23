# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: RESOURCE_BUDGET_EXHAUSTED semantics and honest terminals.

The reference regression: a full_security_assessment terminated with
``stop_condition=resource_budget_exhausted`` while the persisted budget showed
``executions_used=16 / executions_budget=1000 / execution_remaining=984 /
execution_exhausted=false / time_exhausted=false``. A wired-but-rate-limited
OpenRouter model caused the runner to map "model attacker not exhausted" to
resource exhaustion.

Invariants enforced here:
  A/B: resource_budget_exhausted requires a real resource predicate and a
       non-empty exhausted_resource.
  C:   objectives_complete=true => completion contract satisfied.
  D:   completion-gate failure => objectives_complete=false.
  E:   AI 429 => deterministic fallback, never completion, never resource
       exhaustion.
  F:   planning_state=blocked => explicit blocked_reason.
  G:   phase reflects the final lifecycle state (blocked => reassessment).
  H:   a budget with 984 executions remaining is never exhausted.
"""

from __future__ import annotations

import dataclasses
import json

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
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


class _RateLimitedAI:
    """A fake AI client that always raises HTTP 429 (OpenRouter free-tier)."""

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:  # noqa: ARG002
        error = RuntimeError("openrouter: rate limited (HTTP 429) — retry later")
        error.retry_after = 15.0  # type: ignore[attr-defined]
        raise error

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        return []


def _runner(fake: FakeExecutionEngine, *, model_attacker: object | None = None):
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
        model_attacker=model_attacker,
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
            StopCondition.TIME_BUDGET_EXHAUSTED,
            StopCondition.OBJECTIVES_COMPLETE,
        ),
    )
    orchestration.start(mission.mission_id)
    return mission


class TestResourceExhaustionIsTruthful:
    def test_budget_with_984_remaining_is_not_exhausted(self) -> None:
        # TEST 1 / INVARIANT H: 16/1000 executions -> execution_exhausted False.
        _, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        mission.budget.executions_used = 16
        mission.budget.executions_budget = 1000
        assert mission.budget.execution_exhausted is False
        assert mission.budget.execution_remaining == 984
        assert mission.budget.time_exhausted is False
        assert mission.budget.exhausted is False

    def test_explicit_resource_stop_without_exhaustion_is_downgraded(self) -> None:
        # INVARIANT A: an explicit resource_budget_exhausted with no exhausted
        # resource is a lie and must be downgraded to an honest terminal.
        _, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        orchestration.finalize(mission.mission_id, stop_condition=StopCondition.RESOURCE_BUDGET_EXHAUSTED)
        outcome = orchestration.get(mission.mission_id).outcome
        assert outcome.stop_condition != StopCondition.RESOURCE_BUDGET_EXHAUSTED.value
        assert outcome.stop_condition in (StopCondition.NO_ACTIONABLE_WORK.value, StopCondition.BLOCKED.value)
        assert outcome.exhausted_resource == ""

    def test_actual_execution_budget_exhaustion_is_reported(self) -> None:
        # TEST 4 / INVARIANT B: real execution exhaustion -> resource stop with
        # the resource identified.
        _, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        mission.budget.executions_used = mission.budget.executions_budget
        orchestration.finalize(mission.mission_id)
        outcome = orchestration.get(mission.mission_id).outcome
        assert outcome.stop_condition == StopCondition.RESOURCE_BUDGET_EXHAUSTED.value
        assert outcome.exhausted_resource == "executions"

    def test_actual_time_budget_exhaustion_is_reported(self) -> None:
        # TEST 5: wall-clock exhaustion is TIME_BUDGET_EXHAUSTED with the
        # exhausted resource identified (never conflated with execution budget).
        _, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        mission.budget.time_budget_seconds = 10
        mission.budget.time_used_seconds = 20
        assert mission.budget.time_exhausted is True
        orchestration.finalize(mission.mission_id)
        outcome = orchestration.get(mission.mission_id).outcome
        assert outcome.stop_condition == StopCondition.TIME_BUDGET_EXHAUSTED.value
        assert outcome.exhausted_resource == "time"

    def test_invariant_resource_stop_implies_exhaustion(self) -> None:
        # INVARIANT A/B across a real run with a rate-limited model: the run
        # must never emit resource_budget_exhausted with 984 executions left.
        from hunterx.application.model_attacker import ModelAttacker
        from hunterx.domain.model_attacker.reasoner import ModelReasoner

        attacker = ModelAttacker(ModelReasoner(_RateLimitedAI()), max_cycles=8)
        runner, orchestration = _runner(
            FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)),
            model_attacker=attacker,
        )
        mission = _mission(orchestration)
        runner.run(mission.mission_id, max_cycles=24, max_idle_cycles=6)
        mission = orchestration.get(mission.mission_id)
        outcome = mission.outcome
        assert outcome is not None
        # The budget is genuinely not exhausted (16/1000 in the regression).
        assert mission.budget.execution_exhausted is False
        assert outcome.stop_condition != StopCondition.RESOURCE_BUDGET_EXHAUSTED.value
        assert outcome.stop_condition != StopCondition.TIME_BUDGET_EXHAUSTED.value
        assert outcome.exhausted_resource == ""
        # It is an explicit blocked terminal with a truthful reason.
        assert outcome.stop_condition in (
            StopCondition.AI_UNAVAILABLE.value,
            StopCondition.NO_ACTIONABLE_WORK.value,
            StopCondition.BLOCKED.value,
        )


class TestNoFalseCompletion:
    def test_incomplete_assessment_is_not_completed_or_reporting(self) -> None:
        # TEST 2 / INVARIANT C/D: completion gate fails -> not completed.
        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        # Force an open, unclassified actionable hypothesis so the contract
        # gate fails, but leave plenty of budget.
        from hunterx.domain.mission_orchestration.enums import HypothesisState
        from hunterx.domain.mission_orchestration.models import MissionHypothesis

        mission.upsert_hypothesis(
            MissionHypothesis(
                hypothesis_id="H-ACTIONABLE",
                mission_id=mission.mission_id,
                statement="q may be sql-injection",
                state=HypothesisState.PROPOSED,
                priority=0.9,
                provenance={"vulnerability_class": "sql-injection", "endpoint": _TARGET, "parameter": "q"},
            )
        )
        runner.run(mission.mission_id, max_cycles=16)
        mission = orchestration.get(mission.mission_id)
        outcome = mission.outcome
        assert outcome.objectives_complete is False
        assert outcome.stop_condition != StopCondition.COVERAGE_TARGET_ACHIEVED.value
        assert mission.mission.state.value == "blocked"
        assert outcome.blocked_reason, "a blocked terminal must carry an explicit reason"
        # Phase must reflect the blocked lifecycle, not stale reconnaissance.
        assert mission.current_phase.value != "reconnaissance"

    def test_planner_with_no_actionable_work_is_no_actionable_work(self) -> None:
        # TEST 3: completion gate fails and planner has no actionable work ->
        # explicit no-actionable-work terminal, NOT resource exhaustion.
        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        # No hypotheses at all and no ready work -> contract unmet (active
        # testing/browser gates) but nothing runnable remains.
        runner.run(mission.mission_id, max_cycles=6)
        mission = orchestration.get(mission.mission_id)
        outcome = mission.outcome
        assert outcome.objectives_complete is False
        assert outcome.stop_condition in (
            StopCondition.NO_ACTIONABLE_WORK.value,
            StopCondition.BLOCKED.value,
        )
        assert outcome.stop_condition != StopCondition.RESOURCE_BUDGET_EXHAUSTED.value
        assert mission.budget.execution_exhausted is False

    def test_deferred_hypotheses_do_not_masquerade_as_completion(self) -> None:
        # TEST 7: 67 deferred hypotheses with an unmet completion gate must not
        # look complete.
        runner, orchestration = _runner(FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        from hunterx.domain.mission_orchestration.enums import HypothesisState
        from hunterx.domain.mission_orchestration.models import MissionHypothesis

        for index in range(67):
            mission.upsert_hypothesis(
                MissionHypothesis(
                    hypothesis_id=f"H-DEFER-{index}",
                    mission_id=mission.mission_id,
                    statement=f"recon fact {index}",
                    state=HypothesisState.DEFERRED,
                    priority=0.5,
                    provenance={"deferred_reason": "no runnable action", "technology": f"t{index}"},
                )
            )
        runner.run(mission.mission_id, max_cycles=6)
        mission = orchestration.get(mission.mission_id)
        outcome = mission.outcome
        assert outcome.objectives_complete is False
        assert outcome.stop_condition != StopCondition.COVERAGE_TARGET_ACHIEVED.value
        assert outcome.stop_condition != StopCondition.OBJECTIVES_COMPLETE.value
        assert mission.budget.execution_exhausted is False


class TestOpenRouter429DoesNotExhaust:
    def test_429_fallback_never_emits_resource_exhaustion(self) -> None:
        # TEST 6 / INVARIANT E: 429 -> cooldown + deterministic fallback,
        # mission continues, never resource exhaustion, never completion.
        from hunterx.application.ai_suggestion import AIActionSuggester
        from hunterx.application.model_attacker import ModelAttacker
        from hunterx.domain.model_attacker.reasoner import ModelReasoner

        attacker = ModelAttacker(ModelReasoner(_RateLimitedAI()), max_cycles=6)
        runner, orchestration = _runner(
            FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)),
            model_attacker=attacker,
        )
        # Also wire the advisory AI suggester so 429s flow through it too.
        runner._ai_suggester = AIActionSuggester(  # noqa: SLF001  # test wiring
            _RateLimitedAI(), provider="openrouter", model="nvidia/nemotron:free", min_interval_s=0.0
        )
        mission = _mission(orchestration)
        runner.run(mission.mission_id, max_cycles=16, max_idle_cycles=6)
        mission = orchestration.get(mission.mission_id)
        outcome = mission.outcome
        assert mission.budget.execution_exhausted is False
        assert outcome.stop_condition != StopCondition.RESOURCE_BUDGET_EXHAUSTED.value
        assert outcome.stop_condition != StopCondition.COVERAGE_TARGET_ACHIEVED.value
        assert outcome.stop_condition != StopCondition.OBJECTIVES_COMPLETE.value
        # The deterministic side ran real executions (the mission continued).
        assert mission.budget.executions_used > 0


class TestToolFailureDoesNotExhaust:
    def test_tool_failure_is_not_resource_exhaustion(self) -> None:
        # TEST 9: a failed tool (exit code 1) must not become resource
        # exhaustion unless the resource contract explicitly says so.
        from hunterx.application.model_attacker import ModelAttacker
        from hunterx.domain.model_attacker.reasoner import ModelReasoner

        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS), fail_tools=("subfinder",), error="Failed to start tool binary 'subfinder'")
        runner, orchestration = _runner(fake, model_attacker=ModelAttacker(ModelReasoner(_RateLimitedAI()), max_cycles=6))
        mission = _mission(orchestration)
        runner.run(mission.mission_id, max_cycles=12, max_idle_cycles=6)
        mission = orchestration.get(mission.mission_id)
        outcome = mission.outcome
        assert outcome.stop_condition != StopCondition.RESOURCE_BUDGET_EXHAUSTED.value
        assert mission.budget.execution_exhausted is False
        assert outcome.objectives_complete is False


class TestReportInternalConsistency:
    def test_report_json_is_internally_consistent(self) -> None:
        # TEST 10 / INVARIANT A/B/F/G: status, planning_state, phase,
        # stop_condition, exhausted_resource and budget flags must agree.
        from hunterx.application.model_attacker import ModelAttacker
        from hunterx.domain.model_attacker.reasoner import ModelReasoner

        runner, orchestration = _runner(
            FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)),
            model_attacker=ModelAttacker(ModelReasoner(_RateLimitedAI()), max_cycles=6),
        )
        mission = _mission(orchestration)
        runner.run(mission.mission_id, max_cycles=16, max_idle_cycles=6)
        mission = orchestration.get(mission.mission_id)
        outcome = mission.outcome
        state = mission.to_dict()
        payload = json.loads(json.dumps(state))

        # A resource stop always implies a real predicate and a resource name.
        if outcome.stop_condition == StopCondition.RESOURCE_BUDGET_EXHAUSTED.value:
            assert mission.budget.execution_exhausted or mission.budget.time_exhausted
            assert outcome.exhausted_resource in ("executions", "time")
        else:
            assert outcome.exhausted_resource == ""
        # objectives_complete must match the contract; a blocked terminal has a reason.
        assert outcome.objectives_complete == bool(payload["outcome"].get("objectives_complete"))
        if mission.mission.state.value == "blocked":
            assert outcome.blocked_reason
        assert outcome.objectives_complete is False


__all__ = []
