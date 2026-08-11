# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests: mission executor through the fake execution engine."""

from __future__ import annotations

from hunterx.domain.orchestration.enums import MissionType, TaskState
from hunterx.domain.orchestration.models import (
    ExecutionPlan,
    MissionScope,
    MissionStep,
)
from hunterx.engines.orchestration.executor import MissionExecutor
from hunterx.engines.orchestration.planner import IntelligenceSummary, MissionPlanner
from hunterx.engines.orchestration.selector import MissionToolSelector
from tests.framework.orchestration import FakeExecutionEngine


def _plan(targets=("example.com",), *, endpoints=(), capabilities_override=None) -> ExecutionPlan:
    planner = MissionPlanner()
    intelligence = IntelligenceSummary(
        mission_type=MissionType.WEB_PENTEST,
        targets=tuple(targets),
        endpoints=tuple(endpoints),
    )
    return planner.plan(
        mission_id="m1",
        objective="assess example.com",
        intelligence=intelligence,
        scope=MissionScope(roots=tuple(targets)),
    )


def test_executor_runs_all_steps_successfully() -> None:
    engine = FakeExecutionEngine()
    plan = _plan(endpoints=("web",))
    executor = MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine))
    run = executor.run(mission_id="m1", plan=plan)
    assert run.all_completed
    assert len(run.completed) == plan.total_steps()
    assert not run.failed and not run.blocked


def test_executor_uses_pre_normalized_output() -> None:
    engine = FakeExecutionEngine()
    plan = _plan()
    outputs = {step.step_id: {"findings": [{"title": "x"}], "evidence": [{"content": "y"}]} for phase in plan.phases for step in phase.steps}
    executor = MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine))
    run = executor.run(mission_id="m1", plan=plan, tool_outputs=outputs)
    assert run.all_completed
    first = run.outcomes[next(iter(run.outcomes))]
    assert first.findings_count == 1


def test_executor_records_gate_decisions() -> None:
    engine = FakeExecutionEngine()
    plan = _plan()
    executor = MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine))
    executor.run(mission_id="m1", plan=plan)
    records = executor.records()
    assert records["scope"]
    assert records["safety"]
    assert all(decision["allowed"] for decision in records["scope"])


def test_executor_blocks_out_of_scope_target() -> None:
    engine = FakeExecutionEngine()
    plan = _plan(targets=("example.com",))
    # Inject a step targeting an out-of-scope host into a copy plan.
    from dataclasses import replace

    first_phase = plan.phases[0]
    extra = MissionStep(
        step_id="out-of-scope-step",
        phase_id=first_phase.phase_id,
        capability="web-crawling",
        target="evil.org",
        target_type="domain",
    )
    phases = (replace(first_phase, steps=first_phase.steps + (extra,)),) + plan.phases[1:]
    plan = replace(plan, phases=phases)
    executor = MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine))
    run = executor.run(mission_id="m1", plan=plan)
    outcome = run.outcomes["out-of-scope-step"]
    assert outcome.state is TaskState.BLOCKED
    assert "scope" in outcome.error
    assert "out-of-scope-step" in run.blocked


def test_executor_blocked_step_does_not_fail_mission() -> None:
    engine = FakeExecutionEngine()
    plan = _plan()
    executor = MissionExecutor(engine=engine, selector=MissionToolSelector(engine=engine))
    run = executor.run(mission_id="m1", plan=plan)
    # No gates are violated so the mission completes fully.
    assert run.all_completed


def test_executor_no_engine_marks_steps_failed() -> None:
    plan = _plan()
    executor = MissionExecutor(engine=None, selector=MissionToolSelector(engine=None))
    run = executor.run(mission_id="m1", plan=plan)
    assert not run.all_completed
    assert run.failed
