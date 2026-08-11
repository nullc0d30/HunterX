# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: mission planner and dependency graph."""

from __future__ import annotations

import pytest

from hunterx.domain.orchestration.enums import MissionPhaseKind, MissionType
from hunterx.engines.orchestration.graph import MissionDependencyGraph
from hunterx.engines.orchestration.planner import IntelligenceSummary, MissionPlanner


def _plan(planner, *, mission_type=MissionType.WEB_PENTEST, endpoints=(), technologies=(), targets=("example.com",)):
    intelligence = IntelligenceSummary(
        mission_type=mission_type,
        endpoints=tuple(endpoints),
        technologies=tuple(technologies),
        targets=tuple(targets),
    )
    return planner.plan(mission_id="m1", objective="assess example.com", intelligence=intelligence)


def test_plan_produces_phases_and_steps() -> None:
    planner = MissionPlanner()
    plan = _plan(planner)
    assert plan.total_steps() > 0
    kinds = [phase.kind for phase in plan.phases]
    assert MissionPhaseKind.RECONNAISSANCE in kinds
    assert MissionPhaseKind.TECHNOLOGY_DISCOVERY in kinds
    assert MissionPhaseKind.REPORTING in kinds


def test_plan_is_adaptive_to_web_surface() -> None:
    planner = MissionPlanner()
    plan = _plan(planner, endpoints=("web", "http"))
    kinds = {phase.kind for phase in plan.phases}
    assert MissionPhaseKind.ATTACK_SURFACE_MAPPING in kinds
    capabilities = {step.capability for phase in plan.phases for step in phase.steps}
    assert "web-crawling" in capabilities


def test_plan_is_adaptive_to_api_surface() -> None:
    planner = MissionPlanner()
    plan = _plan(planner, endpoints=("api",))
    capabilities = {step.capability for phase in plan.phases for step in phase.steps}
    assert "api-discovery" in capabilities


def test_plan_skips_irrelevant_surface() -> None:
    planner = MissionPlanner()
    plan = _plan(planner, endpoints=())
    capabilities = {step.capability for phase in plan.phases for step in phase.steps}
    assert "web-crawling" not in capabilities
    assert "api-discovery" not in capabilities


def test_plan_adds_validation_when_vulnerabilities() -> None:
    planner = MissionPlanner()
    intelligence = IntelligenceSummary(
        mission_type=MissionType.VULNERABILITY_ASSESSMENT,
        targets=("example.com",),
        vulnerabilities=("CVE-2024-1234",),
    )
    plan = planner.plan(mission_id="m1", objective="assess", intelligence=intelligence)
    kinds = {phase.kind for phase in plan.phases}
    assert MissionPhaseKind.VULNERABILITY_HYPOTHESIS in kinds
    assert MissionPhaseKind.SAFE_VALIDATION in kinds


def test_target_steps_chained_per_target() -> None:
    planner = MissionPlanner()
    plan = _plan(planner, targets=("a.com", "b.com"))
    recon = next(phase for phase in plan.phases if phase.kind is MissionPhaseKind.RECONNAISSANCE)
    targets = {step.target for step in recon.steps}
    assert targets == {"a.com", "b.com"}


def test_graph_ready_and_topological_order() -> None:
    planner = MissionPlanner()
    plan = _plan(planner)
    graph = MissionDependencyGraph(plan)
    assert not graph.has_cycle()
    order = graph.topological_order()
    assert len(order) == plan.total_steps()
    assert len(set(order)) == len(order)
    root = set(graph.root_ids())
    assert root
    assert set(graph.ready(set())) == root


def test_graph_dependency_progression() -> None:
    planner = MissionPlanner()
    plan = _plan(planner, targets=("a.com",))
    graph = MissionDependencyGraph(plan)
    completed: set[str] = set()
    steps_run: list[str] = []
    while True:
        ready = graph.ready(completed)
        if not ready:
            break
        for step_id in ready:
            steps_run.append(step_id)
            completed.add(step_id)
    assert len(steps_run) == plan.total_steps()


def test_graph_parallel_waves() -> None:
    planner = MissionPlanner()
    plan = _plan(planner, targets=("a.com", "b.com"))
    graph = MissionDependencyGraph(plan)
    waves = graph.parallel_waves()
    assert waves
    assert all(len(wave) >= 1 for wave in waves)
    assert len({step_id for wave in waves for step_id in wave}) == plan.total_steps()


def test_graph_detects_unknown_dependency() -> None:
    planner = MissionPlanner()
    plan = _plan(planner)
    graph = MissionDependencyGraph(plan)
    errors = graph.validate()
    assert errors == []


def test_graph_cycle_detection() -> None:
    from hunterx.domain.orchestration.models import ExecutionPlan, MissionStep, Phase

    step_a = MissionStep(step_id="a", phase_id="p", capability="x", target="t", depends_on=("b",))
    step_b = MissionStep(step_id="b", phase_id="p", capability="x", target="t", depends_on=("a",))
    plan = ExecutionPlan(
        plan_id="p1",
        mission_id="m1",
        objective="x",
        phases=(Phase(phase_id="p", name="p", steps=(step_a, step_b)),),
    )
    graph = MissionDependencyGraph(plan)
    assert graph.has_cycle()
    with pytest.raises(ValueError):
        graph.topological_order()
