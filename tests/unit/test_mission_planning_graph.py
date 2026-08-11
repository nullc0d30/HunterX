# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the execution graph builder."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import InvalidMissionPlanError
from hunterx.domain.mission_planning import MissionPlan, MissionType
from hunterx.engines.mission_planning.graph import ExecutionGraphBuilder
from hunterx.engines.mission_planning.planner import MissionPlanner
from tests.framework.mission_planning import external_pentest_profile


def _planned(*, targets: tuple[str, ...] = ("a.com",), config: dict[str, object] | None = None) -> MissionPlan:
    plan = MissionPlan(
        name="M",
        profile_id="external-pentest",
        mission_type=MissionType.EXTERNAL_PENTEST,
        targets=targets,
        config=config or {},
    )
    return MissionPlanner().expand(plan, external_pentest_profile())


class TestExecutionGraphBuilder:
    def test_nodes_match_steps(self) -> None:
        plan = _planned()
        graph = ExecutionGraphBuilder().build(plan)
        assert len(graph.nodes) == plan.total_steps
        assert set(graph.root_ids) == {node.node_id for node in graph.nodes if not node.depends_on}

    def test_cross_phase_dependencies_wired(self) -> None:
        plan = _planned(targets=("a.com",))
        graph = ExecutionGraphBuilder().build(plan)
        enumeration = plan.phase("enumeration")
        assert enumeration is not None
        first_enumeration = enumeration.steps[0]
        recon = plan.phase("recon")
        assert recon is not None
        last_recon = recon.steps[-1]
        node = graph.node(first_enumeration.step_id)
        assert node is not None
        assert last_recon.step_id in node.depends_on

    def test_parallel_flag_carried(self) -> None:
        plan = _planned()
        graph = ExecutionGraphBuilder().build(plan)
        enumeration = plan.phase("enumeration")
        assert enumeration is not None
        node = graph.node(enumeration.steps[0].step_id)
        assert node is not None
        assert node.parallel is True
        recon = plan.phase("recon")
        assert recon is not None
        assert graph.node(recon.steps[0].step_id).parallel is False

    def test_conditions_mark_nodes_conditional(self) -> None:
        plan = _planned(config={"graph": {"conditions": {"validation": "has_findings"}}})
        graph = ExecutionGraphBuilder().build(plan)
        validation = plan.phase("validation")
        assert validation is not None
        node = graph.node(validation.steps[0].step_id)
        assert node is not None
        assert node.conditional is True
        assert node.condition == "has_findings"

    def test_retryable_marks_matching_nodes(self) -> None:
        plan = _planned(config={"graph": {"retryable": ["validation"]}})
        graph = ExecutionGraphBuilder().build(plan)
        validation = plan.phase("validation")
        assert validation is not None
        node = graph.node(validation.steps[0].step_id)
        assert node is not None
        assert node.retryable is True
        recon = plan.phase("recon")
        assert recon is not None
        assert graph.node(recon.steps[0].step_id).retryable is False

    def test_fallbacks_wire_last_to_first(self) -> None:
        plan = _planned(
            config={"graph": {"fallbacks": {"validation": "recon"}}},
            targets=("a.com",),
        )
        graph = ExecutionGraphBuilder().build(plan)
        validation = plan.phase("validation")
        assert validation is not None
        last_node = graph.node(validation.steps[-1].step_id)
        assert last_node is not None
        assert last_node.fallback_node_id == plan.phase("recon").steps[0].step_id

    def test_dag_is_acyclic_and_valid(self) -> None:
        plan = _planned()
        graph = ExecutionGraphBuilder().build(plan)
        assert len(graph.topological_order()) == len(graph.nodes)

    def test_phase_without_steps_produces_no_nodes(self) -> None:
        from hunterx.domain.mission_planning import MissionPhase, MissionPhaseKind, MissionProfile

        profile = MissionProfile(
            profile_id="empty",
            name="Empty",
            phases=(
                MissionPhase(phase_id="noop", name="Noop", kind=MissionPhaseKind.PLANNING),
            ),
        )
        plan = MissionPlan(
            name="M",
            profile_id="empty",
            mission_type=MissionType.CUSTOM,
            targets=("a.com",),
        )
        MissionPlanner().expand(plan, profile)
        with pytest.raises(InvalidMissionPlanError, match="no executable steps"):
            ExecutionGraphBuilder().build(plan)

    def test_dependency_edges_respect_topology(self) -> None:
        plan = _planned()
        graph = ExecutionGraphBuilder().build(plan)
        order = graph.topological_order()
        index = {node_id: i for i, node_id in enumerate(order)}
        for node in graph.nodes:
            for dependency in node.depends_on:
                assert index[dependency] < index[node.node_id]

    def test_rollback_scope_via_graph(self) -> None:
        plan = _planned()
        graph = ExecutionGraphBuilder().build(plan)
        recon = plan.phase("recon")
        assert recon is not None
        failed = recon.steps[-1].step_id
        scope = graph.rollback_scope(failed)
        # recon's last node feeds enumeration, which feeds validation/reporting
        assert failed in scope
        for phase in plan.phases:
            if phase.phase_id != "recon":
                assert any(step.step_id in scope for step in phase.steps)
