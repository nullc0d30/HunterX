# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for mission planning domain models and graph algorithms."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import (
    InvalidMissionPlanError,
    InvalidMissionRequestError,
)
from hunterx.domain.mission_planning import (
    ExecutionGraph,
    ExecutionNode,
    MissionPhase,
    MissionPhaseKind,
    MissionPlan,
    MissionPlanningStatus,
    MissionProfile,
    MissionRequest,
    MissionTemplate,
    MissionType,
)


class TestMissionPhase:
    def test_rejects_empty_id(self) -> None:
        with pytest.raises(InvalidMissionPlanError):
            MissionPhase(phase_id="", name="Recon", kind=MissionPhaseKind.RECONNAISSANCE)

    def test_rejects_negative_duration(self) -> None:
        with pytest.raises(InvalidMissionPlanError):
            MissionPhase(
                phase_id="recon",
                name="Recon",
                kind=MissionPhaseKind.RECONNAISSANCE,
                estimated_duration_seconds=-5,
            )

    def test_rejects_empty_dependency(self) -> None:
        with pytest.raises(InvalidMissionPlanError):
            MissionPhase(
                phase_id="recon",
                name="Recon",
                kind=MissionPhaseKind.RECONNAISSANCE,
                depends_on=("",),
            )


class TestMissionProfile:
    def _profile(self) -> MissionProfile:
        return MissionProfile(
            profile_id="p",
            name="Profile",
            phases=(
                MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),
                MissionPhase(phase_id="b", name="B", kind=MissionPhaseKind.ENUMERATION),
            ),
        )

    def test_requires_at_least_one_phase(self) -> None:
        with pytest.raises(InvalidMissionPlanError):
            MissionProfile(profile_id="p", name="Profile")

    def test_rejects_duplicate_phases(self) -> None:
        phase = MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE)
        with pytest.raises(InvalidMissionPlanError):
            MissionProfile(profile_id="p", name="Profile", phases=(phase, phase))

    def test_phase_lookup_and_support(self) -> None:
        profile = self._profile()
        assert profile.phase("a") is not None
        assert profile.phase("ghost") is None
        assert profile.supports(MissionType.EXTERNAL_PENTEST)  # empty = all


class TestMissionTemplate:
    def test_requires_profile(self) -> None:
        with pytest.raises(InvalidMissionPlanError):
            MissionTemplate(template_id="t", name="T", profile_id="")

    def test_accepts_override_phases(self) -> None:
        template = MissionTemplate(
            template_id="t",
            name="T",
            profile_id="p",
            phases_override=(
                MissionPhase(phase_id="custom", name="Custom", kind=MissionPhaseKind.CLEANUP),
            ),
        )
        assert template.phases_override is not None
        assert template.phases_override[0].phase_id == "custom"


class TestMissionRequest:
    def test_requires_targets(self) -> None:
        with pytest.raises(InvalidMissionRequestError):
            MissionRequest(
                profile_id="p",
                mission_type=MissionType.EXTERNAL_PENTEST,
                name="M",
            )

    def test_requires_name_and_profile(self) -> None:
        with pytest.raises(InvalidMissionRequestError):
            MissionRequest(
                profile_id="p",
                mission_type=MissionType.EXTERNAL_PENTEST,
                name="",
                targets=("a.com",),
            )
        with pytest.raises(InvalidMissionRequestError):
            MissionRequest(
                profile_id="",
                mission_type=MissionType.EXTERNAL_PENTEST,
                name="M",
                targets=("a.com",),
            )


class TestMissionPlan:
    def test_rejects_empty_name(self) -> None:
        with pytest.raises(InvalidMissionPlanError):
            MissionPlan(name="")

    def test_rejects_bad_progress(self) -> None:
        with pytest.raises(InvalidMissionPlanError):
            MissionPlan(name="M", progress=150.0)

    def test_progress_round_trip(self) -> None:
        plan = MissionPlan(name="M")
        plan.update_progress(42.5)
        assert plan.progress == 42.5

    def test_status_properties(self) -> None:
        assert MissionPlanningStatus.COMPLETED.is_terminal
        assert not MissionPlanningStatus.EXECUTING.is_terminal
        assert not MissionPlanningStatus.COMPLETED.is_active
        assert MissionPlanningStatus.EXECUTING.is_active


class TestExecutionGraph:
    def _nodes(self) -> tuple[ExecutionNode, ...]:
        return (
            ExecutionNode(node_id="n1", action="a", target="t", phase_kind=MissionPhaseKind.RECONNAISSANCE),
            ExecutionNode(
                node_id="n2",
                action="b",
                target="t",
                phase_kind=MissionPhaseKind.ENUMERATION,
                depends_on=("n1",),
            ),
            ExecutionNode(
                node_id="n3",
                action="c",
                target="t",
                phase_kind=MissionPhaseKind.ENUMERATION,
                depends_on=("n1",),
            ),
            ExecutionNode(
                node_id="n4",
                action="d",
                target="t",
                phase_kind=MissionPhaseKind.VALIDATION,
                depends_on=("n2", "n3"),
            ),
        )

    def test_build_and_lookup(self) -> None:
        graph = ExecutionGraph(nodes=self._nodes(), root_ids=("n1",))
        assert graph.node("n2") is not None
        assert graph.node("ghost") is None

    def test_rejects_unknown_dependency(self) -> None:
        nodes = (
            ExecutionNode(node_id="n1", action="a", target="t"),
            ExecutionNode(node_id="n2", action="b", target="t", depends_on=("ghost",)),
        )
        with pytest.raises(InvalidMissionPlanError, match="unknown node"):
            ExecutionGraph(nodes=nodes, root_ids=("n1",))

    def test_rejects_cycle(self) -> None:
        nodes = (
            ExecutionNode(node_id="n1", action="a", target="t", depends_on=("n2",)),
            ExecutionNode(node_id="n2", action="b", target="t", depends_on=("n1",)),
        )
        with pytest.raises(InvalidMissionPlanError, match="cycle"):
            ExecutionGraph(nodes=nodes, root_ids=("n1",))

    def test_rejects_duplicate_ids(self) -> None:
        nodes = (
            ExecutionNode(node_id="n1", action="a", target="t"),
            ExecutionNode(node_id="n1", action="b", target="t"),
        )
        with pytest.raises(InvalidMissionPlanError, match="more than once"):
            ExecutionGraph(nodes=nodes, root_ids=("n1",))

    def test_topological_order(self) -> None:
        graph = ExecutionGraph(nodes=self._nodes(), root_ids=("n1",))
        order = graph.topological_order()
        assert order[0] == "n1"
        assert set(order) == {"n1", "n2", "n3", "n4"}
        assert order.index("n2") < order.index("n4")
        assert order.index("n3") < order.index("n4")

    def test_parallel_groups(self) -> None:
        graph = ExecutionGraph(nodes=self._nodes(), root_ids=("n1",))
        groups = graph.parallel_groups()
        assert groups[0] == ["n1"]
        assert set(groups[1]) == {"n2", "n3"}
        assert groups[2] == ["n4"]

    def test_rollback_scope_and_recovery(self) -> None:
        graph = ExecutionGraph(nodes=self._nodes(), root_ids=("n1",))
        scope = graph.rollback_scope("n2")
        assert set(scope) == {"n2", "n4"}
        assert graph.recovery_path("n2") == scope

    def test_total_duration_uses_critical_path(self) -> None:
        nodes = (
            ExecutionNode(node_id="n1", action="a", target="t", estimated_duration_seconds=100),
            ExecutionNode(node_id="n2", action="b", target="t", depends_on=("n1",), estimated_duration_seconds=50),
            ExecutionNode(node_id="n3", action="c", target="t", depends_on=("n1",), estimated_duration_seconds=80),
            ExecutionNode(node_id="n4", action="d", target="t", depends_on=("n2", "n3"), estimated_duration_seconds=10),
        )
        graph = ExecutionGraph(nodes=nodes, root_ids=("n1",))
        # critical path: n1(100) -> n3(80) -> n4(10) = 190
        assert graph.total_duration_seconds() == 190

    def test_successors_and_nodes_in_phase(self) -> None:
        nodes = self._nodes()
        graph = ExecutionGraph(nodes=nodes, root_ids=("n1",))
        assert set(graph.successors("n1")) == {"n2", "n3"}
        assert [n.node_id for n in graph.nodes_in_phase("enum")] == []
