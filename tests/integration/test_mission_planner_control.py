# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 2 — planner-loop / action-dedup / termination repair regression tests.

Pins the required control flow:

1. Same target + same tool + materially identical input is not executed
   indefinitely (action identity / replay protection).
2. New evidence (a new endpoint, parameter, technology, asset or hypothesis)
   legitimately permits a repeated tool.
3. The planner invalidates a repeated branch and transitions to another
   actionable branch.
4. A mission cannot report successful completion while
   ``objectives_complete`` is false (termination distinguishes
   completed/blocked/exhausted/failed/cancelled).
5. Existing valid missions still terminate correctly (deterministic,
   finalized, truthful outcome).
"""

from __future__ import annotations

import dataclasses

import pytest

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.enums import ActionStatus, ReplanTrigger
from hunterx.domain.adaptive_mission_planning.graph import AdaptiveExecutionGraph
from hunterx.domain.adaptive_mission_planning.models import ActionNode
from hunterx.domain.adaptive_mission_planning.replan import ReplanningEngine, ReplanSignal
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "technology_fingerprint": ("whatweb",),
    "vulnerability_scanning": ("nuclei",),
    "dependency_check": ("osv-scanner",),
}


@pytest.fixture(scope="module")
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


def _orchestration(planning: AdaptiveMissionPlanningEngine | None = None):
    orchestrator = MissionOrchestrator(planning=planning)
    return MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )


def _planning() -> AdaptiveMissionPlanningEngine:
    return AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=dict(_CANDIDATES),
        ),
    )


def _runner(fake: FakeExecutionEngine, *, target: str, objective: str = "vulnerability_discovery"):
    planning = _planning()
    orchestration = _orchestration(planning)
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=fake,
    )
    mission = orchestration.create_mission(objective=objective, target=target)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, planning, mission.mission_id


def _nuclei_payload(target: str) -> dict[str, object]:
    return {
        "candidates": [
            {
                "vulnerability_class": "sql-injection",
                "endpoint": f"{target}/vuln/search",
                "parameter": "q",
                "severity": "medium",
            }
        ],
        "count": 1,
    }


class TestActionIdentity:
    def test_identity_distinguishes_material_state(self) -> None:
        base = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/a",
            hypothesis_id="H1",
            selected_tool="nuclei",
            provenance={"parameter": "q"},
        )
        same = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/a",
            hypothesis_id="H1",
            selected_tool="nuclei",
            provenance={"parameter": "q"},
        )
        different_tool = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/a",
            hypothesis_id="H1",
            selected_tool="nikto",
            provenance={"parameter": "q"},
        )
        different_parameter = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/a",
            hypothesis_id="H1",
            selected_tool="nuclei",
            provenance={"parameter": "name"},
        )
        different_hypothesis = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/a",
            hypothesis_id="H2",
            selected_tool="nuclei",
            provenance={"parameter": "q"},
        )
        different_asset = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/b",
            hypothesis_id="H1",
            selected_tool="nuclei",
            provenance={"parameter": "q"},
        )
        assert base.identity_key() == same.identity_key()
        assert base.identity_key() != different_tool.identity_key()
        assert base.identity_key() != different_parameter.identity_key()
        assert base.identity_key() != different_hypothesis.identity_key()
        assert base.identity_key() != different_asset.identity_key()

    def test_graph_detects_identical_and_completed_replays(self) -> None:
        graph = AdaptiveExecutionGraph()
        first = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/a",
            hypothesis_id="H1",
            selected_tool="nuclei",
            status=ActionStatus.COMPLETED,
        )
        graph.add_action(first)
        replay = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/a",
            hypothesis_id="H1",
            selected_tool="nuclei",
            status=ActionStatus.APPROVED,
        )
        fresh = ActionNode(
            capability="vulnerability_scanning",
            asset="https://t/b",
            hypothesis_id="H2",
            selected_tool="nuclei",
            status=ActionStatus.APPROVED,
        )
        assert graph.has_identical_action(replay) is True
        assert graph.has_identical_action(fresh) is False
        assert graph.completed_identical(replay) == [first]
        assert graph.completed_identical(fresh) == []

    def test_replan_engine_refuses_identical_replay(self) -> None:
        graph = AdaptiveExecutionGraph()
        engine = ReplanningEngine()
        signal = lambda hypothesis_id: ReplanSignal(  # noqa: E731
            ReplanTrigger.NEW_HYPOTHESIS_CREATED,
            detail={"hypothesis_id": hypothesis_id, "capability": "vulnerability_scanning"},
        )
        first = engine.build_delta(
            mission_id="m",
            graph=graph,
            signal=signal("H1"),
            current_version=1,
            reason="first hypothesis",
        )
        assert not first.is_empty()
        node = next(c.node for c in first.changes if c.node is not None)
        graph.add_action(node)
        # The identical hypothesis signal must not re-add the same action.
        replay = engine.build_delta(
            mission_id="m",
            graph=graph,
            signal=signal("H1"),
            current_version=2,
            reason="duplicate hypothesis signal",
        )
        assert replay.is_empty(), "a materially identical action must not be re-added"
        # A genuinely new hypothesis is still scheduled.
        fresh = engine.build_delta(
            mission_id="m",
            graph=graph,
            signal=signal("H2"),
            current_version=2,
            reason="new hypothesis",
        )
        assert not fresh.is_empty()
        assert any(
            change.kind.value == "add_action"
            and change.node is not None
            and change.node.hypothesis_id == "H2"
            for change in fresh.changes
        )


class TestPlannerLoop:
    def test_same_tool_same_input_does_not_execute_indefinitely(self) -> None:
        """Test 1: materially identical nuclei work does not loop forever."""
        target = "https://example.com"
        fake = FakeExecutionEngine(outputs={"nuclei": _nuclei_payload(target)})
        runner, orchestration, planning, mission_id = _runner(fake, target=target)

        result = runner.run(mission_id, max_cycles=30)
        # A non-loopback target with actionable (unprobeable) hypotheses
        # terminates honestly as blocked; the plan is exhausted either way.
        assert result["planning_state"] in ("completed", "blocked")

        nuclei_calls = [call for call in fake.calls if call.tool_id == "nuclei"]
        # The tool is never re-executed with the same identity: executions are
        # bounded by the number of distinct actions, not by the cycle budget.
        assert len(nuclei_calls) <= 3, f"nuclei re-ran {len(nuclei_calls)} times"
        graph = planning.get_plan(mission_id)
        nuclei_actions = [
            a for a in graph.actions.values() if a.capability == "vulnerability_scanning"
        ]
        identities = [a.identity_key() for a in nuclei_actions if not a.status.is_terminal]
        # Every pending nuclei action is distinct (replay protection) — and
        # none of them is a replay of an already-completed identical action.
        assert len(identities) == len(set(identities))
        for action in nuclei_actions:
            if not action.status.is_terminal:
                assert graph.completed_identical(action) == []

    def test_new_evidence_legitimately_permits_repeated_tool(self) -> None:
        """Test 2: a new hypothesis/endpoint schedules a new (distinct) action."""
        planning = _planning()
        orchestration = _orchestration(planning)
        target = "https://example.com"
        mission = orchestration.create_mission(objective="vulnerability_discovery", target=target)
        orchestration.start(mission.mission_id)
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs={}),
        )
        graph = planning.get_plan(mission.mission_id)

        def _ingest(endpoint: str) -> None:
            raw = {
                "observation_type": "vulnerability",
                "content": {
                    "candidates": [
                        {
                            "vulnerability_class": "sql-injection",
                            "endpoint": endpoint,
                            "parameter": "q",
                            "severity": "medium",
                        }
                    ],
                    "count": 1,
                },
                "confidence": 0.5,
            }
            ingested = orchestration.ingest_result(
                mission.mission_id,
                tool_id="nuclei",
                asset_key=target,
                raw=raw,
            )
            # The runner replans from the observation (the same step that
            # schedules hypothesis-bound validation actions in the live loop).
            runner._replan_from_observation(  # noqa: SLF001
                mission.mission_id,
                capability="vulnerability_scanning",
                raw=raw,
                observation=ingested,
            )

        def _bound_ids() -> list[str]:
            return [
                a.hypothesis_id
                for a in graph.actions.values()
                if a.hypothesis_id
                and a.capability in ("vulnerability_scanning", "sql_injection")
            ]

        _ingest(f"{target}/vuln/a")
        first_ids = _bound_ids()
        assert first_ids, "a new hypothesis must schedule a validation action"

        _ingest(f"{target}/vuln/b")
        second_ids = _bound_ids()
        assert len(second_ids) > len(first_ids), "new evidence must add a new action"
        assert second_ids[0] != second_ids[1]

        # Re-ingesting the SAME evidence does NOT add a third action.
        _ingest(f"{target}/vuln/a")
        third_ids = _bound_ids()
        assert len(third_ids) == len(second_ids)

    def test_planner_invalidates_replay_and_selects_another_branch(self) -> None:
        """Test 3: a repeated branch is superseded; another action is returned."""
        planning = _planning()
        orchestration = _orchestration(planning)
        target = "https://example.com"
        mission = orchestration.create_mission(objective="vulnerability_discovery", target=target)
        orchestration.start(mission.mission_id)
        graph = planning.get_plan(mission.mission_id)

        completed = ActionNode(
            mission_id=mission.mission_id,
            capability="vulnerability_scanning",
            asset=f"{target}/a",
            hypothesis_id="H1",
            selected_tool="nuclei",
            status=ActionStatus.COMPLETED,
        )
        replay = ActionNode(
            mission_id=mission.mission_id,
            capability="vulnerability_scanning",
            asset=f"{target}/a",
            hypothesis_id="H1",
            selected_tool="nuclei",
            status=ActionStatus.APPROVED,
        )
        other = ActionNode(
            mission_id=mission.mission_id,
            capability="technology_fingerprint",
            asset=target,
            selected_tool="whatweb",
            status=ActionStatus.APPROVED,
        )
        graph.add_action(completed)
        graph.add_action(replay)
        graph.add_action(other)

        mission = orchestration.get(mission.mission_id)
        candidates = orchestration._engine.orchestrator._candidates_from_plan(mission)  # noqa: SLF001
        candidate_ids = [c.action_id for c in candidates]
        assert replay.action_id not in candidate_ids, "a replay must not be re-selected"
        assert other.action_id in candidate_ids, "the planner must move to another branch"
        assert replay.status is ActionStatus.SUPERSEDED


class TestTermination:
    def test_mission_cannot_report_completed_when_objectives_incomplete(self) -> None:
        """Test 4: incomplete objectives are never silently converted to success."""
        target = "https://example.com"
        fake = FakeExecutionEngine(outputs={"nuclei": _nuclei_payload(target)})
        runner, orchestration, _, mission_id = _runner(fake, target=target)

        result = runner.run(mission_id, max_cycles=30)
        mission = orchestration.get(mission_id)
        outcome = mission.outcome

        assert outcome is not None
        assert outcome.objectives_complete is False
        assert outcome.stop_condition != "objectives_complete"
        assert outcome.stop_condition in (
            "blocked",
            "no_actionable_work",
            "resource_budget_exhausted",
            "time_budget_exhausted",
        )
        assert result["status"] != "completed"
        assert result["status"] in ("blocked", "exhausted", "failed", "cancelled")

    def test_explicit_success_stop_reports_completed(self) -> None:
        """A genuinely completed mission still reports completed truthfully."""
        planning = _planning()
        orchestration = _orchestration(planning)
        mission = orchestration.create_mission(objective="vulnerability_discovery", target="https://example.com")
        orchestration.start(mission.mission_id)
        orchestration.finalize(mission.mission_id, stop_condition=StopCondition.OBJECTIVES_COMPLETE)
        mission = orchestration.get(mission.mission_id)
        assert mission.outcome is not None
        assert mission.outcome.objectives_complete is True
        assert mission.outcome.stop_condition == "objectives_complete"

    def test_finalize_default_is_truthful_when_no_stop_fired(self) -> None:
        """No genuine stop + incomplete objectives => blocked, never success."""
        planning = _planning()
        orchestration = _orchestration(planning)
        mission = orchestration.create_mission(objective="vulnerability_discovery", target="https://example.com")
        orchestration.start(mission.mission_id)
        orchestration.finalize(mission.mission_id)
        mission = orchestration.get(mission.mission_id)
        assert mission.outcome is not None
        assert mission.outcome.stop_condition == "blocked"
        assert mission.outcome.objectives_complete is False
