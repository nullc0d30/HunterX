# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the offensive tool orchestration capability.

End-to-end scenario: through the assembled platform, create a mission, plan it
into an execution plan, run the full OBSERVE → DECIDE → PLAN → EXECUTE → LEARN
→ REPLAN → VERIFY loop, and verify deterministic outcomes against the golden
mission datasets: final mission state, planned phases/capabilities, scope
enforcement, coverage and quality.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.orchestration.enums import MissionPhaseKind, MissionState, MissionType
from hunterx.domain.orchestration.models import MissionScope
from hunterx.engines.orchestration.planner import IntelligenceSummary
from hunterx.platform.assembler import build_platform

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "orchestration"


def _load_scenarios() -> list[dict]:
    with (GOLDEN / "scenarios.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)["scenarios"]


def _intelligence(scenario: dict) -> IntelligenceSummary:
    """Build an intelligence summary from a golden scenario fixture."""
    return IntelligenceSummary(
        mission_type=MissionType(scenario["mission_type"]),
        targets=tuple(scenario["targets"]),
        technologies=tuple(scenario.get("technologies", ())),
        endpoints=tuple(scenario.get("endpoints", ())),
        providers=tuple(scenario.get("providers", ())),
        vulnerabilities=tuple(scenario.get("vulnerabilities", ())),
    )


def _tool_outputs(plan) -> dict[str, dict]:
    """Deterministic canonical outputs for every planned step."""
    return {
        step.step_id: {"findings": [{"title": "ok"}], "evidence": [{"content": "ok"}]}
        for phase in plan.phases
        for step in phase.steps
    }


class TestOrchestrationAcceptance:
    def test_golden_scenarios_produce_expected_outcomes(self) -> None:
        platform = build_platform()
        api = platform.offensive_orchestration
        for scenario in _load_scenarios():
            scope_roots = tuple(scenario.get("scope_roots", scenario.get("targets", ())))
            mission = api.create_mission(
                objective=scenario["objective"],
                mission_type=MissionType(scenario["mission_type"]),
                scope=MissionScope(roots=scope_roots, excludes=tuple(scenario.get("excludes", ()))),
                targets=tuple(scenario["targets"]),
            ).value
            plan = api.plan_mission(mission.mission_id, intelligence=_intelligence(scenario)).value

            run = api.run_mission(mission.mission_id, tool_outputs=_tool_outputs(plan)).value
            assert run.mission.state is MissionState(scenario["expected_state"])
            assert run.coverage is not None
            assert run.quality is not None
            assert 0.0 <= run.quality.score <= 1.0

            if scenario.get("expected_blocked"):
                assert run.run.blocked, scenario["name"]

            kinds = {phase.kind for phase in plan.phases}
            for expected_phase in scenario.get("expected_phases", ()):
                assert MissionPhaseKind(expected_phase) in kinds, scenario["name"]

            capabilities = {step.capability for phase in plan.phases for step in phase.steps}
            for expected_capability in scenario.get("expected_capabilities", ()):
                assert expected_capability in capabilities, scenario["name"]

            if scenario.get("expected_steps_gte"):
                assert plan.total_steps() >= scenario["expected_steps_gte"], scenario["name"]

    def test_mission_lifecycle_transitions(self) -> None:
        platform = build_platform()
        api = platform.offensive_orchestration
        mission = api.create_mission(
            objective="lifecycle",
            mission_type=MissionType.WEB_PENTEST,
            targets=("example.com",),
        ).value
        assert mission.state is MissionState.CREATED
        api.plan_mission(mission.mission_id)
        mission = api.get_mission(mission.mission_id)
        assert mission.state is MissionState.READY
        plan = api.get_plan(mission.plan_id)
        api.run_mission(mission.mission_id, tool_outputs=_tool_outputs(plan))
        assert api.get_mission(mission.mission_id).state is MissionState.COMPLETED

    def test_events_are_registered_and_emitted(self) -> None:
        platform = build_platform()
        api = platform.offensive_orchestration
        seen: list[str] = []
        platform.event_bus.subscribe("mission.*", lambda event: seen.append(event.event_type))
        mission = api.create_mission(
            objective="events",
            mission_type=MissionType.WEB_PENTEST,
            targets=("example.com",),
        ).value
        plan = api.plan_mission(mission.mission_id).value
        api.run_mission(mission.mission_id, tool_outputs=_tool_outputs(plan))
        assert "mission.plan.created" in seen
        assert "mission.coverage.computed" in seen
        assert "mission.quality.computed" in seen

    def test_mission_reports_are_available(self) -> None:
        platform = build_platform()
        api = platform.offensive_orchestration
        mission = api.create_mission(
            objective="report",
            mission_type=MissionType.WEB_PENTEST,
            targets=("example.com",),
        ).value
        plan = api.plan_mission(mission.mission_id).value
        run = api.run_mission(mission.mission_id, tool_outputs=_tool_outputs(plan)).value
        report = {
            "mission": run.mission.to_dict(),
            "plan": run.plan.to_dict(),
            "coverage": run.coverage.to_dict(),
            "quality": run.quality.to_dict(),
            "gaps": run.run.gaps,
        }
        assert report["mission"]["mission_id"] == mission.mission_id
        assert "coverage" in report
        assert "quality" in report
