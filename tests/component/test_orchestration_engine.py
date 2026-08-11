# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests: orchestration engine composition root and API facade."""

from __future__ import annotations

from hunterx.domain.orchestration.enums import MissionState, MissionType
from hunterx.domain.orchestration.models import MissionScope
from hunterx.engines.orchestration.api import OffensiveOrchestrationAPI
from hunterx.engines.orchestration.replan import DiscoveredAsset
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.event_bus import InMemoryEventBus
from tests.framework.orchestration import (
    build_orchestration_repositories,
    fake_engine,
)


def _make_api():
    repos = build_orchestration_repositories()
    bus = InMemoryEventBus()
    graph = InMemoryKnowledgeGraph()
    return (
        OffensiveOrchestrationAPI(
            missions=repos["offensive_missions"],
            plans=repos["execution_plans"],
            execution_engine=fake_engine(),
            event_bus=bus,
            knowledge_graph=graph,
        ),
        bus,
        graph,
        repos,
    )


def test_create_and_plan_mission() -> None:
    api, _, _, _ = _make_api()
    result = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        scope=MissionScope(roots=("example.com",)),
        targets=("example.com",),
    )
    assert result.ok
    mission = result.value
    assert mission.state is MissionState.CREATED
    plan_result = api.plan_mission(mission.mission_id)
    assert plan_result.ok
    plan = plan_result.value
    assert plan.total_steps() > 0
    assert api.get_mission(mission.mission_id).plan_id == plan.plan_id


def test_full_mission_run_completes() -> None:
    api, _, _, _ = _make_api()
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        scope=MissionScope(roots=("example.com",)),
        targets=("example.com",),
    ).value
    plan = api.plan_mission(mission.mission_id).value
    run_result = api.run_mission(mission.mission_id)
    assert run_result.ok
    run = run_result.value
    assert run.mission.state is MissionState.COMPLETED
    assert run.coverage is not None
    assert run.quality is not None
    assert len(run.run.completed) == plan.total_steps()


def test_full_mission_run_emits_events() -> None:
    api, bus, _, _ = _make_api()
    seen: list[str] = []
    bus.subscribe("mission.*", lambda event: seen.append(event.event_type))
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        scope=MissionScope(roots=("example.com",)),
        targets=("example.com",),
    ).value
    api.plan_mission(mission.mission_id)
    api.run_mission(mission.mission_id)
    assert "mission.plan.created" in seen
    assert "mission.coverage.computed" in seen
    assert "mission.quality.computed" in seen


def test_out_of_scope_target_results_partial() -> None:
    api, _, _, _ = _make_api()
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        scope=MissionScope(roots=("example.com",)),
        targets=("example.com",),
    ).value
    plan = api.plan_mission(mission.mission_id).value
    # Inject an out-of-scope step via tool outputs targeting evil.org.
    from dataclasses import replace

    from hunterx.domain.orchestration.models import MissionStep

    first = plan.phases[0]
    extra = MissionStep(
        step_id="evil-step",
        phase_id=first.phase_id,
        capability="web-crawling",
        target="evil.org",
        target_type="domain",
    )
    phases = (replace(first, steps=first.steps + (extra,)),) + plan.phases[1:]
    api.engine._plans.save(replace(plan, phases=phases))
    run_result = api.run_mission(mission.mission_id)
    assert run_result.ok
    run = run_result.value
    assert run.mission.state is MissionState.PARTIAL
    assert "evil-step" in run.run.blocked


def test_cancel_mission() -> None:
    api, _, _, _ = _make_api()
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        targets=("example.com",),
    ).value
    result = api.cancel(mission.mission_id)
    assert result.ok
    assert result.value.state is MissionState.CANCELLED


def test_pause_resume() -> None:
    api, _, _, _ = _make_api()
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        targets=("example.com",),
    ).value
    api.plan_mission(mission.mission_id)
    api.run_mission(mission.mission_id)
    mission = api.get_mission(mission.mission_id)
    assert mission.state is MissionState.COMPLETED


def test_replan_does_not_expand_scope() -> None:
    api, _, _, _ = _make_api()
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        scope=MissionScope(roots=("example.com",)),
        targets=("example.com",),
    ).value
    result = api.engine.replan_mission(
        mission.mission_id,
        reason="discovered assets",
        discovered_assets=[DiscoveredAsset(identifier="evil.org")],
    )
    assert result.ok
    decision = result.value
    assert not decision.in_scope_assets
    assert "evil.org" in decision.blocked_assets


def test_list_missions_and_states() -> None:
    api, _, _, _ = _make_api()
    api.create_mission(objective="m1", mission_type=MissionType.WEB_PENTEST, targets=("a.com",))
    api.create_mission(objective="m2", mission_type=MissionType.CLOUD_ASSESSMENT, targets=("b.com",))
    assert len(api.list_missions()) == 2
    assert len(api.engine.list_by_state(MissionState.CREATED)) == 2


def test_checkpoint_via_engine() -> None:
    api, _, _, _ = _make_api()
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        targets=("example.com",),
    ).value
    api.plan_mission(mission.mission_id)
    mission = api.get_mission(mission.mission_id)
    result = api.engine.checkpoint(mission.mission_id, label="pre-run")
    assert result.ok
    checkpoint = result.value
    assert checkpoint.label == "pre-run"
    assert api.engine._checkpoints.latest(mission.plan_id) is not None
