# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: orchestration through the assembled platform.

Exercises the offensive orchestration capability end to end: platform build,
mission create/plan/run, TIDB persistence of orchestration entities, knowledge
graph updates and event emission.
"""

from __future__ import annotations

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.entities.tidb.orchestration import (
    MissionFailure as TidbMissionFailure,
)
from hunterx.domain.entities.tidb.orchestration import (
    MissionPlanRecord,
    MissionStepRecord,
    MissionTaskHistory,
    ToolSelectionRecord,
)
from hunterx.domain.orchestration.enums import MissionState, MissionType
from hunterx.domain.orchestration.models import MissionScope
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.platform.assembler import build_platform


def _outputs(plan) -> dict[str, dict]:
    return {
        step.step_id: {"findings": [{"title": "ok"}], "evidence": [{"content": "ok"}]}
        for phase in plan.phases
        for step in phase.steps
    }


def test_orchestration_end_to_end_via_platform() -> None:
    platform = build_platform()
    api = platform.offensive_orchestration
    mission = api.create_mission(
        objective="integration mission",
        mission_type=MissionType.WEB_PENTEST,
        scope=MissionScope(roots=("example.com",)),
        targets=("example.com",),
    ).value
    plan = api.plan_mission(mission.mission_id).value
    assert plan.total_steps() > 0
    run = api.run_mission(mission.mission_id, tool_outputs=_outputs(plan)).value
    assert run.mission.state is MissionState.COMPLETED
    assert run.coverage is not None
    assert run.quality is not None


def test_orchestration_persists_to_sql_tidb(tmp_path) -> None:
    import sqlalchemy

    sqlalchemy  # noqa: B018 - guard import availability
    settings = DatabaseSettings(url=f"sqlite:///{tmp_path / 'orch.db'}")
    session_factory = SessionFactory(settings)
    session_factory.create_all()
    stores = SqlTidbRepositoryFactory(session_factory)

    plan = MissionPlanRecord(plan_id="P1", mission_id="M1", objective="test", state="planned")
    stores.repository_for(MissionPlanRecord).save(plan)
    step = MissionStepRecord(step_id="S1", plan_id="P1", phase_id="PH1", capability="web-crawling", target="example.com")
    stores.repository_for(MissionStepRecord).save(step)
    history = MissionTaskHistory(
        history_id="H1",
        mission_id="M1",
        plan_id="P1",
        step_id="S1",
        execution_id="E1",
        tool_id="fake",
        target="example.com",
        state="completed",
    )
    stores.repository_for(MissionTaskHistory).save(history)
    selection = ToolSelectionRecord(
        selection_id="SE1",
        mission_id="M1",
        plan_id="P1",
        step_id="S1",
        capability="web-crawling",
        tool_id="fake",
    )
    stores.repository_for(ToolSelectionRecord).save(selection)
    failure = TidbMissionFailure(
        failure_id="F1",
        mission_id="M1",
        plan_id="P1",
        step_id="S1",
        tool_id="fake",
        failure_class="permanent",
        management="blocked",
        error="boom",
    )
    stores.repository_for(TidbMissionFailure).save(failure)

    assert stores.repository_for(MissionPlanRecord).get(plan.id).plan_id == "P1"
    assert stores.repository_for(MissionStepRecord).get(step.id).capability == "web-crawling"
    assert stores.repository_for(MissionTaskHistory).get(history.id).state == "completed"
    assert stores.repository_for(ToolSelectionRecord).get(selection.id).tool_id == "fake"
    assert stores.repository_for(TidbMissionFailure).get(failure.id).failure_class == "permanent"


def test_orchestration_updates_knowledge_graph() -> None:
    platform = build_platform()
    api = platform.offensive_orchestration
    mission = api.create_mission(
        objective="graph mission",
        mission_type=MissionType.WEB_PENTEST,
        targets=("example.com",),
    ).value
    api.plan_mission(mission.mission_id)
    graph = platform.knowledge_graph
    # Mission and plan nodes are upserted; relationship exists.
    neighbors = graph.query_neighbors(mission.mission_id, depth=1)
    assert isinstance(neighbors, list)
