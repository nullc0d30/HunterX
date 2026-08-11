# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for Adaptive Mission & Attack-Path Planning.

Builds the full platform and drives the adaptive mission planning service
through the TIDB SQL persistence layer (SQLite), verifying the normalized
records round-trip through the generic repository factory.
"""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from hunterx.application.adaptive_mission_planning import (
    AdaptiveMissionPlanningQueryService,
    AdaptiveMissionPlanningService,
)
from hunterx.config.settings import DatabaseSettings
from hunterx.domain.adaptive_mission_planning.enums import ReplanTrigger
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory


@pytest.fixture()
def session_factory(tmp_path: object) -> SessionFactory:
    settings = DatabaseSettings(url=f"sqlite:///{tmp_path}/amp_integration.db")
    factory = SessionFactory(settings)
    factory.create_all()
    return factory


def test_platform_end_to_end(session_factory: SessionFactory) -> None:
    from hunterx.platform import build_platform

    platform = build_platform()
    service = platform.adaptive_mission_planning_service
    mission = service.create_mission(objective="bug_bounty_assessment", target="example.com")

    # replanning
    delta = service.replan(
        mission.mission_id,
        trigger=ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
        asset_key="url:http://example.com/login",
        reason="new login endpoint",
    )
    assert delta.plan_version == 2

    # decision + approval
    result = service.candidate_actions(mission.mission_id)
    assert result.proposals
    service.propose_actions(mission.mission_id, result)

    # explainability
    explanation = service.explain_next(mission.mission_id)
    assert "rationale" in explanation or "explanation" in explanation

    # attack paths are intelligence only
    assert service.attack_paths(mission.mission_id) == []


def test_tidb_sql_persistence(session_factory: SessionFactory) -> None:
    stores = SqlTidbRepositoryFactory(session_factory)
    service = AdaptiveMissionPlanningService(engine=AdaptiveMissionPlanningEngine(), stores=stores)
    query = AdaptiveMissionPlanningQueryService(stores=stores)

    mission = service.create_mission(objective="api_security_assessment", target="api.example.com")
    service.replan(
        mission.mission_id,
        trigger=ReplanTrigger.NEW_HYPOTHESIS_CREATED,
        asset_key="url:http://api.example.com/v1",
        detail={"hypothesis_id": "h-1", "capability": "ssrf"},
        reason="ssrf hypothesis",
    )
    checkpoint = service.checkpoint_create(mission.mission_id)
    service.resume_from_checkpoint(mission.mission_id, checkpoint.checkpoint_id)

    records = query.mission_records()
    assert any(record.mission_id == mission.mission_id for record in records)
    actions = query.actions(mission.mission_id)
    assert len(actions) == len(service.graph(mission.mission_id))
    versions = query.plan_versions(mission.mission_id)
    assert len(versions) == 2
    checkpoints = query.checkpoints(mission.mission_id)
    assert checkpoints
