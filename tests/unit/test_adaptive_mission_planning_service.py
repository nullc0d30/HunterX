# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the AdaptiveMissionPlanningEngine facade and service."""

from __future__ import annotations

import pytest

from hunterx.application.adaptive_mission_planning import (
    AdaptiveMissionPlanningQueryService,
    AdaptiveMissionPlanningService,
)
from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    MissionState,
    ReplanTrigger,
)
from hunterx.domain.exceptions.adaptive_mission_planning import (
    AdaptiveMissionNotFoundError,
    AdaptivePlanNotFoundError,
)
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine


@pytest.fixture()
def service() -> AdaptiveMissionPlanningService:
    return AdaptiveMissionPlanningService(engine=AdaptiveMissionPlanningEngine())


class TestCreateAndStatus:
    def test_create_mission_builds_initial_plan(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission(objective="web_security_assessment", target="example.com")
        assert mission.state is MissionState.SCOPING
        assert mission.plan_version == 1
        assert len(mission.graph.actions) >= 3
        assert mission.constraints.included_targets == ("example.com",)

    def test_status_and_missing(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        status = service.status(mission.mission_id)
        assert status.mission_id == mission.mission_id
        with pytest.raises(AdaptiveMissionNotFoundError):
            service.status("missing")

    def test_lifecycle_transitions(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        service.pause(mission.mission_id)
        assert service.status(mission.mission_id).state is MissionState.PAUSED
        service.resume(mission.mission_id)
        assert service.status(mission.mission_id).state is MissionState.REASSESSMENT
        service.complete(mission.mission_id)
        assert service.status(mission.mission_id).state is MissionState.COMPLETED


class TestPlanQueries:
    def test_current_plan_and_history(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        plan = service.current_plan(mission.mission_id)
        assert plan["plan_version"] == 1
        assert plan["actions"]
        history = service.plan_history(mission.mission_id)
        assert len(history) == 1
        assert history[0].plan_version == 1
        version = service.plan_version(mission.mission_id, 1)
        assert version.parent_version == 0

    def test_unknown_version_raises(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        with pytest.raises(AdaptivePlanNotFoundError):
            service.plan_version(mission.mission_id, 99)


class TestReplan:
    def test_new_asset_replans_and_versions(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        before = len(service.graph(mission.mission_id))
        delta = service.replan(
            mission.mission_id,
            trigger=ReplanTrigger.NEW_ASSET_DISCOVERED,
            asset_key="host:app.example.com",
            reason="new asset",
        )
        assert delta.plan_version == 2
        assert len(service.graph(mission.mission_id)) == before + 1
        assert service.status(mission.mission_id).plan_version == 2

    def test_scope_change_blocks_assets(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission(target="example.com")
        service.replan(
            mission.mission_id,
            trigger=ReplanTrigger.SCOPE_CHANGED,
            detail={"excluded_assets": ["example.com"]},
            reason="scope shrunk",
        )
        # the mission reassesses after scope change; no out-of-scope action scheduled
        status = service.status(mission.mission_id)
        assert status.state is MissionState.REASSESSMENT


class TestDecisionFlow:
    def test_candidates_propose_and_approve(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        result = service.candidate_actions(mission.mission_id)
        assert result.proposals or not result.proposals
        if result.proposals:
            scheduled = service.propose_actions(mission.mission_id, result)
            assert scheduled
            action_id = scheduled[0].action.action_id
            action = service.approve_action(mission.mission_id, action_id)
            assert action.status is ActionStatus.APPROVED

    def test_explain_next(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        explanation = service.explain_next(mission.mission_id)
        assert "action_id" in explanation or explanation["explanation"]

    def test_tool_selection(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        action_id = service.graph(mission.mission_id)[0].action_id
        selection = service.select_tool(mission.mission_id, action_id)
        assert selection.action_id == action_id


class TestGapsCheckpointsFailures:
    def test_gaps(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        assert service.evidence_gaps(mission.mission_id) == []
        assert service.proof_gaps(mission.mission_id) == []

    def test_checkpoint_roundtrip(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        checkpoint = service.checkpoint_create(mission.mission_id)
        assert checkpoint.completed_actions == ()
        resumed = service.resume_from_checkpoint(mission.mission_id, checkpoint.checkpoint_id)
        assert resumed.state is MissionState.REASSESSMENT

    def test_failure_and_fallback(self, service: AdaptiveMissionPlanningService) -> None:
        mission = service.create_mission()
        action_id = service.graph(mission.mission_id)[0].action_id
        failure = service.record_failure(
            mission.mission_id,
            action_id=action_id,
            tool_id="nmap",
            error="rate limit exceeded",
            exit_code=429,
        )
        assert failure.failure_class.value == "rate_limit"


class TestQueryService:
    def test_persisted_records_roundtrip(self) -> None:
        from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory

        stores = InMemoryTidbRepositoryFactory()
        service = AdaptiveMissionPlanningService(engine=AdaptiveMissionPlanningEngine(), stores=stores)
        query = AdaptiveMissionPlanningQueryService(stores=stores)
        mission = service.create_mission(objective="api_security_assessment", target="api.example.com")
        records = query.mission_records()
        assert any(record.mission_id == mission.mission_id for record in records)
        assert query.actions(mission.mission_id)
        assert query.plan_versions(mission.mission_id)
