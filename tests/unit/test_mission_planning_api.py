# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the MissionPlanningAPI facade and engine."""

from __future__ import annotations

from hunterx.domain.exceptions import (
    MissionPlanNotFoundError,
    MissionProfileNotFoundError,
)
from hunterx.domain.mission_planning import (
    MissionPlan,
    MissionPlanningStatus,
    MissionRequest,
    MissionType,
)
from hunterx.shared.result import Failure, Success
from tests.framework.mission_planning import external_pentest_profile, make_api


def _request(**overrides: object) -> MissionRequest:
    base: dict[str, object] = {
        "profile_id": "external-pentest",
        "mission_type": MissionType.EXTERNAL_PENTEST,
        "name": "Perimeter Scan",
        "targets": ("example.com", "10.0.0.0/24"),
    }
    base.update(overrides)
    return MissionRequest(**base)  # type: ignore[arg-type]


class TestCreateAndValidate:
    def test_create_enqueues_plan(self) -> None:
        api = make_api(profile=external_pentest_profile())
        result = api.create_mission(_request())
        assert isinstance(result, Success)
        plan = result.value
        assert isinstance(plan, MissionPlan)
        assert plan.status is MissionPlanningStatus.QUEUED
        assert plan.profile_id == "external-pentest"

    def test_create_unknown_profile_fails(self) -> None:
        api = make_api(profile=external_pentest_profile())
        result = api.create_mission(_request(profile_id="ghost"))
        assert isinstance(result, Failure)
        assert isinstance(result.error, MissionProfileNotFoundError)

    def test_create_unsupported_type_fails(self) -> None:
        api = make_api(profile=external_pentest_profile())
        result = api.create_mission(_request(mission_type=MissionType.MOBILE_ASSESSMENT))
        assert isinstance(result, Failure)

    def test_validate_reports_errors(self) -> None:
        api = make_api(profile=external_pentest_profile())
        errors = api.validate(_request(mission_type=MissionType.MOBILE_ASSESSMENT))
        assert errors
        errors = api.validate(_request())
        assert errors == []

    def test_validate_unknown_profile(self) -> None:
        api = make_api(profile=external_pentest_profile())
        errors = api.validate(_request(profile_id="ghost"))
        assert any("was not found" in error for error in errors)


class TestLifecycle:
    def test_plan_mission_produces_ready_plan(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        result = api.plan_mission(plan_id)
        assert isinstance(result, Success)
        plan = result.value
        assert plan.status is MissionPlanningStatus.READY
        assert len(plan.phases) == 4
        assert plan.total_steps > 0

    def test_plan_unknown_plan_fails(self) -> None:
        api = make_api(profile=external_pentest_profile())
        result = api.plan_mission("ghost")
        assert isinstance(result, Failure)
        assert isinstance(result.error, MissionPlanNotFoundError)

    def test_full_lifecycle_flow(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        assert api.plan_mission(plan_id).value.status is MissionPlanningStatus.READY
        assert api.start_mission(plan_id).value.status is MissionPlanningStatus.EXECUTING
        assert api.status(plan_id).value.status is MissionPlanningStatus.EXECUTING
        assert api.complete(plan_id).value.status is MissionPlanningStatus.COMPLETED
        assert api.archive(plan_id).value.status is MissionPlanningStatus.ARCHIVED

    def test_cancel_from_any_active_state(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        assert api.cancel(plan_id).value.status is MissionPlanningStatus.CANCELLED

    def test_cancel_terminal_plan_fails(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        api.cancel(plan_id)
        result = api.cancel(plan_id)
        assert isinstance(result, Failure)

    def test_fail_and_archive(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        api.plan_mission(plan_id)
        api.start_mission(plan_id)
        assert api.fail(plan_id).value.status is MissionPlanningStatus.FAILED
        assert api.archive(plan_id).value.status is MissionPlanningStatus.ARCHIVED

    def test_wait_and_retry_paths(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        api.plan_mission(plan_id)
        api.start_mission(plan_id)
        assert api.engine.wait_mission(plan_id).value.status is MissionPlanningStatus.WAITING
        assert api.engine.unwait_mission(plan_id).value.status is MissionPlanningStatus.EXECUTING
        assert api.engine.retry_mission(plan_id).value.status is MissionPlanningStatus.RETRYING
        assert api.engine.resume_retry(plan_id).value.status is MissionPlanningStatus.EXECUTING
        assert api.engine.pause_mission(plan_id).value.status is MissionPlanningStatus.PAUSED
        assert api.engine.resume_mission(plan_id).value.status is MissionPlanningStatus.EXECUTING


class TestEventsAndTimeline:
    def test_timeline_records_lifecycle(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        mission_id = created.value.mission_id
        plan_id = created.value.plan_id
        api.plan_mission(plan_id)
        api.start_mission(plan_id)
        api.complete(plan_id)
        events = api.history(mission_id).value
        event_types = [entry.event_type for entry in events]
        assert "mission.created" in event_types
        assert "mission.queued" in event_types
        assert "mission.planned" in event_types
        assert "mission.ready" in event_types
        assert "mission.started" in event_types
        assert "mission.completed" in event_types

    def test_event_bus_receives_milestones(self, event_bus) -> None:
        received: list[str] = []
        event_bus.subscribe("mission.started", lambda e: received.append(e.payload["mission_id"]))
        event_bus.subscribe("mission.completed", lambda e: received.append(e.payload["mission_id"]))
        api = make_api(profile=external_pentest_profile(), event_bus=event_bus)
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        mission_id = created.value.mission_id
        api.plan_mission(plan_id)
        api.start_mission(plan_id)
        api.complete(plan_id)
        assert received == [mission_id, mission_id]

    def test_graph_build_records_timeline(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        api.plan_mission(plan_id)
        graph_result = api.graph(plan_id)
        assert isinstance(graph_result, Success)
        graph = graph_result.value
        assert len(graph.nodes) > 0
        events = [entry.event_type for entry in api.history(created.value.mission_id).value]
        assert "mission.graph.built" in events


class TestUpdate:
    def test_update_before_planning(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        result = api.update_mission(plan_id, name="Renamed", targets=("new.com",))
        assert isinstance(result, Success)
        assert result.value.name == "Renamed"
        assert result.value.targets == ("new.com",)

    def test_update_after_planning_fails(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        api.plan_mission(plan_id)
        result = api.update_mission(plan_id, name="Late")
        assert isinstance(result, Failure)

    def test_update_empty_targets_fails(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        result = api.update_mission(created.value.plan_id, targets=())
        assert isinstance(result, Failure)


class TestCheckpoints:
    def test_checkpoint_round_trip_via_api(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        api.plan_mission(plan_id)
        ckpt = api.checkpoint_create(plan_id, "ready-state")
        assert isinstance(ckpt, Success)
        checkpoint_id = ckpt.value.checkpoint_id
        assert len(api.checkpoint_list(plan_id)) == 1
        restored = api.checkpoint_restore(checkpoint_id)
        assert isinstance(restored, Success)
        assert restored.value.plan_id == plan_id

    def test_checkpoint_unknown_fails(self) -> None:
        api = make_api(profile=external_pentest_profile())
        result = api.checkpoint_restore("ghost")
        assert isinstance(result, Failure)


class TestQueries:
    def test_list_and_status(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        assert len(api.list_missions()) == 1
        status = api.status(plan_id)
        assert isinstance(status, Success)
        assert status.value.plan_id == plan_id
        assert api.status("ghost").ok is False

    def test_summary(self) -> None:
        api = make_api(profile=external_pentest_profile())
        created = api.create_mission(_request())
        plan_id = created.value.plan_id
        api.plan_mission(plan_id)
        summary = api.summary(api.status(plan_id).value)
        assert summary["status"] == "ready"
        assert summary["total_steps"] > 0
        assert summary["phases"] == 4


class TestApplicationService:
    def test_service_flow(self) -> None:
        from hunterx.application.mission_planning import MissionPlanningService
        from tests.framework.mission_planning import build_in_memory_planning_repositories

        repos = build_in_memory_planning_repositories()
        service = MissionPlanningService(
            plans=repos["mission_plans"],  # type: ignore[arg-type]
            profiles=repos["mission_profiles"],  # type: ignore[arg-type]
            templates=repos["mission_templates"],  # type: ignore[arg-type]
            checkpoints=repos["checkpoints"],  # type: ignore[arg-type]
            timeline=repos["mission_timeline"],  # type: ignore[arg-type]
        )
        service._api.register_profile(external_pentest_profile())
        created = service.create(_request())
        assert isinstance(created, Success)
        plan_id = created.value.plan_id
        planned = service.plan(plan_id)
        assert isinstance(planned, Success)
        assert planned.value.status is MissionPlanningStatus.READY
        status = service.status(plan_id)
        assert isinstance(status, Success)
        assert status.value.total_steps > 0
        history = service.history(planned.value.mission_id)
        assert isinstance(history, Success)
        assert history.value
        cancelled = service.cancel(plan_id)
        assert isinstance(cancelled, Success)
        assert cancelled.value.status is MissionPlanningStatus.CANCELLED

    def test_service_invalid_request_fails(self) -> None:
        from hunterx.application.mission_planning import MissionPlanningService
        from tests.framework.mission_planning import build_in_memory_planning_repositories

        repos = build_in_memory_planning_repositories()
        service = MissionPlanningService(
            plans=repos["mission_plans"],  # type: ignore[arg-type]
            profiles=repos["mission_profiles"],  # type: ignore[arg-type]
            templates=repos["mission_templates"],  # type: ignore[arg-type]
        )
        service._api.register_profile(external_pentest_profile())
        result = service.create(_request(mission_type=MissionType.MOBILE_ASSESSMENT))
        assert isinstance(result, Failure)
