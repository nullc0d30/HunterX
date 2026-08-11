# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests: application services against in-memory repositories."""

from __future__ import annotations

from hunterx.application.dto import CreateFindingRequest, CreateMissionRequest
from hunterx.application.findings import FindingService
from hunterx.application.missions import MissionService
from hunterx.shared.result import Failure, Success


class TestMissionService:
    def test_create_and_fetch(self, mission_repository) -> None:
        service = MissionService(mission_repository)
        result = service.create(
            CreateMissionRequest(name="web", workflow="smoke", targets=["example.com"])
        )
        assert isinstance(result, Success)
        fetched = service.get(result.value.mission_id)
        assert isinstance(fetched, Success)
        assert fetched.value.name == "web"

    def test_create_invalid_kind_fails(self, mission_repository) -> None:
        service = MissionService(mission_repository)
        result = service.create(
            CreateMissionRequest(name="web", workflow="smoke", targets=["x"], kind="bogus")
        )
        assert isinstance(result, Failure)

    def test_missing_mission_returns_failure(self, mission_repository) -> None:
        service = MissionService(mission_repository)
        result = service.get("doesnotexist")
        assert isinstance(result, Failure)

    def test_lifecycle_transitions(self, mission_repository) -> None:
        service = MissionService(mission_repository)
        created = service.create(CreateMissionRequest(name="m", workflow="smoke", targets=["x"]))
        assert isinstance(created, Success)
        mission_id = created.value.mission_id

        started = service.start(mission_id)
        assert isinstance(started, Success)
        assert started.value.status.value == "running"

        completed = service.complete(mission_id)
        assert isinstance(completed, Success)
        assert completed.value.status.value == "completed"


class TestFindingService:
    def test_create_and_deduplicate(self, finding_repository) -> None:
        service = FindingService(finding_repository)
        request = CreateFindingRequest(title="XSS", severity="high", target="a", tool="scanner")
        first = service.create(request)
        assert isinstance(first, Success)

        second = service.create(request)
        assert isinstance(second, Failure)  # duplicate by content hash

    def test_list_by_mission(self, finding_repository) -> None:
        service = FindingService(finding_repository)
        service.create(CreateFindingRequest(title="A", severity="low", target="a", tool="t", mission_id="m1"))
        service.create(CreateFindingRequest(title="B", severity="low", target="b", tool="t", mission_id="m2"))
        assert len(service.list_by_mission("m1")) == 1
