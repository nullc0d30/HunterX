# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the domain layer: entities, value objects, events, exceptions."""

from __future__ import annotations

import pytest

from hunterx.domain.entities import (
    Finding,
    Mission,
    MissionPriority,
    MissionStatus,
    Target,
    TargetKind,
)
from hunterx.domain.events import DomainEvent
from hunterx.domain.exceptions import (
    HunterXError,
    InvalidFindingError,
    InvalidMissionError,
    InvalidTargetError,
)
from hunterx.domain.value_objects import IPAddress, RiskScore, Severity


class TestValueObjects:
    def test_ip_address_valid(self) -> None:
        assert IPAddress("127.0.0.1").version == 4

    def test_ip_address_invalid(self) -> None:
        with pytest.raises(InvalidTargetError):
            IPAddress("999.1.1.1")

    def test_risk_score_bounds(self) -> None:
        assert RiskScore(7.5).severity == Severity.HIGH
        with pytest.raises(InvalidFindingError):
            RiskScore(11.0)

    def test_severity_parse(self) -> None:
        assert Severity.from_str("critical") == Severity.CRITICAL
        with pytest.raises(InvalidFindingError):
            Severity.from_str("nope")


class TestTarget:
    def test_target_requires_value(self) -> None:
        with pytest.raises(InvalidTargetError):
            Target(kind=TargetKind.IP, value="")

    def test_target_identifier(self) -> None:
        target = Target(kind=TargetKind.DOMAIN, value="example.com")
        assert target.identifier() == "domain:example.com"


class TestMission:
    def test_mission_requires_targets(self) -> None:
        with pytest.raises(InvalidMissionError):
            Mission(name="m", workflow="w", targets=[])

    def test_mission_lifecycle(self) -> None:
        mission = Mission(name="m", workflow="w", targets=["example.com"])
        assert mission.status == MissionStatus.PENDING
        mission.start()
        assert mission.status == MissionStatus.RUNNING
        mission.complete()
        assert mission.status == MissionStatus.COMPLETED
        assert mission.progress == 100.0

    def test_cannot_start_completed_mission(self) -> None:
        mission = Mission(name="m", workflow="w", targets=["x"])
        mission.complete()
        with pytest.raises(InvalidMissionError):
            mission.start()

    def test_priority_default(self) -> None:
        mission = Mission(name="m", workflow="w", targets=["x"])
        assert mission.priority == MissionPriority.MEDIUM


class TestFinding:
    def test_finding_requires_fields(self) -> None:
        with pytest.raises(InvalidFindingError):
            Finding(title="", severity=Severity.LOW, target="x", tool="t")

    def test_content_hash_computed(self) -> None:
        finding = Finding(title="t", severity=Severity.HIGH, target="x", tool="tool")
        hashed = finding.compute_content_hash()
        assert finding.content_hash == hashed
        assert len(hashed) == 64


class TestEvents:
    def test_domain_event_fields(self) -> None:
        event = DomainEvent(event_type="finding.created", payload={"a": 1})
        assert event.event_id
        assert event.occurred_at
        assert event.event_type == "finding.created"
        assert event.to_dict()["event_type"] == "finding.created"


class TestExceptions:
    def test_hunterx_error_is_base(self) -> None:
        assert issubclass(InvalidTargetError, HunterXError)

    def test_error_serialization(self) -> None:
        error = HunterXError("boom")
        payload = error.to_dict()
        assert payload["message"] == "boom"
        assert "code" in payload
