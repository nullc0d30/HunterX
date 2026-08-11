# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Platform integration tests for the Sprint 028 finding orchestration capability."""

from __future__ import annotations

import pytest

from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.entities.tidb.finding_orchestration import (
    FindingPoC,
    FindingRecord,
    FindingStateTransition,
)
from hunterx.domain.events.catalog import build_registry
from hunterx.platform.assembler import build_platform


@pytest.fixture
def platform() -> object:
    return build_platform()


def test_platform_exposes_finding_service(platform: object) -> None:
    assert hasattr(platform, "vulnerability_finding_service")  # type: ignore[attr-defined]


def test_event_catalog_contains_finding_lifecycle_events() -> None:
    registry = build_registry()
    for event_type in (
        "finding.created",
        "finding.supported",
        "finding.validation.started",
        "finding.validation.completed",
        "finding.evidence.added",
        "finding.evidence.conflict",
        "finding.proof.required",
        "finding.proof.started",
        "finding.proof.replayed",
        "finding.proof.validated",
        "finding.impact.assessed",
        "finding.confidence.updated",
        "finding.duplicate.detected",
        "finding.disproved",
        "finding.report_ready",
    ):
        assert registry.has(event_type), event_type


def test_container_resolves_the_service(platform: object) -> None:
    assert platform.resolve(VulnerabilityFindingService) is platform.vulnerability_finding_service  # type: ignore[attr-defined]


def test_end_to_end_finding_lifecycle_persists(platform: object) -> None:
    service: VulnerabilityFindingService = platform.vulnerability_finding_service  # type: ignore[attr-defined]
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        asset_id="asset-1",
        vulnerability_class="sql_injection",
        title="SQLi candidate",
        description="SQLi at /search?q=",
        severity="high",
        tool="nuclei",
        endpoints=("/search",),
        parameters=("q",),
        observations=[
            {"kind": "detection_signature", "value": "sqli-sig", "quality": "high", "source": "scanner"},
            {"kind": "differential_database_behavior", "value": "dbdiff", "quality": "high", "source": "validation"},
        ],
    )
    poc = service.generate_poc(
        finding["finding_id"], reproduction={"request": "/search?q=test", "method": "GET"}
    )
    service.replay_poc(
        finding["finding_id"], poc["poc_id"], outcome={"confirmed": True, "target": "https://example.com"}
    )
    service.assess_impact(finding["finding_id"])
    service.calculate_confidence(finding["finding_id"])
    final = service.finalize_report_ready(finding["finding_id"])
    assert final["transition"]["allowed"] is True

    tidb = platform.tidb  # type: ignore[attr-defined]
    records = tidb.repository_for(FindingRecord).list_by("finding_id", finding["finding_id"], limit=10)
    assert records
    assert records[-1].status == "report_ready"

    pocs = tidb.repository_for(FindingPoC).list_by("finding_id", finding["finding_id"], limit=10)
    assert pocs

    transitions = tidb.repository_for(FindingStateTransition).list_by(
        "finding_id", finding["finding_id"], limit=100
    )
    allowed = [item for item in transitions if item.allowed]
    assert allowed


def test_legacy_finding_architecture_reused(platform: object) -> None:
    service: VulnerabilityFindingService = platform.vulnerability_finding_service  # type: ignore[attr-defined]
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="xss",
        title="XSS",
        description="xss",
        severity="medium",
        tool="dalfox",
    )
    legacy = platform.finding_service.list_by_mission("m1")  # type: ignore[attr-defined]
    assert any(item.finding_id == finding["finding_id"] for item in legacy)


def test_unknown_behavior_via_platform(platform: object) -> None:
    service: VulnerabilityFindingService = platform.vulnerability_finding_service  # type: ignore[attr-defined]
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="unknown_behavior",
        title="Unknown",
        description="unexpected callback",
        severity="medium",
        tool="interactsh",
        observations=[{"kind": "unknown_observation", "value": "unexpected callback", "quality": "high"}],
    )
    profile = service.classify_unknown(
        finding["finding_id"], known_signatures=[], security_relevant=True, reproducible=True
    )
    assert profile["classification"] in ("novel_behavior", "application_specific", "unresolved")
