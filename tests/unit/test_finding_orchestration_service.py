# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Sprint 028 vulnerability finding orchestration service."""

from __future__ import annotations

import pytest

from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.entities.tidb.finding_orchestration import (
    FindingConflict,
    FindingDedupDecision,
    FindingValidationAttempt,
)
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine


@pytest.fixture
def service() -> VulnerabilityFindingService:
    stores = InMemoryTidbRepositoryFactory()
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=stores,
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _observations(*kinds: str) -> list[dict[str, object]]:
    return [{"kind": kind, "value": f"{kind}-value", "quality": "high", "source": "scanner"} for kind in kinds]


def test_create_finding_becomes_supported(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="sql_injection",
        title="SQLi",
        description="SQLi at /search",
        severity="high",
        tool="nuclei",
        endpoints=("/search",),
        parameters=("q",),
        observations=_observations("detection_signature"),
    )
    assert finding["status"] == "supported"
    assert finding["evidence_refs"]


def test_validate_finding_scope_blocked_when_out_of_scope(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://out-of-scope.example",
        vulnerability_class="ssrf",
        title="SSRF",
        description="ssrf",
        severity="high",
        tool="interactsh",
        scope={"scope_ok": False},
    )
    result = service.validate_finding(finding["finding_id"])
    assert result["status"] == "blocked"


def test_full_lifecycle_to_report_ready(service: VulnerabilityFindingService) -> None:
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
        observations=_observations("detection_signature", "differential_database_behavior"),
    )
    poc = service.generate_poc(
        finding["finding_id"], reproduction={"request": "/search?q=test", "method": "GET"}
    )
    assert poc["lifecycle_state"] == "static_validated"
    replay = service.replay_poc(
        finding["finding_id"], poc["poc_id"], outcome={"confirmed": True, "target": "https://example.com"}
    )
    assert replay["verdict"] == "confirmed"
    service.assess_impact(finding["finding_id"])
    service.calculate_confidence(finding["finding_id"])
    final = service.finalize_report_ready(finding["finding_id"])
    assert final["transition"]["allowed"] is True
    assert service.get_finding(finding["finding_id"])["status"] == "report_ready"


def test_false_positive_is_rejected_and_reason_preserved(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="sql_injection",
        title="FP",
        description="generic error",
        severity="medium",
        tool="nuclei",
        observations=_observations("error_message"),
    )
    rejected = service.reject_finding(
        finding["finding_id"], reason="generic_error_response", state="rejected"
    )
    assert rejected["to_state"] == "rejected"
    record = service.get_finding(finding["finding_id"])
    assert record["status"] == "rejected"
    assert record["observations"]


def test_proof_failure_returns_to_proof_required(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        asset_id="asset-1",
        vulnerability_class="sql_injection",
        title="SQLi",
        description="SQLi",
        severity="high",
        tool="nuclei",
        endpoints=("/search",),
        observations=_observations("detection_signature", "differential_database_behavior"),
    )
    poc = service.generate_poc(finding["finding_id"], reproduction={"request": "/search?q=1"})
    # First replay confirms and advances to PROVED.
    service.replay_poc(
        finding["finding_id"], poc["poc_id"], outcome={"confirmed": True, "target": "https://example.com"}
    )
    assert service.get_finding(finding["finding_id"])["status"] == "proved"
    # A non-reproducible replay must regress the finding to PROOF_REQUIRED.
    service.replay_poc(
        finding["finding_id"], poc["poc_id"], outcome={"confirmed": False, "target": "https://example.com"}
    )
    assert service.get_finding(finding["finding_id"])["status"] in ("proof_required", "disputed")


def test_conflict_marks_finding_disputed(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="ssrf",
        title="SSRF",
        description="ssrf",
        severity="high",
        tool="interactsh",
        observations=_observations("detection_signature"),
    )
    stores = service._stores
    conflict = FindingConflict(
        conflict_id="conflict-1",
        finding_id=finding["finding_id"],
        kind="tool_disagreement",
        description="scanner says vulnerable, replay says not",
    )
    stores.repository_for(FindingConflict).save(conflict)
    resolved = service.resolve_conflict(
        finding["finding_id"], "conflict-1", resolution="disputed", reason="replay not reproducible"
    )
    assert resolved["status"] == "disputed"
    assert service.get_finding(finding["finding_id"])["status"] == "disputed"


def test_dedup_marks_duplicate(service: VulnerabilityFindingService) -> None:
    service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        asset_id="asset-1",
        vulnerability_class="xss",
        title="XSS",
        description="xss",
        severity="high",
        tool="dalfox",
        observations=_observations("reflection"),
    )
    second = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        asset_id="asset-1",
        vulnerability_class="xss",
        title="XSS duplicate",
        description="xss",
        severity="high",
        tool="dalfox",
        observations=_observations("reflection"),
    )
    decision = service.deduplicate_finding(second["finding_id"])
    assert decision["relation"] == "same_finding"
    assert service.get_finding(second["finding_id"])["status"] == "duplicate"
    stores = service._stores
    decisions = stores.repository_for(FindingDedupDecision).list_by("finding_id", second["finding_id"], limit=10)
    assert decisions


def test_unknown_behavior_classification(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="unknown_behavior",
        title="Unknown behavior",
        description="unexpected callback",
        severity="medium",
        tool="interactsh",
        observations=[{"kind": "unknown_observation", "value": "unexpected controlled callback", "quality": "high"}],
    )
    profile = service.classify_unknown(
        finding["finding_id"], known_signatures=[], security_relevant=True, reproducible=True
    )
    assert profile["classification"] in ("novel_behavior", "application_specific")


def test_evidence_gaps_exposed(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="xss",
        title="XSS",
        description="xss",
        severity="medium",
        tool="dalfox",
        observations=_observations("reflection"),
    )
    gaps = service.get_evidence_gaps(finding["finding_id"])
    assert any(gap["purpose"] == "validation" for gap in gaps)


def test_rejected_finding_never_report_ready(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="sql_injection",
        title="FP",
        description="generic error",
        severity="medium",
        tool="nuclei",
        observations=_observations("error_message"),
    )
    service.reject_finding(finding["finding_id"], reason="generic_error_response")
    readiness = service.get_report_readiness(finding["finding_id"])
    assert not readiness["reportable"]


def test_validation_attempt_persisted(service: VulnerabilityFindingService) -> None:
    finding = service.create_finding(
        mission_id="m1",
        target_id="https://example.com",
        vulnerability_class="sql_injection",
        title="SQLi",
        description="sqli",
        severity="high",
        tool="nuclei",
        observations=_observations("detection_signature"),
    )
    service.validate_finding(finding["finding_id"])
    attempts = service._stores.repository_for(FindingValidationAttempt).list_by(
        "finding_id", finding["finding_id"], limit=10
    )
    assert attempts
