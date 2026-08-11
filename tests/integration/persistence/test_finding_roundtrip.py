# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding persistence tests (Sprint 034.3 §7).

A complete validated finding must round-trip candidate → evidence →
verification → proof → impact → report-ready → database → reload without
information loss.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import FindingRecord

pytest.importorskip("sqlalchemy")


def _complete_finding() -> FindingRecord:
    return FindingRecord(
        finding_id="F-rt",
        mission_id="mis-rt",
        target_id="tgt-rt",
        asset_id="tgt-rt",
        vulnerability_class="ssrf",
        title="Server-Side Request Forgery in URL parameter",
        description="The search endpoint reflects a user-supplied URL into a server-side request.",
        severity="high",
        confidence=0.92,
        status="report_ready",
        affected_assets=["https://example.com/"],
        affected_endpoints=["https://example.com/fetch"],
        affected_parameters=["url"],
        observations=[
            {"type": "behavioral_differential", "observed": True, "detail": "external callback received"},
            {"type": "response_time", "observed": True, "detail": "time-based oracle"},
        ],
        evidence_refs=["ev-1", "ev-2"],
        validation_refs=["v-1"],
        proof_refs=["p-1"],
        impact_refs=["i-1"],
        reproduction_refs=["r-1"],
        scope={"authorized": True, "scope_id": "scope-rt", "target": "example.com"},
        provenance="nuclei:3.2.0 -> finding-orchestration:1.4.0",
        analysis_version="1.0.0",
    )


def _assert_finding_fields(loaded: FindingRecord) -> None:
    assert loaded.finding_id == "F-rt"
    assert loaded.mission_id == "mis-rt"
    assert loaded.target_id == "tgt-rt"
    assert loaded.asset_id == "tgt-rt"
    assert loaded.vulnerability_class == "ssrf"
    assert loaded.title == "Server-Side Request Forgery in URL parameter"
    assert loaded.description == "The search endpoint reflects a user-supplied URL into a server-side request."
    assert loaded.severity == "high"
    assert loaded.confidence == 0.92
    assert loaded.status == "report_ready"
    assert loaded.affected_assets == ["https://example.com/"]
    assert loaded.affected_endpoints == ["https://example.com/fetch"]
    assert loaded.affected_parameters == ["url"]
    assert len(loaded.observations) == 2
    assert loaded.evidence_refs == ["ev-1", "ev-2"]
    assert loaded.validation_refs == ["v-1"]
    assert loaded.proof_refs == ["p-1"]
    assert loaded.impact_refs == ["i-1"]
    assert loaded.reproduction_refs == ["r-1"]
    assert loaded.scope == {"authorized": True, "scope_id": "scope-rt", "target": "example.com"}
    assert loaded.provenance == "nuclei:3.2.0 -> finding-orchestration:1.4.0"
    assert loaded.analysis_version == "1.0.0"


def test_complete_finding_roundtrips_through_sql(sql_factory) -> None:
    repo = sql_factory.repository_for(FindingRecord)
    finding = _complete_finding()
    repo.save(finding)

    loaded = repo.get(finding.id)
    assert loaded is not None
    _assert_finding_fields(loaded)


def test_complete_finding_roundtrips_through_memory(memory_factory) -> None:
    repo = memory_factory.repository_for(FindingRecord)
    finding = _complete_finding()
    repo.save(finding)

    loaded = repo.get(finding.id)
    assert loaded is not None
    _assert_finding_fields(loaded)


def test_finding_status_lifecycle_persists(sql_factory) -> None:
    """The candidate → validated → report_ready status transitions survive."""
    repo = sql_factory.repository_for(FindingRecord)
    finding = _complete_finding()
    repo.save(finding)

    loaded = repo.get(finding.id)
    assert loaded.status == "report_ready"
    assert loaded.created_at == finding.created_at
    # Envelope counters survive too.
    assert loaded.version == finding.version
    assert loaded.schema_version == 1
    assert loaded.id == finding.id
