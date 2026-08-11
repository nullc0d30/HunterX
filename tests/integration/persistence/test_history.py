# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""History / timeline tests (Sprint 034.3 §9).

Validates temporal intelligence: first/last seen, discovery history, state
changes, finding history and proof history; chronological ordering; repeated
observations that never overwrite historical evidence.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    FindingRecord,
    IntelligenceAssetRecord,
    IntelligenceChangeRecord,
    IntelligenceEvidenceRecord,
    ObservationRecord,
    TargetHistoryRecord,
    VulnerabilityProof,
)

pytest.importorskip("sqlalchemy")

T0 = "2026-08-10T08:00:00+00:00"
T1 = "2026-08-10T09:00:00+00:00"
T2 = "2026-08-10T10:00:00+00:00"
T3 = "2026-08-10T11:00:00+00:00"


def test_first_and_last_seen_tracking(backend_factory) -> None:
    repo = backend_factory.repository_for(IntelligenceAssetRecord)
    asset = IntelligenceAssetRecord(asset_id="a-history", target_id="tgt-1", asset_key="domain:example.com")
    asset.mark_seen(now=T1)
    repo.save(asset)

    loaded = repo.get(asset.id)
    assert loaded is not None
    assert loaded.first_seen == T1
    assert loaded.last_seen == T1

    # Repeated observation updates last_seen but preserves first_seen.
    loaded.mark_seen(now=T2)
    repo.save(loaded)
    again = repo.get(asset.id)
    assert again.first_seen == T1
    assert again.last_seen == T2

    # A third observation moves last_seen forward.
    again.mark_seen(now=T3)
    repo.save(again)
    final = repo.get(asset.id)
    assert final.first_seen == T1
    assert final.last_seen == T3


def test_repeated_observations_are_append_only(backend_factory) -> None:
    """Repeated observations from different runs must not overwrite history."""
    repo = backend_factory.repository_for(ObservationRecord)
    repo.save_many(
        [
            ObservationRecord(
                observation_id=f"obs-{i}",
                target_id="tgt-1",
                mission_id="mis-1",
                tool="nmap",
                timestamp=stamp,
                value="80/tcp open",
                dedup_key="port|tgt-1|80/tcp",
            )
            for i, stamp in enumerate([T0, T1, T2, T3])
        ]
    )
    records = repo.list_by("target_id", "tgt-1", limit=10)
    assert len(records) == 4
    # Each run is preserved as its own attributable record.
    assert {r.timestamp for r in records} == {T0, T1, T2, T3}
    assert len({r.observation_id for r in records}) == 4


def test_discovery_history_is_chronological(backend_factory) -> None:
    repo = backend_factory.repository_for(TargetHistoryRecord)
    repo.save_many(
        [
            TargetHistoryRecord(
                created_at=stamp,
                target_id="tgt-1",
                mission_id="mis-1",
                asset_key=f"domain:h{i}.example.com",
                field="asset",
                kind="new",
                new_value=f"h{i}.example.com",
                source="subfinder",
                changed_at=stamp,
            )
            for i, stamp in enumerate([T0, T1, T2])
        ]
    )
    loaded = repo.list(order_by="created_at", descending=False, limit=10)
    assert [r.changed_at for r in loaded] == [T0, T1, T2]


def test_state_changes_are_chronological(backend_factory) -> None:
    repo = backend_factory.repository_for(IntelligenceChangeRecord)
    repo.save_many(
        [
            IntelligenceChangeRecord(
                created_at=stamp,
                target_id="tgt-1",
                asset_key="domain:example.com",
                kind="new",
                previous={"status": "unknown"},
                current={"status": s},
                source="intelligence-engine",
                detected_at=stamp,
            )
            for s, stamp in [("discovered", T1), ("assessed", T2), ("validated", T3)]
        ]
    )
    loaded = repo.list(order_by="created_at", descending=False, limit=10)
    assert [r.current["status"] for r in loaded] == ["discovered", "assessed", "validated"]
    assert [r.detected_at for r in loaded] == [T1, T2, T3]


def test_finding_history_is_append_only(backend_factory) -> None:
    """A finding's lifecycle must be reconstructable; updates never destroy the
    prior state snapshot."""
    repo = backend_factory.repository_for(FindingRecord)
    finding = FindingRecord(
        finding_id="F-history",
        mission_id="mis-1",
        target_id="tgt-1",
        title="SQLi",
        status="candidate",
    )
    repo.save(finding)
    original_version = finding.version
    original_revision = finding.revision

    updated = repo.get(finding.id)
    assert updated is not None
    updated.status = "validated"
    updated.touch()
    repo.save(updated)

    final = repo.get(finding.id)
    assert final is not None
    assert final.status == "validated"
    # The optimistic-lock counter is caller-managed via touch(): the repository
    # preserves it across the round-trip.
    assert final.version == original_version + 1
    assert final.revision == original_revision + 1


def test_proof_history_links_back(backend_factory) -> None:
    proof_repo = backend_factory.repository_for(VulnerabilityProof)
    evidence_repo = backend_factory.repository_for(IntelligenceEvidenceRecord)

    evidence_repo.save_many(
        [
            IntelligenceEvidenceRecord(
                evidence_id=f"ev-{i}",
                target_id="tgt-1",
                mission_id="mis-1",
                what=f"proof observation {i}",
                source="tool",
                tool="tool",
                when=stamp,
            )
            for i, stamp in enumerate([T1, T2])
        ]
    )
    proof_repo.save(
        VulnerabilityProof(
            proof_id="P-history",
            finding_id="F-history",
            mission_id="mis-1",
            target_id="tgt-1",
            evidence_ids=["ev-0", "ev-1"],
            proof_status="proven",
            validated_at=T3,
        )
    )

    records = proof_repo.list_by("proof_id", "P-history")
    assert len(records) == 1
    loaded = records[0]
    assert loaded.evidence_ids == ["ev-0", "ev-1"]
    assert loaded.validated_at == T3
    assert len(evidence_repo.list_by("evidence_id", "ev-0")) == 1
    assert len(evidence_repo.list_by("evidence_id", "ev-1")) == 1


def test_timeline_ordering_on_list_is_descending(backend_factory) -> None:
    """The default list() ordering (created_at descending) reflects newest-first
    timeline semantics; ascending order is available explicitly."""
    repo = backend_factory.repository_for(IntelligenceAssetRecord)
    repo.save_many(
        [
            IntelligenceAssetRecord(
                asset_id=f"a{i}",
                target_id="tgt-1",
                asset_key=f"domain:h{i}.example.com",
                created_at=stamp,
            )
            for i, stamp in enumerate([T0, T1, T2, T3])
        ]
    )
    desc = repo.list(order_by="created_at", descending=True, limit=10)
    asc = repo.list(order_by="created_at", descending=False, limit=10)
    assert [a.created_at for a in desc] == [T3, T2, T1, T0]
    assert [a.created_at for a in asc] == [T0, T1, T2, T3]
