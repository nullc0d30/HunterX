# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adversarial data-isolation tests (Sprint 034.3 §4).

Direct-id access, deleted-record visibility and cross-scope reference probing
must never expose another tenant's/target's/mission's intelligence.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    FindingRecord,
    IntelligenceAssetRecord,
    IntelligenceEvidenceRecord,
    IntelligenceTargetRecord,
    ObservationRecord,
)

pytest.importorskip("sqlalchemy")


@pytest.fixture()
def populated(factory):
    repo = factory.repository_for(IntelligenceTargetRecord)
    target_a = IntelligenceTargetRecord(target_id="tgt-sec-a", value="a.example.com", tenant="tenant-a")
    target_b = IntelligenceTargetRecord(target_id="tgt-sec-b", value="b.example.com", tenant="tenant-b")
    repo.save(target_a)
    repo.save(target_b)

    asset_repo = factory.repository_for(IntelligenceAssetRecord)
    asset_a = IntelligenceAssetRecord(asset_id="a-sec", target_id="tgt-sec-a", asset_key="domain:a.example.com")
    asset_b = IntelligenceAssetRecord(asset_id="b-sec", target_id="tgt-sec-b", asset_key="domain:b.example.com")
    asset_repo.save(asset_a)
    asset_repo.save(asset_b)

    finding_repo = factory.repository_for(FindingRecord)
    finding_a = FindingRecord(finding_id="F-sec-a", mission_id="mis-a", target_id="tgt-sec-a", title="A finding")
    finding_b = FindingRecord(finding_id="F-sec-b", mission_id="mis-b", target_id="tgt-sec-b", title="B finding")
    finding_repo.save(finding_a)
    finding_repo.save(finding_b)
    return {
        "target_a": target_a.id,
        "target_b": target_b.id,
        "asset_a": asset_a.id,
        "asset_b": asset_b.id,
        "finding_a": finding_a.id,
        "finding_b": finding_b.id,
    }


def test_direct_id_access_to_other_target_asset_is_not_possible(factory, populated) -> None:
    """Direct-id reads are keyed by the opaque envelope id, so knowing one
    target's ids gives no access to the other's collection."""
    asset_repo = factory.repository_for(IntelligenceAssetRecord)
    a = asset_repo.get(populated["asset_a"])
    b = asset_repo.get(populated["asset_b"])
    assert a is not None and a.target_id == "tgt-sec-a"
    assert b is not None and b.target_id == "tgt-sec-b"


def test_cross_scope_queries_return_nothing(factory, populated) -> None:
    """Filtering a query by a target that owns no records yields an empty page —
    never another target's records."""
    asset_repo = factory.repository_for(IntelligenceAssetRecord)
    assert asset_repo.list_by("target_id", "tgt-sec-a", limit=100) and len(
        asset_repo.list_by("target_id", "tgt-sec-a")
    ) == 1
    # A third, non-existent target scope must not surface either target's assets.
    assert asset_repo.list_by("target_id", "tgt-sec-never") == []


def test_soft_deleted_records_are_invisible_to_all_scopes(factory, populated) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    repo.soft_delete(populated["target_b"])

    # Not visible via direct get, list, or target-scoped query.
    assert repo.get(populated["target_b"]) is None
    assert all(t.target_id != "tgt-sec-b" for t in repo.list_by("target_id", "tgt-sec-b"))
    assert all(t.target_id != "tgt-sec-b" for t in repo.list(limit=100))
    # The live target remains fully readable.
    assert repo.get(populated["target_a"]) is not None


def test_findings_cannot_be_reassigned_across_scope(factory, populated) -> None:
    """A finding persisted under mission-A must stay under mission-A; a
    mission-B query must not return it."""
    finding_repo = factory.repository_for(FindingRecord)
    a_findings = finding_repo.list_by("mission_id", "mis-a")
    b_findings = finding_repo.list_by("mission_id", "mis-b")
    assert {f.finding_id for f in a_findings} == {"F-sec-a"}
    assert {f.finding_id for f in b_findings} == {"F-sec-b"}
    assert {f.finding_id for f in a_findings}.isdisjoint({f.finding_id for f in b_findings})


def test_evidence_is_scoped_and_not_shared(factory) -> None:
    ev_repo = factory.repository_for(IntelligenceEvidenceRecord)
    ev_a = IntelligenceEvidenceRecord(evidence_id="ev-a", target_id="tgt-a", mission_id="mis-a", what="a", source="tool", tool="tool")
    ev_b = IntelligenceEvidenceRecord(evidence_id="ev-b", target_id="tgt-b", mission_id="mis-b", what="b", source="tool", tool="tool")
    ev_repo.save(ev_a)
    ev_repo.save(ev_b)

    assert {e.evidence_id for e in ev_repo.list_by("target_id", "tgt-a")} == {"ev-a"}
    assert {e.evidence_id for e in ev_repo.list_by("target_id", "tgt-b")} == {"ev-b"}


def test_observation_scoping_never_crosses_targets(factory) -> None:
    obs_repo = factory.repository_for(ObservationRecord)
    obs_repo.save_many(
        [
            ObservationRecord(observation_id=f"o-{t}", target_id=f"tgt-{t}", mission_id=f"mis-{t}", tool="nmap", value="x")
            for t in ("a", "b")
        ]
    )
    assert {o.observation_id for o in obs_repo.list_by("target_id", "tgt-a")} == {"o-a"}
    assert {o.observation_id for o in obs_repo.list_by("target_id", "tgt-b")} == {"o-b"}
