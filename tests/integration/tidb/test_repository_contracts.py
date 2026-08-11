# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Repository contract tests (Sprint 034.3 §17).

The same contract suite runs against the in-memory and SQL TIDB repository
implementations. The suite verifies equivalent semantic behavior for the
documented ``TidbRepository`` port operations.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    URL,
    FindingRecord,
    IntelligenceAssetRecord,
    IntelligenceTargetRecord,
    ObservationRecord,
)
from hunterx.domain.exceptions import DomainValidationError, NotFoundError


@pytest.fixture()
def factory(backend_factory):
    return backend_factory


def test_save_and_get_roundtrip(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(
        target_id="tgt-contract", mission_id="mis-1", value="example.com", kind="domain"
    )
    repo.save(target)

    loaded = repo.get(target.id)
    assert loaded is not None
    assert loaded.target_id == "tgt-contract"
    assert loaded.value == "example.com"
    assert loaded.kind == "domain"
    assert loaded.created_at == target.created_at


def test_upsert_does_not_duplicate(factory) -> None:
    repo = factory.repository_for(IntelligenceAssetRecord)
    asset = IntelligenceAssetRecord(asset_id="a1", target_id="tgt-1", asset_key="domain:example.com")
    repo.save(asset)
    asset.properties = {"color": "blue"}
    repo.save(asset)

    assert repo.count() == 1
    loaded = repo.get(asset.id)
    assert loaded.properties == {"color": "blue"}


def test_get_absent_returns_none(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    assert repo.get("does-not-exist") is None


def test_get_or_raise_absent_raises(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    with pytest.raises(NotFoundError):
        repo.get_or_raise("does-not-exist")


def test_soft_delete_hides_and_restores(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(target_id="tgt-soft", value="soft.example.com")
    repo.save(target)
    repo.soft_delete(target.id)

    assert repo.get(target.id) is None
    assert repo.count() == 0
    restored = repo.get(target.id, include_deleted=True)
    assert restored is not None
    assert restored.is_deleted
    assert repo.count(include_deleted=True) == 1


def test_soft_deleted_rows_hidden_from_list_and_list_by(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    live = IntelligenceTargetRecord(target_id="tgt-live", value="live.example.com")
    dead = IntelligenceTargetRecord(target_id="tgt-dead", value="dead.example.com")
    repo.save(live)
    repo.save(dead)
    repo.soft_delete(dead.id)

    listed = repo.list(limit=100)
    assert all(e.id != dead.id for e in listed)
    assert any(e.id == live.id for e in listed)

    filtered = repo.list_by("target_id", "tgt-dead")
    assert filtered == []
    assert len(repo.list_by("target_id", "tgt-live")) == 1


def test_hard_delete(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(target_id="tgt-hard", value="hard.example.com")
    repo.save(target)
    repo.delete(target.id)
    assert repo.get(target.id, include_deleted=True) is None
    assert repo.count(include_deleted=True) == 0


def test_hard_delete_absent_raises(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    with pytest.raises(NotFoundError):
        repo.delete("does-not-exist")


def test_save_many_and_count(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    targets = [
        IntelligenceTargetRecord(target_id=f"tgt-{i}", value=f"host-{i}.example.com")
        for i in range(20)
    ]
    assert repo.save_many(targets) == 20
    assert repo.count() == 20
    assert repo.count(include_deleted=True) == 20


def test_list_pagination_and_ordering(factory) -> None:
    repo = factory.repository_for(IntelligenceTargetRecord)
    repo.save_many(
        [IntelligenceTargetRecord(target_id=f"tgt-list-{i}", value=f"host-{i}.example.com") for i in range(10)]
    )
    page = repo.list(limit=5, offset=0, order_by="created_at", descending=True)
    assert len(page) == 5
    page2 = repo.list(limit=5, offset=5, order_by="created_at", descending=True)
    ids1 = {e.id for e in page}
    ids2 = {e.id for e in page2}
    assert ids1.isdisjoint(ids2)
    assert len(ids1 | ids2) == 10


def test_list_by_filters(factory) -> None:
    repo = factory.repository_for(ObservationRecord)
    repo.save_many(
        [
            ObservationRecord(observation_id=f"obs-{i}", target_id="tgt-a", tool="nmap", value=f"p{i}")
            for i in range(3)
        ]
    )
    repo.save(ObservationRecord(observation_id="obs-x", target_id="tgt-b", tool="naabu", value="p0"))
    found = repo.list_by("target_id", "tgt-a")
    assert len(found) == 3
    assert all(e.target_id == "tgt-a" for e in found)


def test_stream_yields_all(factory) -> None:
    repo = factory.repository_for(URL)
    repo.save_many(
        [URL(url=f"https://h{i}.example.com/", host=f"h{i}.example.com") for i in range(50)]
    )
    streamed = list(repo.stream(batch_size=7))
    assert len(streamed) == 50
    assert repo.count() == 50


def test_json_fields_survive_roundtrip(factory) -> None:
    repo = factory.repository_for(FindingRecord)
    finding = FindingRecord(
        finding_id="F-contract",
        mission_id="mis-1",
        target_id="tgt-1",
        title="SQL injection on search",
        severity="high",
        affected_assets=["https://example.com/search"],
        observations=[{"type": "behavioral_differential", "observed": True}],
        evidence_refs=["ev-1", "ev-2"],
        scope={"authorized": True},
    )
    repo.save(finding)
    loaded = repo.get(finding.id)
    assert loaded.affected_assets == ["https://example.com/search"]
    assert loaded.observations == [{"type": "behavioral_differential", "observed": True}]
    assert loaded.evidence_refs == ["ev-1", "ev-2"]
    assert loaded.scope == {"authorized": True}
    assert loaded.title == "SQL injection on search"


def test_documented_validation_divergence(factory) -> None:
    """Documented semantic divergence (Sprint 034.3 §17).

    The SQL repository validates the TIDB envelope on ``save`` and rejects an
    invalid entity; the in-memory repository does not validate. This is the one
    intentional behavioral difference between the two backends.
    """
    bad = IntelligenceTargetRecord(id="not-a-valid-ulid", target_id="t", value="x")
    if hasattr(factory, "_session_factory"):
        with pytest.raises(DomainValidationError):
            factory.repository_for(IntelligenceTargetRecord).save(bad)
    else:
        factory.repository_for(IntelligenceTargetRecord).save(bad)
        assert factory.repository_for(IntelligenceTargetRecord).get(bad.id) is not None


def test_documented_unknown_field_divergence(factory) -> None:
    """Documented semantic divergence (Sprint 034.3 §17).

    SQL ``list_by``/``list`` reject unknown columns with ``ValueError``; the
    in-memory repository silently returns empty results.
    """
    repo = factory.repository_for(IntelligenceTargetRecord)
    if hasattr(factory, "_session_factory"):
        with pytest.raises(ValueError):
            repo.list_by("no_such_column", 1)
    else:
        assert repo.list_by("no_such_column", 1) == []
