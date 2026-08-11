# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Transaction integrity tests (Sprint 034.3 §19).

Verifies that multi-step persistence operations never leave the database in an
invalid partial state: ``save_many`` batches are atomic, a constraint violation
rolls back cleanly, and a failed write in a finding→evidence→proof flow leaves
no half-written rows and preserves prior committed state.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    URL,
    FindingRecord,
    IntelligenceEvidenceRecord,
    IntelligenceTargetRecord,
    ObservationRecord,
    VulnerabilityProof,
)
from hunterx.domain.exceptions import DomainValidationError

pytest.importorskip("sqlalchemy")


def test_save_many_is_atomic_on_validation_error(sql_factory) -> None:
    repo = sql_factory.repository_for(IntelligenceTargetRecord)
    valid = IntelligenceTargetRecord(target_id="tgt-ok", value="ok.example.com")
    invalid = IntelligenceTargetRecord(id="not-a-valid-ulid", target_id="tgt-bad", value="x")

    with pytest.raises(DomainValidationError):
        repo.save_many([valid, invalid])

    assert repo.count() == 0
    assert repo.count(include_deleted=True) == 0


def test_save_many_rolls_back_on_constraint_violation(sql_factory) -> None:
    url_repo = sql_factory.repository_for(URL)
    first = URL(url="https://dup.example.com/", host="dup.example.com")
    duplicate = URL(url="https://dup.example.com/", host="other.example.com")
    assert first.id != duplicate.id

    with pytest.raises(Exception):
        url_repo.save_many([first, duplicate])

    assert url_repo.count() == 0
    assert url_repo.count(include_deleted=True) == 0


def test_failed_write_leaves_no_half_row(tmp_path) -> None:
    """A DB failure mid-write must not leave a partially written row."""
    import sqlite3

    from hunterx.config.settings import DatabaseSettings
    from hunterx.infrastructure.db.sql.crud import SqlCrudRepository
    from hunterx.infrastructure.db.sql.factory import SessionFactory

    db_path = tmp_path / "nohalf.db"
    sf = SessionFactory(DatabaseSettings(url=f"sqlite:///{db_path}"))
    sf.create_all()
    repo = SqlCrudRepository(sf, IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(target_id="tgt-half", value="half.example.com")
    repo.save(target)

    # A raw insert that omits a required NOT NULL column; the commit must fail
    # and roll back the whole row (no half-written row).
    con = sqlite3.connect(db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "INSERT INTO tidb_intelligence_targets (id, created_at) VALUES (?, ?)",
                ("01JTESTTARGET000000000000A", "2026-08-10T00:00:00+00:00"),
            )
        con.rollback()
    finally:
        con.close()

    # The database remains usable and the prior row is intact.
    assert repo.get(target.id) is not None
    assert repo.count() == 1


def test_finding_evidence_proof_flow_keeps_consistent_state(sql_factory) -> None:
    """The canonical multi-step flow is per-row atomic; a mid-flow failure must
    leave previously committed rows intact and no corrupt proof row."""
    finding_repo = sql_factory.repository_for(FindingRecord)
    evidence_repo = sql_factory.repository_for(IntelligenceEvidenceRecord)
    proof_repo = sql_factory.repository_for(VulnerabilityProof)

    finding = FindingRecord(
        finding_id="F-flow", mission_id="mis-1", target_id="tgt-1", title="SSRF", status="candidate"
    )
    evidence = IntelligenceEvidenceRecord(
        evidence_id="ev-flow",
        target_id="tgt-1",
        mission_id="mis-1",
        what="DNS rebinding observed",
        how="replay",
        source="httpx",
        tool="httpx",
    )
    proof = VulnerabilityProof(
        proof_id="p-flow",
        finding_id="F-flow",
        target_id="tgt-1",
        proof_type="poc",
        proof_status="in_progress",
    )

    finding_repo.save(finding)
    evidence_repo.save(evidence)
    # Simulate a mid-flow failure: invalid proof id rejected by the SQL validator.
    bad_proof = VulnerabilityProof(
        id="not-a-valid-ulid",
        proof_id="p-bad",
        finding_id="F-flow",
        target_id="tgt-1",
    )
    with pytest.raises(DomainValidationError):
        proof_repo.save(bad_proof)

    # Prior committed rows survive and remain queryable.
    assert finding_repo.get(finding.id) is not None
    assert evidence_repo.get(evidence.id) is not None
    assert proof_repo.get(proof.id) is None
    assert proof_repo.count() == 0


def test_mission_state_survives_failed_write(sql_factory) -> None:
    """A failed persistence attempt must not corrupt previously stored state."""
    repo = sql_factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(target_id="tgt-stable", value="stable.example.com", status="active")
    repo.save(target)

    with pytest.raises(DomainValidationError):
        repo.save(
            IntelligenceTargetRecord(id="also-not-valid", target_id="tgt-stable", value="bad.example.com")
        )

    loaded = repo.get(target.id)
    assert loaded is not None
    assert loaded.status == "active"
    assert loaded.value == "stable.example.com"


def test_observation_batch_is_atomic(sql_factory) -> None:
    repo = sql_factory.repository_for(ObservationRecord)
    ok = ObservationRecord(observation_id="obs-1", target_id="tgt-1", tool="nmap", value="80/open")
    bad = ObservationRecord(id="not-a-valid-ulid", observation_id="obs-2", target_id="tgt-1", tool="x", value="y")

    with pytest.raises(DomainValidationError):
        repo.save_many([ok, bad])

    assert repo.count() == 0
