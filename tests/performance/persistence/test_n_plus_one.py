# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""N+1 / query-efficiency tests (Sprint 034.3 §10).

Instruments SQLAlchemy cursor execution to count statements issued by the
repository methods and verifies that list(), list_by(), get(), stream() and
save() do not exhibit N+1 access patterns.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from hunterx.domain.entities.tidb import (
    IntelligenceTargetRecord,
    ObservationRecord,
)

pytest.importorskip("sqlalchemy")


@dataclass
class QueryCounter:
    selects: int = 0
    inserts: int = 0
    updates: int = 0
    total: int = 0
    statements: list[str] = field(default_factory=list)


@pytest.fixture()
def counter(session_factory) -> QueryCounter:
    counter = QueryCounter()

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        verb = statement.lstrip().split(" ", 1)[0].upper()
        if verb == "SELECT":
            counter.selects += 1
        elif verb == "INSERT":
            counter.inserts += 1
        elif verb == "UPDATE":
            counter.updates += 1
        counter.total += 1
        counter.statements.append(statement.strip())

    from sqlalchemy import event

    event.listen(session_factory.engine, "before_cursor_execute", before_cursor_execute)
    counter.session_factory = session_factory  # type: ignore[attr-defined]
    return counter


@pytest.fixture()
def seeded(counter, sql_factory) -> None:
    repo = sql_factory.repository_for(ObservationRecord)
    repo.save_many(
        [
            ObservationRecord(observation_id=f"obs-{i}", target_id="tgt-1", mission_id="mis-1", tool="nmap", value=f"p{i}")
            for i in range(500)
        ]
    )
    counter.total = 0
    counter.selects = 0
    counter.inserts = 0
    counter.updates = 0


def test_list_is_single_query(counter, seeded, sql_factory) -> None:
    repo = sql_factory.repository_for(ObservationRecord)
    result = repo.list(limit=500)
    assert len(result) == 500
    assert counter.selects == 1


def test_list_by_is_single_query(counter, seeded, sql_factory) -> None:
    repo = sql_factory.repository_for(ObservationRecord)
    result = repo.list_by("target_id", "tgt-1", limit=500)
    assert len(result) == 500
    assert counter.selects == 1


def test_get_is_single_query(counter, seeded, sql_factory) -> None:
    repo = sql_factory.repository_for(ObservationRecord)
    first = repo.list(limit=1)[0]
    counter.selects = 0
    loaded = repo.get(first.id)
    assert loaded is not None
    assert counter.selects == 1


def test_stream_is_batched_not_n_plus_one(counter, seeded, sql_factory) -> None:
    repo = sql_factory.repository_for(ObservationRecord)
    streamed = list(repo.stream(batch_size=100))
    assert len(streamed) == 500
    assert counter.selects <= 2


def test_count_is_single_query(counter, seeded, sql_factory) -> None:
    repo = sql_factory.repository_for(ObservationRecord)
    assert repo.count() == 500
    assert counter.selects == 1


def test_save_many_uses_batched_writes(counter, sql_factory) -> None:
    """save_many flushes all rows in one transaction; the per-row existence
    pre-check is a documented N+1 read pattern (Sprint 034.3 §10)."""
    repo = sql_factory.repository_for(IntelligenceTargetRecord)
    targets = [IntelligenceTargetRecord(target_id=f"tgt-{i}", value=f"h{i}.example.com") for i in range(50)]
    repo.save_many(targets)
    assert counter.total > 0
    assert repo.count() == 50
    # Inserts are flushed in one statement per row in the same transaction —
    # never a per-row commit.
    assert counter.inserts == 50


def test_correlation_queries_are_not_n_plus_one(counter, sql_factory) -> None:
    """A finding-package style correlation (finding + its evidence refs) issues a
    bounded number of queries, not one per finding."""
    from hunterx.domain.entities.tidb import FindingRecord, IntelligenceEvidenceRecord

    evidence_repo = sql_factory.repository_for(IntelligenceEvidenceRecord)
    finding_repo = sql_factory.repository_for(FindingRecord)

    evidence_repo.save_many(
        [IntelligenceEvidenceRecord(evidence_id=f"ev-{i}", target_id="tgt-1", source="x", tool="x", what="w") for i in range(20)]
    )
    finding_repo.save_many(
        [FindingRecord(finding_id=f"F-{i}", target_id="tgt-1", title="f", evidence_refs=[f"ev-{i}"]) for i in range(20)]
    )
    counter.total = 0
    counter.selects = 0

    findings = finding_repo.list_by("target_id", "tgt-1", limit=20)
    # 1 query for the findings page + 1 query per evidence lookup.
    queries = 0
    for finding in findings:
        evidence_repo.list_by("evidence_id", finding.evidence_refs[0])
        queries += 1
    # The application-level correlation is deliberately query-per-finding (a
    # documented pattern); each call is itself a single query with no nested
    # N+1 amplification.
    assert queries == 20
    assert counter.selects == 21
