# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Concurrency tests (Sprint 034.3 §18).

Concurrent writes against the same target, different targets, the same finding
and different findings are exercised on a file-backed SQLite database (WAL +
busy timeout). The suite verifies no silent data loss, no duplicate records and
a consistent final state.
"""

from __future__ import annotations

import threading

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.entities.tidb import (
    FindingRecord,
    IntelligenceAssetRecord,
    IntelligenceTargetRecord,
    ObservationRecord,
)
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory

pytest.importorskip("sqlalchemy")


@pytest.fixture()
def file_factory(tmp_path):
    from sqlalchemy import create_engine

    url = f"sqlite:///{tmp_path}/concurrency.db"
    engine = create_engine(
        url,
        connect_args={"timeout": 30, "check_same_thread": False},
    )
    with engine.connect() as con:
        con.exec_driver_sql("PRAGMA journal_mode=WAL")
        con.exec_driver_sql("PRAGMA busy_timeout=30000")
    factory = SessionFactory(DatabaseSettings(url=url), engine=engine)
    factory.create_all()
    try:
        yield factory
    finally:
        factory.dispose()


def _run_concurrent(workers: list) -> list:
    threads = [threading.Thread(target=worker) for worker in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    results = []
    for worker in workers:
        results.append(worker.result)
    return results


def test_concurrent_writes_to_different_targets(file_factory) -> None:
    factory = SqlTidbRepositoryFactory(file_factory)

    def make(target_id: str):
        def worker() -> None:
            repo = factory.repository_for(IntelligenceTargetRecord)
            errors = []
            for i in range(10):
                try:
                    repo.save(
                        IntelligenceTargetRecord(
                            target_id=target_id, value=f"{target_id}-{i}.example.com"
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
            worker.result = errors

        worker.result = []
        return worker

    workers = [make(f"tgt-{i}") for i in range(4)]
    errors = _run_concurrent(workers)
    repo = factory.repository_for(IntelligenceTargetRecord)
    assert repo.count() == 40
    assert all(not errs for errs in errors)


def test_concurrent_writes_to_same_target(file_factory) -> None:
    factory = SqlTidbRepositoryFactory(file_factory)

    def worker() -> None:
        repo = factory.repository_for(IntelligenceAssetRecord)
        errors = []
        for i in range(10):
            try:
                repo.save(
                    IntelligenceAssetRecord(
                        asset_id=f"a-{i}", target_id="tgt-shared", asset_key=f"domain:h{i}.example.com"
                    )
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        worker.result = errors

    worker.result = []
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    repo = factory.repository_for(IntelligenceAssetRecord)
    # All 40 distinct asset rows must be present — no lost updates on the shared
    # target's collection (each worker wrote distinct ids).
    assert repo.count() == 40
    assert all(not e for e in worker.result)


def test_concurrent_upsert_same_finding_no_duplicates(file_factory) -> None:
    factory = SqlTidbRepositoryFactory(file_factory)
    repo = factory.repository_for(FindingRecord)
    base = FindingRecord(finding_id="F-race", target_id="tgt-1", title="initial")
    repo.save(base)

    def worker() -> None:
        errors = []
        for i in range(10):
            try:
                # Every thread upserts the same finding id; the row count must
                # never exceed 1.
                repo.save(
                    FindingRecord(id=base.id, finding_id="F-race", target_id="tgt-1", title=f"w{i}")
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
        worker.result = errors

    worker.result = []
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    loaded = repo.get(base.id)
    assert repo.count() == 1
    assert loaded is not None
    assert loaded.finding_id == "F-race"


def test_concurrent_different_findings(file_factory) -> None:
    factory = SqlTidbRepositoryFactory(file_factory)

    def make(prefix: str):
        def worker() -> None:
            repo = factory.repository_for(FindingRecord)
            errors = []
            for i in range(5):
                try:
                    repo.save(FindingRecord(finding_id=f"F-{prefix}-{i}", target_id="tgt-1", title=prefix))
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
            worker.result = errors

        worker.result = []
        return worker

    workers = [make("w1"), make("w2")]
    errors = _run_concurrent(workers)
    assert factory.repository_for(FindingRecord).count() == 10
    assert all(not errs for errs in errors)


def test_concurrent_batch_writes_same_mission(file_factory) -> None:
    factory = SqlTidbRepositoryFactory(file_factory)

    def make(prefix: str):
        def worker() -> None:
            repo = factory.repository_for(ObservationRecord)
            errors = []
            batch = [
                ObservationRecord(
                    observation_id=f"obs-{prefix}-{i}",
                    target_id="tgt-1",
                    mission_id="mis-race",
                    tool="nmap",
                    value=str(i),
                )
                for i in range(10)
            ]
            try:
                repo.save_many(batch)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            worker.result = errors

        worker.result = []
        return worker

    workers = [make("t1"), make("t2")]
    errors = _run_concurrent(workers)

    repo = factory.repository_for(ObservationRecord)
    assert repo.count() == 20
    assert all(e.target_id == "tgt-1" and e.mission_id == "mis-race" for e in repo.stream())
    assert all(not errs for errs in errors)
