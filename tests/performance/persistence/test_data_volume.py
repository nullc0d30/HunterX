# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Data-volume tests (Sprint 034.3 §25).

Generates a representative dataset (thousands of assets, endpoints,
observations, findings) and measures insert, query, list, correlation and
report-retrieval latency to identify pathological queries.
"""

from __future__ import annotations

import time

import pytest

from hunterx.domain.entities.tidb import (
    URL,
    Endpoint,
    FindingRecord,
    IntelligenceAssetRecord,
    IntelligenceEvidenceRecord,
    ObservationRecord,
)

pytest.importorskip("sqlalchemy")

_ASSETS = 3000
_ENDPOINTS = 2000
_OBSERVATIONS = 3000
_FINDINGS = 1000


@pytest.fixture(scope="module")
def volume_factory(tmp_path_factory):
    from hunterx.config.settings import DatabaseSettings
    from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
    from hunterx.infrastructure.db.sql.factory import SessionFactory

    factory = SessionFactory(
        DatabaseSettings(url=f"sqlite:///{tmp_path_factory.mktemp('volume') / 'volume.db'}")
    )
    factory.create_all()
    store = SqlTidbRepositoryFactory(factory)
    try:
        yield store
    finally:
        factory.dispose()


@pytest.fixture(scope="module")
def volume_dataset(volume_factory):
    t0 = time.perf_counter()
    asset_repo = volume_factory.repository_for(IntelligenceAssetRecord)
    obs_repo = volume_factory.repository_for(ObservationRecord)
    url_repo = volume_factory.repository_for(URL)
    endpoint_repo = volume_factory.repository_for(Endpoint)
    finding_repo = volume_factory.repository_for(FindingRecord)

    asset_repo.save_many(
        [
            IntelligenceAssetRecord(
                asset_id=f"asset-{i}",
                target_id=f"tgt-{i % 3}",
                mission_id=f"mis-{i % 3}",
                asset_key=f"domain:h{i}.example.com",
                name=f"h{i}.example.com",
            )
            for i in range(_ASSETS)
        ]
    )
    obs_repo.save_many(
        [
            ObservationRecord(
                observation_id=f"obs-{i}",
                target_id=f"tgt-{i % 3}",
                mission_id=f"mis-{i % 3}",
                tool="nmap",
                value=f"port-{80 + (i % 50)}",
                normalized_value=f"tcp/{80 + (i % 50)}",
            )
            for i in range(_OBSERVATIONS)
        ]
    )
    url_repo.save_many(
        [
            URL(
                url=f"https://h{i}.example.com/api/{i}",
                host=f"h{i}.example.com",
                path=f"/api/{i}",
                target_id=f"tgt-{i % 3}",
            )
            for i in range(_ENDPOINTS)
        ]
    )
    endpoint_repo.save_many(
        [
            Endpoint(
                url_id=f"url-{i}",
                method="GET",
                path=f"/api/{i}",
                discovered_by="katana",
            )
            for i in range(_ENDPOINTS)
        ]
    )
    finding_repo.save_many(
        [
            FindingRecord(
                finding_id=f"F-{i}",
                mission_id=f"mis-{i % 3}",
                target_id=f"tgt-{i % 3}",
                title=f"finding {i}",
                severity="high" if i % 2 else "medium",
                status="candidate",
                evidence_refs=[f"ev-{i}"],
            )
            for i in range(_FINDINGS)
        ]
    )
    elapsed = time.perf_counter() - t0
    return {"elapsed": elapsed}


def test_bulk_insert_succeeds(volume_factory, volume_dataset) -> None:
    assert volume_factory.repository_for(IntelligenceAssetRecord).count() == _ASSETS
    assert volume_factory.repository_for(ObservationRecord).count() == _OBSERVATIONS
    assert volume_factory.repository_for(Endpoint).count() == _ENDPOINTS
    assert volume_factory.repository_for(FindingRecord).count() == _FINDINGS
    # Bulk load of the representative dataset completes without pathological
    # slowness (5000+ rows in well under 60s on a dev machine).
    assert volume_dataset["elapsed"] < 60.0


def test_scoped_list_is_fast(volume_factory, volume_dataset) -> None:
    t0 = time.perf_counter()
    assets = volume_factory.repository_for(IntelligenceAssetRecord).list_by("target_id", "tgt-0", limit=2000)
    assert len(assets) == 1000
    elapsed = time.perf_counter() - t0
    assert elapsed < 5.0


def test_scoped_observation_query_is_fast(volume_factory, volume_dataset) -> None:
    t0 = time.perf_counter()
    observations = volume_factory.repository_for(ObservationRecord).list_by("mission_id", "mis-1", limit=5000)
    assert len(observations) == 1000
    elapsed = time.perf_counter() - t0
    assert elapsed < 5.0


def test_correlation_query_is_fast(volume_factory, volume_dataset) -> None:
    t0 = time.perf_counter()
    findings = volume_factory.repository_for(FindingRecord).list_by("target_id", "tgt-2", limit=2000)
    assert len(findings) == 333
    # Correlation: one finding → its evidence refs (single lookup each).
    evidence_repo = volume_factory.repository_for(IntelligenceEvidenceRecord)
    for finding in findings:
        evidence_repo.list_by("evidence_id", finding.evidence_refs[0] if finding.evidence_refs else "none", limit=1)
    elapsed = time.perf_counter() - t0
    assert elapsed < 20.0


def test_report_retrieval_is_fast(volume_factory, volume_dataset) -> None:
    """Report-style retrieval (findings for a mission grouped by severity) is a
    bounded set of indexed queries."""
    t0 = time.perf_counter()
    findings = volume_factory.repository_for(FindingRecord).list_by("mission_id", "mis-0", limit=5000)
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    elapsed = time.perf_counter() - t0
    assert elapsed < 10.0
    assert sum(by_severity.values()) == 334


def test_pagination_is_stable(volume_factory, volume_dataset) -> None:
    repo = volume_factory.repository_for(IntelligenceAssetRecord)
    page1 = repo.list(limit=1000, offset=0, order_by="created_at", descending=True)
    page2 = repo.list(limit=1000, offset=1000, order_by="created_at", descending=True)
    assert len(page1) == 1000 and len(page2) == 1000
    assert {e.id for e in page1}.isdisjoint({e.id for e in page2})


def test_stream_scales_to_thousands(volume_factory, volume_dataset) -> None:
    repo = volume_factory.repository_for(ObservationRecord)
    streamed = list(repo.stream(batch_size=500))
    assert len(streamed) == _OBSERVATIONS
