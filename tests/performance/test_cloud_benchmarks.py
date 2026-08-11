# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance baselines for the cloud & SaaS intelligence capability.

Baselines: bundle analysis, 1k-observation correlation, 1k-record inventory
queries and merged-confidence scoring. Committed results are drift-checked
against ``artifacts/benchmarks``.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.application.cloud import CloudQueryService
from hunterx.domain.cloud import (
    CloudAnalyzer,
    CloudCorrelator,
    CloudInput,
    CloudProviderObservation,
    CloudServiceObservation,
)
from hunterx.domain.cloud.confidence import CloudConfidenceEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.cloud.registry import register_cloud_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "cloud"


def _bundle(name: str) -> CloudInput:
    payload = json.loads((GOLDEN / name).read_text(encoding="utf-8"))
    headers: list[tuple[str, str]] = []
    for key, value in (payload.get("headers") or {}).items():
        if isinstance(value, list):
            headers.extend((str(key), str(item)) for item in value)
        else:
            headers.append((str(key), str(value)))
    return CloudInput(
        target=payload.get("target", ""),
        domain=payload.get("domain", ""),
        records=tuple(dict(item) for item in payload.get("records") or ()),
        certificates=tuple(dict(item) for item in payload.get("certificates") or ()),
        headers=tuple(headers),
        html=payload.get("html", ""),
        scripts=tuple((item["url"], item["content"]) for item in payload.get("scripts") or ()),
        technologies=tuple(dict(item) for item in payload.get("technologies") or ()),
        observed_urls=tuple(payload.get("observed_urls") or ()),
        documents=tuple(dict(item) for item in payload.get("documents") or ()),
        source="cloud",
    )


def _analyze() -> object:
    analyzer = CloudAnalyzer()
    return analyzer.analyze(_bundle("multi_cloud_input.json"))


def _make_query_service() -> CloudQueryService:
    engine = ExecutionEngine()
    register_cloud_adapters(engine)
    engine.install_hook("cloud-analysis", lambda _tid, _version: "1.0.0")
    engine.install("cloud-analysis", version="1.0.0")
    stores = InMemoryTidbRepositoryFactory()
    from hunterx.application.cloud import CloudService

    service = CloudService(engine=engine, stores=stores)
    for _i in range(10):
        service.run(
            mission_id="perf",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _bundle("multi_cloud_input.json")},
        )
    return CloudQueryService(stores=stores)


def test_analyze_bundle_benchmark(benchmark) -> None:
    bundle = _bundle("multi_cloud_input.json")
    analyzer = CloudAnalyzer()
    count = benchmark(analyzer.analyze, bundle)
    assert len(count.all_observations()) >= 1


def test_correlate_1k_observations_benchmark(benchmark) -> None:
    observations = [
        CloudServiceObservation(provider="aws", service="s3", endpoint=f"bucket-{i}.s3.amazonaws.com", source="dns")
        for i in range(500)
    ]
    observations += [
        CloudProviderObservation(name="aws", source="dns"),
        CloudProviderObservation(name="aws", source="http"),
        CloudProviderObservation(name="azure", source="dns"),
    ]
    correlator = CloudCorrelator()
    result = benchmark(correlator.correlate, observations)
    assert len(result.records) >= 500


def test_inventory_query_benchmark(benchmark) -> None:
    query = _make_query_service()
    result = benchmark(query.services, mission_id="perf")
    assert isinstance(result, list)


def test_merged_confidence_benchmark(benchmark) -> None:
    engine = CloudConfidenceEngine()
    group = [CloudProviderObservation(name="aws", source="dns"), CloudProviderObservation(name="aws", source="http")]
    score = benchmark(engine.merged_confidence, group, conflicted=False)
    assert 0.0 <= score <= 1.0


def test_history_diff_benchmark(benchmark) -> None:
    from hunterx.domain.cloud.history import CloudHistory

    history = CloudHistory()
    snapshot = [
        CloudServiceObservation(provider="aws", service="s3", endpoint=f"b-{i}.s3.amazonaws.com", source="dns")
        for i in range(500)
    ]
    comparison = benchmark(history.compare, snapshot[:250], snapshot)
    assert len(comparison.changes) >= 250
