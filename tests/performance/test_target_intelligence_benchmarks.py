# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance tests for the Adaptive Target Intelligence layer.

The system must support thousands of assets and millions of observations with
bounded in-memory growth and no N+1 scans. These benchmarks exercise the
ingestion, coverage, correlation and cycle pipelines at scale with generous
budgets that catch quadratic blowups without being flaky on slow CI.
"""

from __future__ import annotations

import time

from hunterx.domain.target_intelligence.enums import (
    IntelligenceTargetKind,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import IntelligenceTarget, Observation
from hunterx.engines.target_intelligence import TargetIntelligenceEngine


def _target() -> IntelligenceTarget:
    return IntelligenceTarget(
        target_id="perf-1",
        mission_id="mis-1",
        scope="example.com",
        identity="Perf",
        kind=IntelligenceTargetKind.DOMAIN,
        value="example.com",
    )


def _observation(index: int) -> Observation:
    return Observation(
        target_id="perf-1",
        mission_id="mis-1",
        tool="httpx",
        capability="technology_fingerprint",
        observation_type=ObservationType.TECHNOLOGY,
        value=f"tech-{index}",
        asset_key=f"hostname:host-{index % 1000}.example.com",
    )


class TestTargetIntelligencePerformance:
    def test_ingest_thousands_of_observations(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        started = time.monotonic()
        engine.ingest_observations(target, [_observation(i) for i in range(10_000)])
        elapsed = time.monotonic() - started
        assert engine.observations.count(target_id="perf-1") == 10_000
        assert elapsed < 10.0, f"ingestion too slow: {elapsed:.2f}s"

    def test_observation_dedup_is_constant_time(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_observations(target, [_observation(i) for i in range(2_000)])
        started = time.monotonic()
        engine.ingest_observations(target, [_observation(i) for i in range(2_000)])
        elapsed = time.monotonic() - started
        assert engine.observations.count(target_id="perf-1") == 2_000  # duplicates dropped
        assert elapsed < 5.0, f"dedup too slow: {elapsed:.2f}s"

    def test_coverage_matrix_queries_scale(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        engine.ingest_observations(target, [_observation(i) for i in range(5_000)])
        started = time.monotonic()
        matrix = engine.coverage.matrix("perf-1")
        state = engine.snapshot(target)
        elapsed = time.monotonic() - started
        assert matrix.entries
        assert state.observation_count == 5_000
        assert elapsed < 5.0, f"matrix query too slow: {elapsed:.2f}s"

    def test_cycle_runs_with_many_assets(self) -> None:
        engine = TargetIntelligenceEngine()
        target = _target()
        engine.register_target(target)
        from hunterx.domain.target_intelligence.models import IntelligenceAsset
        from hunterx.domain.topology.enums import EntityKind

        engine.ingest_assets(
            target,
            [
                IntelligenceAsset(
                    target_id="perf-1",
                    mission_id="mis-1",
                    kind=EntityKind.URL,
                    name=f"https://host-{i}.example.com/api/search?q=x",
                    properties={"parameters": ["q"]},
                )
                for i in range(1_000)
            ],
        )
        started = time.monotonic()
        state, actions, decision = engine.run_cycle(target, mission_objective="find vulns", authorization_granted=True)
        elapsed = time.monotonic() - started
        assert state.assets
        assert actions
        assert elapsed < 10.0, f"cycle too slow: {elapsed:.2f}s"

    def test_correlation_of_large_batch(self) -> None:
        from hunterx.domain.target_intelligence.correlation import IntelligenceCorrelationEngine

        engine = IntelligenceCorrelationEngine()
        observations = [
            _observation(i)
            for i in range(5_000)
            for _ in range(2)
        ]
        started = time.monotonic()
        result = engine.correlate(observations)
        elapsed = time.monotonic() - started
        assert result.chains
        assert elapsed < 5.0, f"correlation too slow: {elapsed:.2f}s"
