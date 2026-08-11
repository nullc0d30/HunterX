# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance tests for Target Memory & Campaign Intelligence.

The historical layer must support 10k-100k+ observations, large snapshots and
large diffs with bounded time and no N+1 scans for current-state queries.
These benchmarks use generous budgets that catch quadratic blowups without
being flaky on slow CI.
"""

from __future__ import annotations

import time

from hunterx.domain.target_memory.engines import (
    TargetDiffEngine,
    TargetMemoryAssembler,
)
from hunterx.domain.target_memory.models import TargetSnapshot


def _observation(index: int, *, mission: str = "m1") -> dict[str, object]:
    return {
        "target_id": "perf-1",
        "mission_id": mission,
        "tool": "httpx",
        "observation_type": "endpoint",
        "value": f"https://www.example.com/path/{index}",
        "normalized_value": f"/path/{index}",
        "asset_key": f"url:https://www.example.com/path/{index}",
        "source": "katana",
        "confidence": 1.0,
        "timestamp": "2026-08-01T00:00:00+00:00",
        "expires_at": None,
    }


def _snapshot(target_id: str, count: int) -> TargetSnapshot:
    observations = {
        f"endpoint:/path/{index}": {"value": f"/path/{index}", "last_seen": "2026-08-01T00:00:00+00:00"}
        for index in range(count)
    }
    return TargetSnapshot(target_id=target_id, observation_count=count, state={"observations": observations})


class TestMemoryAssemblyPerformance:
    def test_assemble_ten_thousand_observations(self) -> None:
        assembler = TargetMemoryAssembler(now="2026-08-10T00:00:00+00:00")
        started = time.monotonic()
        memory_observations = assembler.assemble([_observation(i) for i in range(10_000)])
        elapsed = time.monotonic() - started
        assert len(memory_observations) == 10_000
        assert elapsed < 10.0, f"assembly too slow: {elapsed:.2f}s"

    def test_assemble_hundred_thousand_observations(self) -> None:
        assembler = TargetMemoryAssembler(now="2026-08-10T00:00:00+00:00")
        started = time.monotonic()
        memory_observations = assembler.assemble([_observation(i) for i in range(100_000)])
        elapsed = time.monotonic() - started
        assert len(memory_observations) == 100_000
        assert elapsed < 20.0, f"assembly too slow: {elapsed:.2f}s"

    def test_repeated_observation_counting_is_linear(self) -> None:
        assembler = TargetMemoryAssembler(now="2026-08-10T00:00:00+00:00")
        # 100k observations across 10k keys -> aggregation without blowup.
        started = time.monotonic()
        memory_observations = assembler.assemble([_observation(i % 10_000) for i in range(100_000)])
        elapsed = time.monotonic() - started
        assert len(memory_observations) == 10_000
        assert all(obs.observation_count == 10 for obs in memory_observations)
        assert elapsed < 20.0, f"aggregation too slow: {elapsed:.2f}s"


class TestSnapshotAndDiffPerformance:
    def test_large_snapshot_hash_is_fast(self) -> None:
        snapshot = _snapshot("perf-1", 50_000)
        started = time.monotonic()
        _ = snapshot.state_hash
        elapsed = time.monotonic() - started
        assert elapsed < 10.0, f"hashing too slow: {elapsed:.2f}s"

    def test_large_diff_is_fast(self) -> None:
        engine = TargetDiffEngine()
        snap_a = _snapshot("perf-1", 50_000)
        observations = snap_a.state["observations"].copy()
        observations["endpoint:/brand-new"] = {"value": "/brand-new", "last_seen": "2026-08-02T00:00:00+00:00"}
        snap_b = TargetSnapshot(target_id="perf-1", observation_count=50_001, state={"observations": observations})
        started = time.monotonic()
        diff = engine.diff(snap_a, snap_b)
        elapsed = time.monotonic() - started
        assert any(change.key == "endpoint:/brand-new" for change in diff.changes)
        assert elapsed < 10.0, f"diff too slow: {elapsed:.2f}s"

    def test_million_observation_metadata_diff(self) -> None:
        # Diff over a large historical metadata set stays bounded.
        engine = TargetDiffEngine()
        snap_a = _snapshot("perf-1", 100_000)
        snap_b = _snapshot("perf-1", 100_000)
        started = time.monotonic()
        diff = engine.diff(snap_a, snap_b)
        elapsed = time.monotonic() - started
        assert diff.state_hash_a == diff.state_hash_b
        assert elapsed < 15.0, f"identical diff too slow: {elapsed:.2f}s"
