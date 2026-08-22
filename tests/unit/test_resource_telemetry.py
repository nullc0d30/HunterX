# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-governance tests: runtime memory instrumentation.

The probe records a cross-sectional snapshot (process RSS/VmRSS, process-tree
RSS, heap, mission aggregate sizes and serialized bytes, model context) used to
classify where a runaway's memory actually lives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.resource.telemetry import (
    MissionMemoryProbe,
    TelemetryLog,
    collection_metrics,
    mapping_metrics,
    process_status_mb,
)


@dataclass
class _Obs:
    observation_id: str = "o"
    content: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"observation_id": self.observation_id, "content": self.content}


@dataclass
class _Context:
    observations: list[Any] = field(default_factory=list)
    decisions: list[Any] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    tool_executions: list[Any] = field(default_factory=list)
    attack_paths: list[Any] = field(default_factory=list)
    surface_relationships: list[Any] = field(default_factory=list)
    history: list[Any] = field(default_factory=list)
    endpoints: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    assets: dict[str, Any] = field(default_factory=dict)
    technologies: dict[str, Any] = field(default_factory=dict)
    services: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    proofs: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Mission:
    mission_id: str = "m1"
    observations: list[Any] = field(default_factory=list)
    hypotheses: list[Any] = field(default_factory=list)
    decisions: list[Any] = field(default_factory=list)
    branches: list[Any] = field(default_factory=list)
    runs: list[Any] = field(default_factory=list)
    trace: list[Any] = field(default_factory=list)
    negative_evidence: list[Any] = field(default_factory=list)
    baselines: list[Any] = field(default_factory=list)
    differential_results: list[Any] = field(default_factory=list)
    impact_analyses: list[Any] = field(default_factory=list)
    novel_behaviors: list[Any] = field(default_factory=list)
    telemetry_snapshots: list[Any] = field(default_factory=list)
    checkpoints: list[Any] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    context: _Context = field(default_factory=_Context)


class TestCollectionMetrics:
    def test_counts_and_approx_bytes(self) -> None:
        metrics = collection_metrics("observations", [_Obs(content={"blob": "x" * 5000}), _Obs(content={"blob": "y" * 3000})])
        assert metrics.count == 2
        assert metrics.approx_bytes >= 8000

    def test_mapping_metrics(self) -> None:
        metrics = mapping_metrics("services", {"s1": {"identity": "tcp:80"}, "s2": {"identity": "tcp:443"}})
        assert metrics.count == 2
        assert metrics.approx_bytes > 0


class TestMissionMemoryProbe:
    def test_snapshot_is_json_safe(self) -> None:
        mission = _Mission(observations=[_Obs(content={"blob": "x" * 20000})], coverage={"a": {"b": {"state": "tested"}}})
        probe = MissionMemoryProbe()
        record = probe.snapshot(mission_id="m1", mission=mission, governor=None)
        assert record["mission_id"] == "m1"
        assert "vmrss_mb" in record
        assert "process_tree_rss_mb" in record
        assert "mission_aggregate_approx_bytes" in record
        assert record["mission_aggregate_approx_bytes"] >= 20000
        assert record["model"]["enabled"] is False
        # JSON-safe round trip.
        import json

        json.dumps(record)

    def test_aggregate_bytes_sums_collections(self) -> None:
        probe = MissionMemoryProbe()
        mission = _Mission(observations=[_Obs(content={"blob": "x" * 10000})], context=_Context(endpoints={"e1": {"key": "k"}}))
        collections = probe.measure_mission(mission)
        assert probe.aggregate_bytes(collections) >= 10000

    def test_process_status_returns_three_keys(self) -> None:
        status = process_status_mb()
        assert set(status) == {"vmrss_mb", "vmhwm_mb", "vmpeak_mb"}


class TestTelemetryLog:
    def test_append_ignores_empty_path(self, tmp_path) -> None:
        log = TelemetryLog("")
        log.append({"a": 1})  # must not raise

    def test_append_writes_json_lines(self, tmp_path) -> None:
        path = str(tmp_path / "telemetry.jsonl")
        log = TelemetryLog(path)
        log.append({"a": 1})
        log.append({"b": {"c": [1, 2]}})
        with open(path, encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        assert len(lines) == 2
        import json

        assert json.loads(lines[0]) == {"a": 1}


__all__ = []
