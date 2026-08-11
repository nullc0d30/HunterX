# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the performance gate helpers (eng.benchmark)."""

from __future__ import annotations

import json
import pathlib

from eng.benchmark import detect_slow_tests
from eng.gates.checks import _compare_benchmark_baseline
from eng.tooling import ToolResult


class _FakeRunner:
    def __init__(self, outcomes: dict[str, ToolResult]) -> None:
        self.outcomes = outcomes

    def available(self, executable: str) -> bool:
        return executable in self.outcomes

    def run(
        self, args: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int = 600
    ) -> ToolResult:
        return self.outcomes.get(args[0], ToolResult(returncode=127))


def test_detect_slow_tests() -> None:
    text = (
        "========= slowest durations =========\n"
        "0.50s call test_fast\n"
        "12.30s call test_slow_one\n"
        "30.00s call test_slow_two\n"
    )
    slow = detect_slow_tests(text, 10.0)
    assert [s.split(" ")[0] for s in slow] == ["test_slow_one", "test_slow_two"]


def test_detect_slow_tests_no_matches() -> None:
    assert detect_slow_tests("0.10s call test_fast\n", 10.0) == []


def test_compare_benchmark_baseline_creates_baseline(tmp_path: pathlib.Path) -> None:
    out_dir = tmp_path / "artifacts" / "benchmarks"
    out_dir.mkdir(parents=True)
    (out_dir / "latest.json").write_text(json.dumps({"test_a": 1.0}), encoding="utf-8")
    regressions = _compare_benchmark_baseline(tmp_path, 20.0)
    assert regressions == []
    assert (out_dir / "baseline.json").is_file()


def test_compare_benchmark_baseline_detects_regression(tmp_path: pathlib.Path) -> None:
    out_dir = tmp_path / "artifacts" / "benchmarks"
    out_dir.mkdir(parents=True)
    (out_dir / "latest.json").write_text(json.dumps({"test_a": 1.5}), encoding="utf-8")
    (out_dir / "baseline.json").write_text(json.dumps({"test_a": 1.0}), encoding="utf-8")
    regressions = _compare_benchmark_baseline(tmp_path, 20.0)
    assert len(regressions) == 1
    assert "test_a" in regressions[0]


def test_compare_benchmark_baseline_within_drift(tmp_path: pathlib.Path) -> None:
    out_dir = tmp_path / "artifacts" / "benchmarks"
    out_dir.mkdir(parents=True)
    (out_dir / "latest.json").write_text(json.dumps({"test_a": 1.1}), encoding="utf-8")
    (out_dir / "baseline.json").write_text(json.dumps({"test_a": 1.0}), encoding="utf-8")
    assert _compare_benchmark_baseline(tmp_path, 20.0) == []
