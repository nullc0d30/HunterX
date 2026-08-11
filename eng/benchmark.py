# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance gate helpers.

Runs the ``pytest-benchmark`` suite over ``tests/performance`` and exposes two
primitives the performance gate uses:

* :func:`run_benchmarks` — execute the benchmarks and persist both a *latest*
  result and the *baseline* used for drift comparison.
* :func:`detect_slow_tests` — parse the ``--durations`` summary for tests that
  exceed a threshold.

Everything is deterministic and testable; the heavy lifting stays in the
external tools while the gate only interprets their output.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass

from eng.tooling import ToolRunner

_DURATIONS_RE = re.compile(r"^\s*([0-9.]+)s\s+(call|setup|teardown)\s+(\S.*)$")


@dataclass(frozen=True, slots=True)
class BenchmarkRun:
    """Outcome of one benchmark-suite execution.

    Attributes:
        combined: raw pytest output (includes the durations summary).
        report_path: relative path of the normalized benchmark JSON.
        benchmark_failed: whether the benchmark suite itself failed.

    """

    combined: str
    report_path: str
    benchmark_failed: bool


def run_benchmarks(runner: ToolRunner, repo_root: pathlib.Path) -> BenchmarkRun | None:
    """Run the performance suite with pytest-benchmark.

    Returns a :class:`BenchmarkRun`, or ``None`` when pytest is not available
    (the gate then reports skipped).
    """
    out_dir = repo_root / "artifacts" / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    if not runner.available("pytest") and not runner.available("python"):
        return None
    cmd: list[str] = ["pytest"] if runner.available("pytest") else ["python", "-m", "pytest"]
    result = runner.run(
        [
            *cmd,
            "--benchmark-autosave",
            "--benchmark-save",
            "latest",
            "--benchmark-json",
            str(out_dir / "raw.json"),
            "--durations=20",
            "tests/performance/",
        ],
        cwd=str(repo_root),
    )
    if result.returncode == 127:
        return None
    if result.returncode != 0 and "unrecognized arguments" in result.combined:
        return None
    _normalize_benchmark_json(out_dir / "raw.json", out_dir / "latest.json")
    return BenchmarkRun(
        combined=result.combined,
        report_path="artifacts/benchmarks/latest.json",
        benchmark_failed=result.returncode != 0,
    )


def _normalize_benchmark_json(raw_path: pathlib.Path, out_path: pathlib.Path) -> None:
    """Rewrite pytest-benchmark JSON into a ``name -> mean_seconds`` dict.

    The raw pytest-benchmark format nests per-benchmark stats; the baseline
    comparison only needs the mean wall-clock time per benchmark name.
    """
    try:
        data = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    normalized: dict[str, float] = {}
    for item in data.get("benchmarks", []):
        stats = item.get("stats", {})
        name = item.get("name") or item.get("fullname") or ""
        mean = stats.get("mean")
        if name and mean is not None:
            normalized[name] = float(mean)
    out_path.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")


def detect_slow_tests(text: str, threshold: float) -> list[str]:
    """Return the names of tests whose recorded duration exceeds ``threshold``.

    Parses the ``--durations`` summary block produced by pytest.
    """
    slow: list[str] = []
    for line in text.splitlines():
        match = _DURATIONS_RE.match(line)
        if not match:
            continue
        seconds = float(match.group(1))
        if seconds > threshold:
            slow.append(f"{match.group(3)} ({seconds:.2f}s)")
    return slow
