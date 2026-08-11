# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the quality-gate framework (eng.gates)."""

from __future__ import annotations

import pathlib

import pytest
from eng.gates import (
    GateBlockedError,
    GateReport,
    GateResult,
    GateRunner,
    GateSpec,
    GateStatus,
    load_gate_specs,
)
from eng.tooling import ToolResult


class _FakeRunner:
    """A ToolInvoker that returns canned results keyed by first arg."""

    def __init__(self, outcomes: dict[str, ToolResult]) -> None:
        self.outcomes = outcomes

    def run(
        self, args: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int = 600
    ) -> ToolResult:
        return self.outcomes.get(args[0], ToolResult(returncode=0, stdout="", executable=args[0]))


def _ok(name: str) -> GateResult:
    return GateResult(name=name, status=GateStatus.PASS)


def test_report_counts_and_blocking() -> None:
    report = GateReport(
        results=[
            _ok("ruff"),
            GateResult(name="mypy", status=GateStatus.FAIL, mandatory=True),
            GateResult(name="docs", status=GateStatus.PASS, mandatory=False),
        ]
    )
    assert report.passed == 2
    assert report.failed == 1
    assert report.errors == 0
    assert report.blocked is True


def test_optional_failure_does_not_block() -> None:
    report = GateReport(results=[GateResult(name="packaging", status=GateStatus.FAIL, mandatory=False)])
    assert report.blocked is False


def test_error_mandatory_blocks() -> None:
    report = GateReport(results=[GateResult(name="mypy", status=GateStatus.ERROR, mandatory=True)])
    assert report.blocked is True


def test_runner_invokes_checks_and_records_duration(tmp_path: pathlib.Path) -> None:
    runner = GateRunner(
        gates=[GateSpec(name="ruff"), GateSpec(name="missing")],
        checks={"ruff": lambda r, root, spec: _ok(spec.name)},
        runner=_FakeRunner({}),
        repo_root=tmp_path,
    )
    report = runner.run()
    assert report.passed == 1
    unknown = [r for r in report.results if r.name == "missing"][0]
    assert unknown.status == GateStatus.ERROR


def test_run_blocking_raises_on_mandatory_failure(tmp_path: pathlib.Path) -> None:
    runner = GateRunner(
        gates=[GateSpec(name="ruff")],
        checks={"ruff": lambda r, root, spec: GateResult(name=spec.name, status=GateStatus.FAIL)},
        runner=_FakeRunner({}),
        repo_root=tmp_path,
    )
    with pytest.raises(GateBlockedError):
        runner.run_blocking()


def test_run_blocking_passes_when_all_pass(tmp_path: pathlib.Path) -> None:
    runner = GateRunner(
        gates=[GateSpec(name="ruff")],
        checks={"ruff": lambda r, root, spec: _ok(spec.name)},
        runner=_FakeRunner({}),
        repo_root=tmp_path,
    )
    report = runner.run_blocking()
    assert report.blocked is False


def test_runner_catches_checker_exceptions(tmp_path: pathlib.Path) -> None:
    def boom(runner: object, root: pathlib.Path, spec: GateSpec) -> GateResult:
        raise RuntimeError("checker exploded")

    runner = GateRunner(
        gates=[GateSpec(name="ruff")],
        checks={"ruff": boom},
        runner=_FakeRunner({}),
        repo_root=tmp_path,
    )
    report = runner.run()
    assert report.errors == 1
    assert report.results[0].detail.startswith("checker raised")


def test_runner_applies_spec_mandatory_flag(tmp_path: pathlib.Path) -> None:
    """The spec's mandatory flag overrides whatever the checker returned."""
    runner = GateRunner(
        gates=[GateSpec(name="packaging", mandatory=False)],
        checks={"packaging": lambda r, root, spec: GateResult(name=spec.name, status=GateStatus.FAIL)},
        runner=_FakeRunner({}),
        repo_root=tmp_path,
    )
    report = runner.run()
    assert report.results[0].mandatory is False
    assert report.blocked is False


def test_load_gate_specs_reads_yaml(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "gates.yaml"
    path.write_text(
        "gates:\n  - name: coverage\n    mandatory: true\n    threshold: 80.0\n  - name: git-diff\n    mandatory: false\n",
        encoding="utf-8",
    )
    specs = load_gate_specs(path)
    assert specs[0].name == "coverage"
    assert specs[0].threshold == 80.0
    assert specs[0].mandatory is True
    assert specs[1].mandatory is False


def test_gate_result_mandatory_defaults_true() -> None:
    assert GateResult(name="x").mandatory is True
