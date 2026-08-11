# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the readiness assessment (eng.readiness)."""

from __future__ import annotations

import pathlib

from eng.gates import GateReport, GateResult, GateStatus
from eng.readiness import assess_readiness
from eng.supplychain import LicenseCheck, LockCheck


def _passing_report() -> GateReport:
    results = []
    for name in (
        "ruff",
        "mypy",
        "pytest",
        "coverage",
        "architecture",
        "deadcode",
        "dependencies",
        "docs",
        "security",
        "performance",
        "compliance",
        "hygiene",
    ):
        results.append(GateResult(name=name, status=GateStatus.PASS))
    results.append(GateResult(name="git-diff", status=GateStatus.PASS))
    results.append(GateResult(name="packaging", status=GateStatus.PASS))
    return GateReport(results=results)


def test_readiness_passes_when_all_green(tmp_path: pathlib.Path) -> None:
    assessment = assess_readiness(
        tmp_path,
        gate_report=_passing_report(),
        lock_check=LockCheck(ok=True),
        license_check=LicenseCheck(ok=True),
    )
    assert assessment.ready is True
    assert assessment.overall >= 90.0
    assert assessment.scores["security"] == 100.0
    assert assessment.scores["architecture"] == 100.0
    assert (tmp_path / "artifacts" / "readiness.json").is_file()


def test_readiness_not_ready_on_mandatory_failure(tmp_path: pathlib.Path) -> None:
    report = _passing_report()
    report.results.append(GateResult(name="mypy", status=GateStatus.FAIL, mandatory=True))
    assessment = assess_readiness(
        tmp_path,
        gate_report=report,
        lock_check=LockCheck(ok=True),
        license_check=LicenseCheck(ok=True),
    )
    assert assessment.ready is False
    assert any("mypy" in d for d in assessment.tech_debt)


def test_readiness_locked_dependencies_drop_score(tmp_path: pathlib.Path) -> None:
    assessment = assess_readiness(
        tmp_path,
        gate_report=_passing_report(),
        lock_check=LockCheck(ok=False, detail="unlocked: rich"),
        license_check=LicenseCheck(ok=True),
    )
    assert assessment.scores["dependencies"] == 40.0
    assert assessment.ready is False


def test_readiness_serializes_scores(tmp_path: pathlib.Path) -> None:
    assessment = assess_readiness(
        tmp_path,
        gate_report=_passing_report(),
        lock_check=LockCheck(ok=True),
        license_check=LicenseCheck(ok=True),
    )
    data = assessment.to_dict()
    for name in (
        "architecture",
        "security",
        "quality",
        "coverage",
        "documentation",
        "dependencies",
        "release",
        "performance",
    ):
        assert name in data["scores"]
    assert "overall" in data
    assert "tech_debt" in data
