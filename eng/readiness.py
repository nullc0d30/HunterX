# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Final production-readiness assessment.

Combines architecture health, security health, code quality, coverage,
documentation, dependency and release readiness into a single scored report
with a production-readiness score and technical-debt summary.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from eng.gates import GateReport, GateStatus
from eng.supplychain import LicenseCheck, LockCheck


@dataclass(slots=True)
class ReadinessAssessment:
    """The final readiness report.

    Attributes:
        scores: named score components (each 0..100).
        gate_report: the quality-gate report backing the score.
        lock_check: lock-file consistency outcome.
        license_check: license allow-list outcome.
        tech_debt: list of technical-debt entries.
        overall: weighted production-readiness score.
        ready: whether HunterX is production ready (all mandatory gates pass).
        generated_at: ISO timestamp.

    """

    scores: dict[str, float] = field(default_factory=dict)
    gate_report: GateReport | None = None
    lock_check: LockCheck | None = None
    license_check: LicenseCheck | None = None
    tech_debt: list[str] = field(default_factory=list)
    overall: float = 0.0
    ready: bool = False
    generated_at: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize the assessment for JSON output."""
        return {
            "generated_at": self.generated_at,
            "scores": {k: round(v, 1) for k, v in self.scores.items()},
            "overall": round(self.overall, 1),
            "ready": self.ready,
            "tech_debt": self.tech_debt,
            "gates": self.gate_report.to_dict() if self.gate_report else None,
            "lock_check": {"ok": self.lock_check.ok, "detail": self.lock_check.detail} if self.lock_check else None,
            "license_check": {
                "ok": self.license_check.ok,
                "detail": self.license_check.detail,
                "disallowed": self.license_check.disallowed,
            }
            if self.license_check
            else None,
        }


#: Component weights must sum to 1.0.
_WEIGHTS = {
    "architecture": 0.15,
    "security": 0.20,
    "quality": 0.15,
    "coverage": 0.15,
    "documentation": 0.10,
    "dependencies": 0.10,
    "release": 0.10,
    "performance": 0.05,
}


def _gate_score(report: GateReport, names: tuple[str, ...]) -> float:
    """Score 0..100 for a group of gates (100 when all pass)."""
    relevant = [r for r in report.results if r.name in names]
    if not relevant:
        return 100.0
    passed = sum(1 for r in relevant if r.status == GateStatus.PASS)
    return round(passed / len(relevant) * 100.0, 1)


def assess_readiness(
    repo_root: pathlib.Path,
    gate_report: GateReport | None = None,
    lock_check: LockCheck | None = None,
    license_check: LicenseCheck | None = None,
) -> ReadinessAssessment:
    """Compute the readiness assessment for a repository.

    Args:
        repo_root: repository root (used for coverage artifact and tech-debt
            detection).
        gate_report: result of the quality-gate run; when ``None`` a fresh run
            is executed.
        lock_check: lock-file consistency result; computed when ``None``.
        license_check: license allow-list result; computed when ``None``.

    """
    from eng.gates import GateRunner, GateSpec
    from eng.gates.checks import default_checks
    from eng.supplychain import check_licenses, check_lock_consistency

    if gate_report is None:
        runner = GateRunner(
            gates=[
                GateSpec(name=n)
                for n in (
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
                )
            ],
            checks=default_checks(),
            repo_root=repo_root,
        )
        gate_report = runner.run()
    if lock_check is None:
        lock_check = check_lock_consistency(repo_root)
    if license_check is None:
        license_check = check_licenses(repo_root)

    scores = {
        "architecture": _gate_score(gate_report, ("architecture",)),
        "security": _gate_score(gate_report, ("security", "dependencies", "compliance")),
        "quality": _gate_score(gate_report, ("ruff", "mypy", "pytest", "deadcode")),
        "coverage": _coverage_score(repo_root, gate_report),
        "documentation": _gate_score(gate_report, ("docs",)),
        "dependencies": 100.0 if lock_check.ok else 40.0,
        "release": _gate_score(gate_report, ("git-diff", "packaging")),
        "performance": _gate_score(gate_report, ("performance",)),
    }

    overall = round(sum(scores[k] * _WEIGHTS[k] for k in _WEIGHTS), 1)
    ready = gate_report.blocked is False and lock_check.ok
    tech_debt = _collect_tech_debt(repo_root, gate_report, license_check)

    assessment = ReadinessAssessment(
        scores=scores,
        gate_report=gate_report,
        lock_check=lock_check,
        license_check=license_check,
        tech_debt=tech_debt,
        overall=overall,
        ready=ready,
        generated_at=datetime.now(UTC).isoformat(),
    )

    out_dir = repo_root / "artifacts"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "readiness.json").write_text(json.dumps(assessment.to_dict(), indent=2) + "\n", encoding="utf-8")
    return assessment


def _coverage_score(repo_root: pathlib.Path, report: GateReport) -> float:
    """Derive a coverage score from the coverage gate result."""
    for result in report.results:
        if result.name == "coverage":
            if result.status == GateStatus.FAIL:
                return 40.0
            if result.status == GateStatus.PASS:
                return 100.0
            return 60.0  # could not measure
    return 100.0


def _collect_tech_debt(repo_root: pathlib.Path, report: GateReport, license_check: LicenseCheck) -> list[str]:
    """Assemble a human-readable technical-debt summary."""
    debt: list[str] = []
    for result in report.results:
        if result.status == GateStatus.FAIL:
            debt.append(f"{result.name}: {result.detail}")
        elif result.status == GateStatus.ERROR:
            debt.append(f"{result.name}: gate could not execute ({result.detail})")
    for entry in license_check.disallowed:
        debt.append(f"license: {entry} not in allow-list")
    return debt
