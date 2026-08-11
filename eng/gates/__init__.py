# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Quality-gate framework.

A *gate* is a named check with a deterministic pass/fail outcome and an
optional artifact (report file, coverage xml, etc.). :class:`GateRunner` runs
the configured gates, collects a :class:`GateReport` and can **block** the
pipeline (raise :class:`GateBlockedError`) when any mandatory gate fails.

Gates are defined declaratively in ``eng/config/gates.yaml`` so thresholds can
be tuned without code changes. Each gate maps to a Python callable in
:mod:`eng.gates.checks`.
"""

from __future__ import annotations

import pathlib
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

import yaml

from eng.tooling import ToolRunner


class GateStatus(StrEnum):
    """Outcome of a single gate run."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # gate could not be executed (tool missing, unexpected)
    SKIPPED = "skipped"


@dataclass(slots=True)
class GateResult:
    """Outcome of one gate plus machine-readable detail.

    Attributes:
        name: gate identifier (e.g. ``"ruff"``).
        status: pass/fail/error/skipped.
        detail: short human summary.
        duration_ms: wall-clock time.
        tool_output: captured stdout/stderr for report embedding.
        artifact: optional report file path produced by the gate.
        mandatory: whether failure blocks the merge (from config).

    """

    name: str
    status: GateStatus = GateStatus.SKIPPED
    detail: str = ""
    duration_ms: int = 0
    tool_output: str = ""
    artifact: str = ""
    mandatory: bool = True


@dataclass(slots=True)
class GateReport:
    """Aggregate of all gate results for one run.

    Attributes:
        results: per-gate outcomes.
        started_at: ISO timestamp of the run.
        passed: number of passing gates.
        failed: number of failing gates.
        errors: number of errored gates.
        skipped: number of skipped gates.

    """

    results: list[GateResult] = field(default_factory=list)
    started_at: str = ""

    @property
    def passed(self) -> int:
        """Number of passing gates."""
        return sum(1 for r in self.results if r.status == GateStatus.PASS)

    @property
    def failed(self) -> int:
        """Number of failing gates."""
        return sum(1 for r in self.results if r.status == GateStatus.FAIL)

    @property
    def errors(self) -> int:
        """Number of gates that could not be executed."""
        return sum(1 for r in self.results if r.status == GateStatus.ERROR)

    @property
    def skipped(self) -> int:
        """Number of skipped gates."""
        return sum(1 for r in self.results if r.status == GateStatus.SKIPPED)

    @property
    def blocked(self) -> bool:
        """Return ``True`` when a mandatory gate failed or errored."""
        return any(r.status in (GateStatus.FAIL, GateStatus.ERROR) and r.mandatory for r in self.results)

    def to_dict(self) -> dict[str, object]:
        """Serialize the report to a plain dict for JSON output."""
        return {
            "started_at": self.started_at,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "blocked": self.blocked,
            "results": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "detail": r.detail,
                    "duration_ms": r.duration_ms,
                    "mandatory": r.mandatory,
                    "artifact": r.artifact,
                }
                for r in self.results
            ],
        }


class GateBlockedError(RuntimeError):
    """Raised when the gate runner decides the pipeline must stop."""


@dataclass(slots=True)
class GateSpec:
    """Declarative definition of one gate.

    Attributes:
        name: identifier matching a checker in :mod:`eng.gates.checks`.
        mandatory: whether failure raises :class:`GateBlockedError`.
        threshold: numeric pass threshold (coverage %, seconds, ...).

    """

    name: str
    mandatory: bool = True
    threshold: float | None = None


#: Checker signature: (runner, repo_root, spec) -> GateResult
Checker = Callable[[ToolRunner, pathlib.Path, GateSpec], GateResult]


@dataclass(slots=True)
class GateRunner:
    """Execute a set of gates and aggregate results.

    Attributes:
        gates: gate specs to run.
        checks: mapping of gate name -> checker callable.
        runner: tool invoker (real or fake).
        repo_root: repository root used as working directory.

    """

    gates: list[GateSpec]
    checks: dict[str, Checker]
    runner: ToolRunner = field(default_factory=ToolRunner)
    repo_root: pathlib.Path = field(default_factory=pathlib.Path.cwd)

    def run(self) -> GateReport:
        """Run every gate in declaration order."""
        import time
        from datetime import UTC, datetime

        report = GateReport(started_at=datetime.now(UTC).isoformat())
        for spec in self.gates:
            checker = self.checks.get(spec.name)
            if checker is None:
                report.results.append(
                    GateResult(name=spec.name, status=GateStatus.ERROR, detail="unknown gate", mandatory=spec.mandatory)
                )
                continue
            started = time.monotonic()
            try:
                result = checker(self.runner, self.repo_root, spec)
            except Exception as exc:  # noqa: BLE001 - gate must never crash the pipeline silently
                result = GateResult(
                    name=spec.name,
                    status=GateStatus.ERROR,
                    detail=f"checker raised: {type(exc).__name__}: {exc}",
                    mandatory=spec.mandatory,
                )
            result.mandatory = spec.mandatory
            result.duration_ms = int((time.monotonic() - started) * 1000)
            report.results.append(result)
        return report

    def run_blocking(self) -> GateReport:
        """Run gates and raise :class:`GateBlockedError` if any mandatory gate fails."""
        report = self.run()
        if report.blocked:
            failed = [r.name for r in report.results if r.status in (GateStatus.FAIL, GateStatus.ERROR) and r.mandatory]
            raise GateBlockedError(f"quality gates blocked: {', '.join(failed)}")
        return report


def load_gate_specs(path: pathlib.Path) -> list[GateSpec]:
    """Load gate specifications from ``gates.yaml``."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    specs: list[GateSpec] = []
    for entry in raw.get("gates", []):
        specs.append(
            GateSpec(
                name=str(entry.get("name", "")),
                mandatory=bool(entry.get("mandatory", True)),
                threshold=entry.get("threshold"),
            )
        )
    return specs
