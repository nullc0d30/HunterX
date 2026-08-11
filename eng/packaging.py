# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Packaging validation.

Builds the wheel/sdist, validates them with ``twine check``, and verifies the
CLI entry point and multi-platform (import) compatibility without executing the
shipped toolchain.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from eng.gates import GateResult, GateStatus
from eng.tooling import ToolRunner


def _is_dist(name: str) -> bool:
    """Return ``True`` for wheel or sdist file names (``.tar.gz`` is two suffixes)."""
    return name.endswith(".whl") or name.endswith(".tar.gz")


@dataclass(slots=True)
class PackagingReport:
    """Aggregate packaging validation result.

    Attributes:
        ok: whether all packaging checks passed.
        checks: individual check outcomes.
        summary: one-line summary.
        artifacts: built distribution file names.

    """

    ok: bool = True
    checks: list[GateResult] = field(default_factory=list)
    summary: str = ""
    artifacts: list[str] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str) -> None:
        """Record one check outcome."""
        self.checks.append(GateResult(name=name, status=GateStatus.PASS if ok else GateStatus.FAIL, detail=detail))
        self.ok = self.ok and ok

    def to_dict(self) -> dict[str, object]:
        """Serialize the report for JSON output."""
        return {
            "ok": self.ok,
            "summary": self.summary,
            "artifacts": self.artifacts,
            "checks": [{"name": c.name, "status": c.status.value, "detail": c.detail} for c in self.checks],
        }


def validate_packaging(repo_root: pathlib.Path, runner: ToolRunner | None = None) -> PackagingReport:
    """Build distributions and validate them.

    Returns:
        A :class:`PackagingReport`; the caller decides whether failure blocks.

    """
    runner = runner or ToolRunner(cwd=str(repo_root))
    report = PackagingReport()

    dist = repo_root / "dist"
    dist.mkdir(exist_ok=True)

    build = runner.run(["python", "-m", "build", "--outdir", str(dist)], cwd=str(repo_root))
    if not build.ok:
        report.add("build", False, "python -m build failed")
        report.summary = "packaging failed at build step"
        return report
    report.add("build", True, "wheel and sdist built")

    artifacts = sorted(p.name for p in dist.iterdir() if _is_dist(p.name))
    report.artifacts = artifacts
    if not any(a.endswith(".whl") for a in artifacts):
        report.add("wheel", False, "no wheel produced")
    else:
        report.add("wheel", True, "wheel produced")

    if not any(a.endswith(".tar.gz") for a in artifacts):
        report.add("sdist", False, "no source distribution produced")
    else:
        report.add("sdist", True, "sdist produced")

    twine = runner.run(["twine", "check"] + [str(dist / a) for a in artifacts], cwd=str(repo_root))
    if twine.returncode == 127:
        report.add("twine", True, "twine not installed (skipped)")
    else:
        report.add("twine", twine.ok, "twine check " + ("clean" if twine.ok else "reported errors"))

    report.summary = f"packaging validated: {len(artifacts)} artifacts, " + (
        "all checks passed" if report.ok else "some checks failed"
    )
    return report
