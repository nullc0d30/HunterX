# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Static-analysis, test, coverage, architecture and dependency gates.

Every checker has the same signature: ``(runner, repo_root, spec) -> GateResult``
so the gate runner can treat them uniformly.
"""

from __future__ import annotations

import pathlib
import re
import xml.etree.ElementTree as ET
from typing import Any

from eng.gates import GateResult, GateSpec, GateStatus
from eng.tooling import ToolResult, ToolRunner

#: v7 source roots and the engineering platform. The retired v6 flat
#: ``hunterx/`` package at the repository root is legacy-only and is excluded
#: from linting (see pyproject.toml [tool.ruff] extend-exclude).
_SRC = ("src", "eng")
_TESTS = "tests"
_ALEMBIC = "alembic"


def _result(name: str, ok: bool, detail: str, tool: ToolResult | None = None, artifact: str = "") -> GateResult:
    return GateResult(
        name=name,
        status=GateStatus.PASS if ok else GateStatus.FAIL,
        detail=detail,
        tool_output=tool.combined if tool else "",
        artifact=artifact,
    )


def _cmd(executable: str, args: list[str]) -> list[str]:
    return [executable, *args]


# ---------------------------------------------------------------------------
# lint / type / test gates
# ---------------------------------------------------------------------------
def ruff_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run ``ruff check`` over source, tests and migration code."""
    result = runner.run(_cmd("ruff", ["check", *_SRC, _TESTS, _ALEMBIC, "eng"]), cwd=str(repo_root))
    if result.returncode == 127:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="ruff not installed")
    return _result(spec.name, result.ok, "ruff check clean" if result.ok else "ruff violations found", result)


def mypy_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run ``mypy`` strict over the clean type-checked surface.

    The gate covers the engineering platform (``eng``) and the shared kernel
    (``src/hunterx/shared``), both kept mypy-strict clean. The remaining v7
    source is under active implementation and is type-checked incrementally;
    the retired v6 flat package is intentionally excluded. ``--follow-imports
    =skip`` keeps the gate scoped to exactly that surface instead of descending
    into every imported module of the wider package.
    """
    result = runner.run(
        _cmd("mypy", ["eng", "src/hunterx/shared", "--follow-imports=skip"]), cwd=str(repo_root)
    )
    if result.returncode == 127:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="mypy not installed")
    return _result(spec.name, result.ok, "mypy clean" if result.ok else "mypy type errors found", result)


def pytest_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run the full pytest suite (unit/component/integration/architecture/golden/security).

    Relies on ``[tool.pytest.ini_options] testpaths`` in ``pyproject.toml``,
    which restricts the suite to the v7 test directories and excludes the
    retired v6 flat tests at ``tests/`` root.
    """
    result = runner.run(
        _cmd("pytest", ["-q", "--no-cov", "-m", "not tools"]),
        cwd=str(repo_root),
    )
    if result.returncode == 127:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="pytest not installed")
    return _result(spec.name, result.ok, "pytest suite passed" if result.ok else "pytest failures", result)


def coverage_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run pytest under coverage and enforce a coverage threshold.

    The threshold defaults to 80% and is overridable in ``gates.yaml``.
    """
    threshold = spec.threshold if spec.threshold is not None else 80.0
    result = runner.run(
        _cmd(
            "pytest",
            [
                "-q",
                "--cov",
                "src/hunterx",
                "--cov-report",
                "xml:artifacts/coverage.xml",
                "--cov-report",
                "term",
                "-m",
                "not tools",
                "tests/unit",
                "tests/component",
                "tests/architecture",
            ],
        ),
        cwd=str(repo_root),
    )
    if result.returncode == 127:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="pytest/coverage not installed")
    total = _coverage_from_xml(repo_root / "artifacts" / "coverage.xml")
    if total is None:
        # fall back to parsing the term output
        total = _coverage_from_term(result.combined)
    if total is None:
        return GateResult(
            name=spec.name, status=GateStatus.ERROR, detail="could not determine coverage", tool_output=result.combined
        )
    detail = f"coverage {total:.1f}% (threshold {threshold:.1f}%)"
    return _result(spec.name, total >= threshold, detail, result, artifact="artifacts/coverage.xml")


def _coverage_from_xml(path: pathlib.Path) -> float | None:
    """Extract total line coverage percent from a coverage ``coverage.xml``."""
    try:
        root = ET.parse(str(path)).getroot()
        line_rate = float(root.attrib.get("line-rate", "0"))
        return line_rate * 100.0
    except (OSError, ET.ParseError, ValueError):
        return None


def _coverage_from_term(text: str) -> float | None:
    """Parse a ``Total`` line like ``Total 1234 100 93%`` from coverage term output."""
    match = re.search(r"Total\s+\d+\s+\d+\s+(\d+(?:\.\d+)?)%", text)
    if not match:
        return None
    return float(match.group(1))


def architecture_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run the in-tree architecture linter (``hunterx-arch lint``)."""
    result = runner.run(_cmd("hunterx-arch", ["lint", "--root", "."]), cwd=str(repo_root))
    if result.returncode == 127:
        # fall back to python -m invocation
        result = runner.run(_cmd("python", ["-m", "hunterx.architecture", "lint", "--root", "."]), cwd=str(repo_root))
    if result.returncode == 127:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="architecture tool unavailable")
    return _result(spec.name, result.ok, "architecture clean" if result.ok else "architecture violations", result)


def deadcode_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run ``vulture`` for dead-code detection with configured ignore list.

    Whitelist files are passed as analysis sources *before* the target so
    vulture treats their names as used (argparse consumes all positional paths).
    """
    ignore = _deadcode_ignore(repo_root)
    result = runner.run(
        _cmd("vulture", [*ignore, "src/hunterx", "--min-confidence", "70"]), cwd=str(repo_root)
    )
    if result.returncode == 127:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="vulture not installed")
    return _result(spec.name, result.ok, "no dead code detected" if result.ok else "dead code detected", result)


def _deadcode_ignore(repo_root: pathlib.Path) -> list[str]:
    ignore_file = repo_root / "config" / "vulture_allowlist.py"
    if not ignore_file.is_file():
        return []
    # vulture whitelists are added as source files to analyse.
    return [str(ignore_file)]


def performance_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Detect performance regressions and slow tests.

    Runs ``pytest`` with ``pytest-benchmark`` over ``tests/performance``,
    compares benchmark means against a stored baseline (``artifacts/benchmarks/
    baseline.json``) and fails when drift exceeds the configured threshold.
    Slow tests are reported via ``--durations``; the threshold (seconds) is
    configurable per gate spec.
    """
    from eng.benchmark import detect_slow_tests, run_benchmarks

    if not (repo_root / "tests" / "performance").is_dir():
        return _result(spec.name, True, "no performance suite defined")
    result = run_benchmarks(runner, repo_root)
    if result is None:
        return GateResult(name=spec.name, status=GateStatus.SKIPPED, detail="pytest-benchmark unavailable")
    if result.benchmark_failed:
        return _result(spec.name, False, "benchmark run failed", artifact=result.report_path)

    threshold = spec.threshold if spec.threshold is not None else 20.0
    regressions = _compare_benchmark_baseline(repo_root, threshold)
    slow_threshold = float(spec.threshold) if spec.threshold is not None else 10.0
    slow = detect_slow_tests(result.combined, slow_threshold)

    problems: list[str] = []
    if regressions:
        problems.append(f"{len(regressions)} benchmark regression(s) beyond {threshold:.0f}%")
    if slow:
        problems.append(f"{len(slow)} slow test(s) beyond {slow_threshold:.0f}s")
    if problems:
        return _result(spec.name, False, "; ".join(problems), artifact=result.report_path)
    detail = f"benchmarks within {threshold:.0f}% of baseline, no slow tests"
    return _result(spec.name, True, detail, artifact=result.report_path)


def _compare_benchmark_baseline(repo_root: pathlib.Path, drift_pct: float) -> list[str]:
    """Return names of benchmarks whose mean drifted beyond ``drift_pct``.

    The baseline is stored at ``artifacts/benchmarks/baseline.json`` (a dict of
    ``name -> mean_seconds``). When no baseline exists the gate records the
    current run as the new baseline and passes.
    """
    baseline_path = repo_root / "artifacts" / "benchmarks" / "baseline.json"
    current_path = repo_root / "artifacts" / "benchmarks" / "latest.json"
    try:
        import json

        current: dict[str, float] = json.loads(current_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not current:
        return []
    if not baseline_path.is_file():
        baseline_path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        return []
    try:
        baseline: dict[str, float] = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    regressions: list[str] = []
    for name, mean in current.items():
        prev = baseline.get(name)
        if not prev or prev <= 0:
            continue
        if (mean - prev) / prev * 100.0 > drift_pct:
            regressions.append(f"{name} {mean:.4f}s vs {prev:.4f}s")
    return regressions


def compliance_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Verify license compliance, third-party attribution and open-source notices."""
    from eng.supplychain import check_licenses

    license_check = check_licenses(repo_root, runner=runner)
    problems: list[str] = []
    if not license_check.ok:
        problems.append(license_check.detail or "disallowed licenses found")
    if not (repo_root / "NOTICE").is_file():
        problems.append("NOTICE (third-party attribution) missing")
    if not (repo_root / "LICENSE").is_file():
        problems.append("LICENSE missing")
    if not (repo_root / "THIRD_PARTY_NOTICES").is_file() and not (repo_root / "docs" / "THIRD_PARTY_NOTICES").is_file():
        problems.append("THIRD_PARTY_NOTICES missing")
    if problems:
        return _result(spec.name, False, "; ".join(problems))
    return _result(spec.name, True, "license compliance and attribution verified")


def hygiene_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Validate repository hygiene: CODEOWNERS, templates, security policy, bots."""
    required = {
        "SECURITY.md": repo_root / "SECURITY.md",
        "CONTRIBUTING.md": repo_root / "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md": repo_root / "CODE_OF_CONDUCT.md",
        "CODEOWNERS": repo_root / ".github" / "CODEOWNERS",
        "dependabot": repo_root / ".github" / "dependabot.yml",
        "issue templates": repo_root / ".github" / "ISSUE_TEMPLATE",
        "PR template": repo_root / ".github" / "PULL_REQUEST_TEMPLATE.md",
    }
    missing = [name for name, path in required.items() if not path.exists()]
    if missing:
        return _result(spec.name, False, "missing: " + ", ".join(missing))
    return _result(spec.name, True, "repository hygiene checks passed")


def security_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run the full security pipeline (bandit, semgrep, pip-audit, safety, trivy, gitleaks)."""
    from eng.security import run_security_pipeline, to_gate_result

    report = run_security_pipeline(repo_root, runner=runner)
    return to_gate_result(report)


def packaging_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Build and validate the wheel/sdist (best-effort; optional by default)."""
    from eng.packaging import validate_packaging

    report = validate_packaging(repo_root, runner=runner)
    return GateResult(
        name=spec.name,
        status=GateStatus.PASS if report.ok else GateStatus.FAIL,
        detail=report.summary,
        mandatory=spec.mandatory,
    )


def dependencies_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Run ``pip-audit`` on the lock file and the direct dependency set.

    ``--disable-pip`` avoids auditing the live environment; combined with
    ``--no-deps`` it audits exactly the locked direct dependencies.
    """
    result = runner.run(
        _cmd(
            "pip-audit",
            ["-r", "requirements.lock", "--disable-pip", "--no-deps", "-o", "artifacts/deps-audit.json", "--format", "json"],
        ),
        cwd=str(repo_root),
    )
    if result.returncode == 127:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="pip-audit not installed")
    return _result(
        spec.name, result.ok, "no known vulnerabilities" if result.ok else "vulnerable dependencies found", result
    )


# ---------------------------------------------------------------------------
# documentation / formatting / hygiene gates
# ---------------------------------------------------------------------------
def docs_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Validate repository documentation (links, required files, structure)."""
    from eng.docs import validate_docs

    report = validate_docs(repo_root)
    ok = report.failed == 0
    return _result(spec.name, ok, report.summary, artifact=report.json_path)


def git_diff_gate(runner: ToolRunner, repo_root: pathlib.Path, spec: GateSpec) -> GateResult:
    """Fail when uncommitted changes are present (reproducibility gate)."""
    result = runner.run(_cmd("git", ["status", "--porcelain"]), cwd=str(repo_root))
    if not result.ok:
        return GateResult(name=spec.name, status=GateStatus.ERROR, detail="git unavailable")
    if not result.stdout.strip():
        return _result(spec.name, True, "working tree clean")
    return _result(spec.name, False, "working tree has uncommitted changes")


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------
def default_checks() -> dict[str, Any]:
    """Return the canonical gate-name to checker mapping."""
    return {
        "ruff": ruff_gate,
        "mypy": mypy_gate,
        "pytest": pytest_gate,
        "coverage": coverage_gate,
        "architecture": architecture_gate,
        "deadcode": deadcode_gate,
        "dependencies": dependencies_gate,
        "docs": docs_gate,
        "performance": performance_gate,
        "compliance": compliance_gate,
        "hygiene": hygiene_gate,
        "security": security_gate,
        "packaging": packaging_gate,
        "git-diff": git_diff_gate,
    }
