# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the individual quality-gate checkers (eng.gates.checks)."""

from __future__ import annotations

import pathlib

from eng.gates import GateSpec, GateStatus
from eng.gates.checks import (
    compliance_gate,
    coverage_gate,
    hygiene_gate,
    performance_gate,
)
from eng.tooling import ToolResult


class _CannedRunner:
    """Returns canned ToolResults for the tool names the gates invoke."""

    def __init__(self, outcomes: dict[str, ToolResult]) -> None:
        self.outcomes = outcomes

    def available(self, executable: str) -> bool:
        return executable in self.outcomes

    def run(
        self, args: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int = 600
    ) -> ToolResult:
        return self.outcomes.get(args[0], ToolResult(returncode=127, stderr=f"missing {args[0]}"))


def _coverage_term(total: str) -> str:
    return f"Name    Stmts   Miss  Cover\n---------------------------------\nTotal     100     7    {total}%"


def test_coverage_gate_parses_term_output(tmp_path: pathlib.Path) -> None:
    runner = _CannedRunner(
        {
            "pytest": ToolResult(returncode=0, stdout=_coverage_term("92.0")),
        }
    )
    result = coverage_gate(runner, tmp_path, GateSpec(name="coverage", threshold=80.0))
    assert result.status == GateStatus.PASS
    assert "92.0%" in result.detail


def test_coverage_gate_fails_below_threshold(tmp_path: pathlib.Path) -> None:
    runner = _CannedRunner(
        {
            "pytest": ToolResult(returncode=0, stdout=_coverage_term("50.0")),
        }
    )
    result = coverage_gate(runner, tmp_path, GateSpec(name="coverage", threshold=80.0))
    assert result.status == GateStatus.FAIL


def test_coverage_gate_reads_xml(tmp_path: pathlib.Path) -> None:
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    (tmp_path / "artifacts" / "coverage.xml").write_text(
        '<coverage version="7" line-rate="0.88"><sources/><packages/></coverage>',
        encoding="utf-8",
    )
    runner = _CannedRunner(
        {
            "pytest": ToolResult(returncode=0, stdout="no term output"),
        }
    )
    result = coverage_gate(runner, tmp_path, GateSpec(name="coverage", threshold=80.0))
    assert result.status == GateStatus.PASS
    assert result.artifact == "artifacts/coverage.xml"


def test_coverage_gate_error_when_unmeasurable(tmp_path: pathlib.Path) -> None:
    runner = _CannedRunner(
        {
            "pytest": ToolResult(returncode=0, stdout=""),
        }
    )
    result = coverage_gate(runner, tmp_path, GateSpec(name="coverage", threshold=80.0))
    assert result.status == GateStatus.ERROR


def test_hygiene_gate_detects_missing_files(tmp_path: pathlib.Path) -> None:
    (tmp_path / ".github").mkdir(parents=True)
    (tmp_path / ".github" / "ISSUE_TEMPLATE").mkdir()
    (tmp_path / "SECURITY.md").write_text("sec", encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text("cont", encoding="utf-8")
    (tmp_path / "CODE_OF_CONDUCT.md").write_text("coc", encoding="utf-8")
    (tmp_path / ".github" / "PULL_REQUEST_TEMPLATE.md").write_text("pr", encoding="utf-8")
    (tmp_path / ".github" / "dependabot.yml").write_text("dependabot", encoding="utf-8")
    result = hygiene_gate(_CannedRunner({}), tmp_path, GateSpec(name="hygiene"))
    assert result.status == GateStatus.FAIL
    assert "CODEOWNERS" in result.detail


def test_hygiene_gate_passes_when_complete(tmp_path: pathlib.Path) -> None:
    (tmp_path / ".github").mkdir(parents=True)
    (tmp_path / ".github" / "ISSUE_TEMPLATE").mkdir()
    for name in ("SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    (tmp_path / ".github" / "PULL_REQUEST_TEMPLATE.md").write_text("pr", encoding="utf-8")
    (tmp_path / ".github" / "dependabot.yml").write_text("dependabot", encoding="utf-8")
    (tmp_path / ".github" / "CODEOWNERS").write_text("* @owner", encoding="utf-8")
    result = hygiene_gate(_CannedRunner({}), tmp_path, GateSpec(name="hygiene"))
    assert result.status == GateStatus.PASS


def test_compliance_gate_detects_missing_attribution(tmp_path: pathlib.Path) -> None:
    (tmp_path / "LICENSE").write_text("apache", encoding="utf-8")
    (tmp_path / "NOTICE").write_text("notice", encoding="utf-8")
    result = compliance_gate(_CannedRunner({}), tmp_path, GateSpec(name="compliance"))
    assert result.status == GateStatus.FAIL
    assert "THIRD_PARTY_NOTICES" in result.detail


def test_compliance_gate_passes_with_attribution(tmp_path: pathlib.Path) -> None:
    (tmp_path / "LICENSE").write_text("apache", encoding="utf-8")
    (tmp_path / "NOTICE").write_text("notice", encoding="utf-8")
    (tmp_path / "THIRD_PARTY_NOTICES").write_text("notices", encoding="utf-8")
    result = compliance_gate(_CannedRunner({}), tmp_path, GateSpec(name="compliance"))
    assert result.status == GateStatus.PASS


def test_performance_gate_skips_without_performance_dir(tmp_path: pathlib.Path) -> None:
    (tmp_path / "tests").mkdir()
    result = performance_gate(_CannedRunner({}), tmp_path, GateSpec(name="performance"))
    assert result.status == GateStatus.PASS
