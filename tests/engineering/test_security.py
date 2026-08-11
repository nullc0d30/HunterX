# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the security pipeline (eng.security)."""

from __future__ import annotations

import json
import pathlib

from eng.gates import GateStatus
from eng.security import (
    SecurityReport,
    SecurityScanner,
    _count_findings,
    run_security_pipeline,
    to_gate_result,
)
from eng.tooling import ToolResult


class _FakeRunner:
    """Emulates a toolchain where only pip-audit/safety/bandit exist."""

    def __init__(self, outcomes: dict[str, ToolResult]) -> None:
        self.outcomes = outcomes
        self.calls: list[list[str]] = []

    def available(self, executable: str) -> bool:
        return executable in self.outcomes

    def run(
        self, args: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int = 600
    ) -> ToolResult:
        self.calls.append(args)
        return self.outcomes.get(args[0], ToolResult(returncode=127, stderr=f"missing {args[0]}"))


def test_skipped_when_tool_missing() -> None:
    runner = _FakeRunner({})
    scanner = SecurityScanner("bandit", "bandit", ["-r", "src"], pathlib.Path("."), runner)
    result = scanner.scan()
    assert result.status == "skipped"


def test_pass_when_tool_clean(tmp_path: pathlib.Path) -> None:
    runner = _FakeRunner({"bandit": ToolResult(returncode=0, stdout="No issues found.\n")})
    scanner = SecurityScanner("bandit", "bandit", ["-r", "src"], tmp_path, runner)
    result = scanner.scan()
    assert result.status == "pass"
    assert result.findings == 0


def test_fail_when_findings(tmp_path: pathlib.Path) -> None:
    runner = _FakeRunner({"bandit": ToolResult(returncode=1, stdout="Issue: B101\nTotal issues: 3\n")})
    scanner = SecurityScanner("bandit", "bandit", ["-r", "src"], tmp_path, runner)
    result = scanner.scan()
    assert result.status == "fail"
    assert result.findings == 3
    # the artifact is written under artifacts/security/
    assert result.report is not None
    assert (tmp_path / result.report).is_file()


def test_findings_count_bandit() -> None:
    result = ToolResult(returncode=1, stdout="Total issues: 5")
    assert _count_findings("bandit", result) == 5


def test_findings_count_pip_audit_json() -> None:
    payload = json.dumps([{"name": "a", "version": "1.0"}, {"name": "b", "version": "2.0"}])
    result = ToolResult(returncode=1, stdout=payload)
    assert _count_findings("pip-audit", result) == 2


def test_findings_count_safety_dict() -> None:
    payload = '{"report_meta": {"vulnerabilities_found": 0}}'
    result = ToolResult(returncode=0, stdout=payload)
    assert _count_findings("safety", result) == 0
    payload2 = '{"report_meta": {"vulnerabilities_found": 4}}'
    result2 = ToolResult(returncode=1, stdout=payload2)
    assert _count_findings("safety", result2) == 4


def test_findings_count_safety_with_banner_prefix() -> None:
    payload = "DEPRECATED: this command (`check`) has been DEPRECATED.\n\n{\"report_meta\": {\"vulnerabilities_found\": 2}}"
    result = ToolResult(returncode=1, stdout=payload)
    assert _count_findings("safety", result) == 2


def test_error_status_when_platform_blocks_executable(tmp_path: pathlib.Path) -> None:
    runner = _FakeRunner({"bandit": ToolResult(returncode=126, stderr="could not execute bandit: policy")})
    scanner = SecurityScanner("bandit", "bandit", ["-r", "src"], tmp_path, runner)
    result = scanner.scan()
    assert result.status == "error"
    assert "policy" in result.detail


def test_findings_count_trivy_json() -> None:
    payload = json.dumps(
        [
            {
                "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}, {"VulnerabilityID": "CVE-2"}],
                "Secrets": [{"RuleID": "aws"}],
                "Misconfigurations": [],
            },
            {"Vulnerabilities": [], "Secrets": []},
        ]
    )
    result = ToolResult(returncode=1, stdout=payload)
    assert _count_findings("trivy-fs", result) == 3


def test_trivy_image_skipped_when_image_unavailable(tmp_path: pathlib.Path) -> None:
    runner = _FakeRunner(
        {"trivy": ToolResult(returncode=1, stdout="", stderr="unable to initialize a docker client: image not found")}
    )
    scanner = SecurityScanner(
        "trivy-image",
        "trivy",
        ["image", "--exit-code", "1", "nullc0d30/hunterx:latest"],
        tmp_path,
        runner,
        skip_failures_containing=("image not found", "unable to"),
    )
    result = scanner.scan()
    assert result.status == "skipped"


def test_run_security_pipeline_aggregates(tmp_path: pathlib.Path) -> None:
    (tmp_path / "requirements.lock").write_text("pydantic==2.0.0\n", encoding="utf-8")
    runner = _FakeRunner(
        {
            "bandit": ToolResult(returncode=0, stdout="clean"),
            "semgrep": ToolResult(returncode=0, stdout="{}"),
            "pip-audit": ToolResult(returncode=0, stdout="[]"),
            "safety": ToolResult(returncode=0, stdout=""),
            "gitleaks": ToolResult(returncode=0, stdout=""),
            "trivy": ToolResult(returncode=0, stdout="[]"),
        }
    )
    report = run_security_pipeline(tmp_path, runner=runner)
    assert report.failed == 0
    assert report.blocked is False
    assert report.summary.startswith("7/7")
    assert (tmp_path / "artifacts" / "security-report.json").is_file()


def test_pipeline_fails_on_vulnerabilities(tmp_path: pathlib.Path) -> None:
    (tmp_path / "requirements.lock").write_text("pydantic==2.0.0\n", encoding="utf-8")
    runner = _FakeRunner(
        {
            "bandit": ToolResult(returncode=0, stdout="clean"),
            "semgrep": ToolResult(returncode=0, stdout="{}"),
            "pip-audit": ToolResult(returncode=1, stdout='[{"name":"x"}]'),
            "safety": ToolResult(returncode=0, stdout=""),
            "gitleaks": ToolResult(returncode=0, stdout=""),
            "trivy": ToolResult(returncode=0, stdout="[]"),
        }
    )
    report = run_security_pipeline(tmp_path, runner=runner)
    assert report.blocked is True
    assert report.failed >= 1


def test_to_gate_result() -> None:
    gate = to_gate_result(SecurityReport(scans=[], failed=0, blocked=False))
    assert gate.name == "security-pipeline"
    assert gate.status == GateStatus.PASS
    gate = to_gate_result(SecurityReport(scans=[], failed=1, blocked=True))
    assert gate.status == GateStatus.FAIL
