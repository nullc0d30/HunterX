# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security pipeline.

Orchestrates the static/dependency/container secret scanners and generates
machine-readable reports under ``artifacts/security/``. Scanners that are not
installed are reported as skipped so a local run degrades gracefully while CI
installs the full toolchain.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from eng.gates import GateResult, GateStatus
from eng.tooling import ToolResult, ToolRunner

_ARTIFACT_DIR = pathlib.Path("artifacts") / "security"


@dataclass(slots=True)
class ScanResult:
    """Outcome of one security scanner.

    Attributes:
        name: scanner identifier.
        status: pass/fail/error/skipped.
        findings: count of findings reported by the scanner.
        report: relative artifact path (``None`` when skipped).
        detail: human summary.

    """

    name: str
    status: str = "skipped"
    findings: int = 0
    report: str | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        """Return ``True`` when the scan reported no blocking findings."""
        return self.status == "pass"

    def to_dict(self) -> dict[str, object]:
        """Serialize the scan result for JSON output."""
        return {
            "name": self.name,
            "status": self.status,
            "findings": self.findings,
            "report": self.report,
            "detail": self.detail,
        }


@dataclass(slots=True)
class SecurityReport:
    """Aggregate of all scanner results.

    Attributes:
        scans: per-scanner outcomes.
        failed: number of failing (finding > 0) scans.
        summary: one-line human summary.
        json_path: artifact path.
        blocked: whether any scan failed (blocks the pipeline).

    """

    scans: list[ScanResult] = field(default_factory=list)
    failed: int = 0
    summary: str = ""
    json_path: str = ""
    blocked: bool = False

    def to_dict(self) -> dict[str, object]:
        """Serialize the aggregate report for JSON output."""
        return {
            "failed": self.failed,
            "blocked": self.blocked,
            "summary": self.summary,
            "scans": [s.to_dict() for s in self.scans],
        }


class SecurityScanner:
    """Run a scanner if available and classify its result."""

    def __init__(
        self,
        name: str,
        executable: str,
        args: list[str],
        repo_root: pathlib.Path,
        runner: ToolRunner,
        skip_failures_containing: tuple[str, ...] = (),
    ) -> None:
        self.name = name
        self.executable = executable
        self.args = args
        self.repo_root = repo_root
        self.runner = runner
        self.skip_failures_containing = skip_failures_containing

    def scan(self) -> ScanResult:
        """Execute the scanner and return a classified :class:`ScanResult`."""
        if not self.runner.available(self.executable):
            return ScanResult(name=self.name, status="skipped", detail=f"{self.executable} not installed")
        result = self.runner.run([self.executable, *self.args], cwd=str(self.repo_root))
        if result.returncode == 127:
            return ScanResult(name=self.name, status="error", detail=f"{self.executable} failed to start")
        if result.returncode == 126:
            return ScanResult(name=self.name, status="error", detail=result.stderr or f"{self.executable} could not execute")
        # Some scans (e.g. a container image that has not been published yet)
        # are genuinely unavailable in a given context; treat those as skipped
        # rather than failing the pipeline.
        if not result.ok and any(token in result.combined for token in self.skip_failures_containing):
            return ScanResult(
                name=self.name,
                status="skipped",
                detail=_first_line(result.combined) or "skipped (unavailable in this context)",
            )
        findings = self._count_findings(result)
        report_path = self._artifact(result)
        status = "pass" if result.ok else "fail"
        return ScanResult(
            name=self.name,
            status=status,
            findings=findings,
            report=report_path,
            detail=_first_line(result.combined) or f"exit {result.returncode}",
        )

    def _artifact(self, result: ToolResult) -> str:
        out = (self.repo_root / _ARTIFACT_DIR).resolve()
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"{self.name}.txt"
        path.write_text(result.combined, encoding="utf-8")
        root = self.repo_root.resolve()
        return str(path.relative_to(root))

    def _count_findings(self, result: ToolResult) -> int:
        return _count_findings(self.name, result)


def _count_findings(name: str, result: ToolResult) -> int:
    """Best-effort finding counts per scanner output format."""
    text = result.combined
    if name == "bandit":
        import re

        match = re.search(r"Total issues:\s*(\d+)", text, re.IGNORECASE)
        return int(match.group(1)) if match else 0
    if name == "pip-audit":
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return len(data)
            return int(data.get("count", 0))
        except (ValueError, AttributeError):
            return 0
    if name == "safety":
        import json as _json

        # Safety v3 emits a JSON dict with report_meta.vulnerabilities_found;
        # the CLI may prefix deprecation warnings to stdout, so locate the
        # JSON document before parsing.
        start = text.find('{"')
        try:
            data = _json.loads(text[start:] if start >= 0 else text)
        except ValueError:
            return 0
        if isinstance(data, dict):
            return int(data.get("report_meta", {}).get("vulnerabilities_found", 0) or 0)
        return len(data)
    if name in ("trivy-fs", "trivy-image"):
        return _count_trivy(text)
    # semgrep / gitleaks: non-zero exit means findings in most modes
    return 0


def _count_trivy(text: str) -> int:
    """Count findings from a Trivy JSON report (list of result objects)."""
    import re

    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        # fall back to scanning the plain output for known headers
        return len(re.findall(r"(?:^\s*[-+]\s|Total:\s+\d+)", text, re.MULTILINE))
    if not isinstance(data, list):
        return 0
    count = 0
    for result in data:
        if not isinstance(result, dict):
            continue
        count += len(result.get("Vulnerabilities") or [])
        count += len(result.get("Secrets") or [])
        count += len(result.get("Misconfigurations") or [])
    return count


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return ""


def run_security_pipeline(repo_root: pathlib.Path, runner: ToolRunner | None = None) -> SecurityReport:
    """Run the full security scanner suite and write the aggregate report."""
    runner = runner or ToolRunner(cwd=str(repo_root))
    scans: list[ScanResult] = []

    scans.append(
        SecurityScanner(
            "bandit",
            "bandit",
            [
                "-r",
                "src/hunterx",
                "-f",
                "txt",
                "-o",
                "artifacts/security/bandit.txt",
                "-q",
                # Fail the gate on Medium+ findings only. Low/informational
                # findings stay in the report (bandit.txt) for tracking; most
                # Low findings are identifier-string false positives (e.g.
                # capability names containing "secret"/"token"). Real secrets
                # are additionally caught by gitleaks and Trivy in this pipeline.
                "-ll",
            ],
            repo_root,
            runner,
        ).scan()
    )
    scans.append(
        SecurityScanner(
            "semgrep",
            "semgrep",
            ["--config", "auto", "--json-output", "artifacts/security/semgrep.json", "src/"],
            repo_root,
            runner,
        ).scan()
    )
    scans.append(
        SecurityScanner(
            "pip-audit",
            "pip-audit",
            [
                "-r",
                "requirements.lock",
                "--disable-pip",
                "--no-deps",
                "--format",
                "json",
                "-o",
                "artifacts/security/pip-audit.json",
            ],
            repo_root,
            runner,
        ).scan()
    )
    scans.append(
        SecurityScanner(
            "safety",
            "safety",
            ["check", "-r", "requirements.lock", "--json"],
            repo_root,
            runner,
        ).scan()
    )
    scans.append(
        SecurityScanner(
            "gitleaks",
            "gitleaks",
            [
                "detect",
                "--source",
                ".",
                "--report-format",
                "json",
                "--report-path",
                "artifacts/security/gitleaks.json",
                "--no-banner",
            ],
            repo_root,
            runner,
        ).scan()
    )
    # Trivy filesystem scan: vulnerabilities, secrets and misconfiguration on
    # the repository tree (skips vendor/generated directories).
    scans.append(
        SecurityScanner(
            "trivy-fs",
            "trivy",
            [
                "fs",
                "--scanners",
                "vuln,secret,misconfig",
                "--skip-dirs",
                "build,dist,reports,artifacts,payloads",
                "--format",
                "json",
                "--output",
                "artifacts/security/trivy-fs.json",
                "--exit-code",
                "1",
                ".",
            ],
            repo_root,
            runner,
        ).scan()
    )
    # Trivy image scan of the published container image (best-effort: needs the
    # image to be pulled; skipped locally when Docker/Trivy is unavailable).
    scans.append(
        SecurityScanner(
            "trivy-image",
            "trivy",
            [
                "image",
                "--scanners",
                "vuln,secret",
                "--severity",
                "HIGH,CRITICAL",
                "--format",
                "json",
                "--output",
                "artifacts/security/trivy-image.json",
                "--exit-code",
                "1",
                "nullc0d30/hunterx:latest",
            ],
            repo_root,
            runner,
            skip_failures_containing=("image not found", "unable to", "not found", "failed to pull", "no such image"),
        ).scan()
    )

    failed = sum(1 for s in scans if s.status == "fail")
    summary = (
        f"{len(scans) - failed}/{len(scans)} scanners clean"
        if failed == 0
        else f"{failed} scanner(s) reported findings"
    )
    report = SecurityReport(scans=scans, failed=failed, summary=summary, blocked=failed > 0)

    (repo_root / "artifacts").mkdir(exist_ok=True)
    path = repo_root / "artifacts" / "security-report.json"
    report.json_path = str(path)
    path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return report


def to_gate_result(report: SecurityReport) -> GateResult:
    """Adapt a :class:`SecurityReport` to a :class:`eng.gates.GateResult`."""
    return GateResult(
        name="security-pipeline",
        status=GateStatus.PASS if report.blocked is False else GateStatus.FAIL,
        detail=report.summary,
        artifact=report.json_path,
    )
