# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the architecture report model and health score."""

from __future__ import annotations

from hunterx.architecture.report import ArchitectureReport
from hunterx.architecture.violations import Violation


def _error(code: str = "ARCH-001", module: str = "hunterx.domain.a") -> Violation:
    return Violation(
        code=code,
        severity="error",
        message="test",
        remediation="fix it",
        module=module,
    )


def test_clean_report() -> None:
    report = ArchitectureReport(module_count=10, source_line_count=100)
    assert report.is_clean()
    assert report.health_score() == 100.0
    assert report.grade() == "A"


def test_errors_deduct_score() -> None:
    report = ArchitectureReport()
    report.violations = [_error()] * 3
    assert report.health_score() == 76.0
    assert not report.is_clean()


def test_warning_penalty_is_capped() -> None:
    warnings = [
        Violation(code="ARCH-007", severity="warning", message="w", remediation="r", module="m")
    ] * 50
    report = ArchitectureReport()
    report.violations = warnings
    assert report.health_score() == 85.0


def test_cycles_deduct_score() -> None:
    report = ArchitectureReport()
    report.cycles = [["hunterx.a", "hunterx.b"]]
    assert report.health_score() == 88.0


def test_counts() -> None:
    report = ArchitectureReport()
    report.violations = [
        _error(),
        Violation(code="ARCH-007", severity="warning", message="w", remediation="r", module="m"),
        Violation(code="ARCH-100", severity="info", message="i", remediation="r", module="m"),
    ]
    assert report.error_count() == 1
    assert report.warning_count() == 1
    assert report.info_count() == 1
    assert report.violations_by_code() == {"ARCH-001": 1, "ARCH-007": 1, "ARCH-100": 1}


def test_violations_by_layer() -> None:
    report = ArchitectureReport()
    report.violations = [_error(module="hunterx.domain.a"), _error(module="hunterx.infrastructure.b")]
    assert report.violations_by_layer() == {"domain": 1, "infrastructure": 1}


def test_json_round_trip() -> None:
    report = ArchitectureReport()
    report.violations = [_error()]
    payload = report.to_dict()
    assert payload["summary"]["errors"] == 1
    assert payload["violations"][0]["code"] == "ARCH-001"


def test_mermaid_graph() -> None:
    report = ArchitectureReport(layer_graph={"domain": ["shared"], "application": ["domain"]})
    mermaid = report.render_mermaid()
    assert "flowchart LR" in mermaid
    assert "domain --> shared" in mermaid
