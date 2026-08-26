# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security Test Matrix unit tests — the completion contract."""

from __future__ import annotations

from hunterx.domain.mission_orchestration.security_matrix import (
    MatrixState,
    SecurityTestMatrix,
)


def test_initial_state_all_not_assessed() -> None:
    matrix = SecurityTestMatrix()
    assert matrix.domains
    assert not matrix.is_complete()
    assert len(matrix.incomplete_domains()) == len(matrix.applicable_domains())


def test_record_negative_execution_is_terminal() -> None:
    matrix = SecurityTestMatrix()
    updated = matrix.record_execution(
        capability="sql_injection",
        tool_id="sqlmap",
        outcome="tested_negative",
        notes="clean",
    )
    assert "sql_injection" in updated
    domain = matrix.domain("sql_injection")
    assert domain is not None
    assert domain.status is MatrixState.TESTED_NEGATIVE
    assert domain.status.is_terminal


def test_validated_finding_marks_positive_validated() -> None:
    matrix = SecurityTestMatrix()
    matrix.record_execution(capability="xss", tool_id="probe", outcome="tested_positive")
    matrix.record_validated_finding("xss")
    assert matrix.domain("xss").status is MatrixState.TESTED_POSITIVE_VALIDATED


def test_conditional_domain_not_applicable_with_evidence() -> None:
    matrix = SecurityTestMatrix()
    # graphql starts applicable until the enumerated context proves absence
    changed = matrix.update_applicability(set())
    assert "graphql_testing" in changed
    domain = matrix.domain("graphql_testing")
    assert domain.status is MatrixState.NOT_APPLICABLE_WITH_EVIDENCE
    assert domain.status.is_terminal
    assert "graphql" in domain.applicability_evidence


def test_conditional_domain_applicable_when_marker_present() -> None:
    matrix = SecurityTestMatrix()
    matrix.update_applicability({"graphql"})
    assert matrix.domain("graphql_testing").applicability == "applicable"
    assert not matrix.is_complete()


def test_completion_requires_all_applicable_terminal() -> None:
    matrix = SecurityTestMatrix()
    matrix.update_applicability(set())
    for domain in list(matrix.domains.values()):
        if not domain.requires_markers:
            matrix.record_execution(
                capability=domain.capabilities[0] if domain.capabilities else "",
                tool_id="t",
                outcome="tested_negative" if domain.capabilities else "tested_negative",
            )
            if not domain.capabilities:
                matrix.mark_tested_negative(domain.domain, "analyzed")
    assert matrix.is_complete()


def test_deferred_is_never_terminal() -> None:
    matrix = SecurityTestMatrix()
    domain = matrix.domain("authentication")
    domain.status = MatrixState.DEFERRED
    assert not domain.status.is_terminal
    assert not matrix.is_complete()


def test_blocked_with_reason_is_explicit_terminal() -> None:
    matrix = SecurityTestMatrix()
    assert matrix.mark_blocked("browser_testing", "playwright unavailable")
    assert matrix.domain("browser_testing").status is MatrixState.BLOCKED_WITH_REASON


def test_coverage_by_category_separates_metrics() -> None:
    matrix = SecurityTestMatrix()
    report = matrix.coverage_by_category()
    for category in ("reconnaissance", "attack_surface", "active_testing", "validation", "analysis"):
        assert category in report
        assert "coverage_ratio" in report[category]
        assert "active_testing_ratio" in report[category]
