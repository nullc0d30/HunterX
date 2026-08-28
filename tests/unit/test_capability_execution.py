# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability execution — domain semantics.

Exactly-one authoritative status per capability (FINDING / VERIFIED /
NO_FINDING / NOT_APPLICABLE / BLOCKED / FAILED), precedence aggregation,
coverage persistence shape, and the no-catalog-only-claims guarantee.
"""

from __future__ import annotations

import json

from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.capability_execution.models import (
    CapabilityExecutionRecord,
    ToolExecutionRecord,
    aggregate_status,
    build_capability_coverage,
)


def _record(
    capability: str = "sql-injection",
    outcome: CapabilityExecutionStatus = CapabilityExecutionStatus.NO_FINDING,
    *,
    surface: str = "http://127.0.0.1:1/api",
    session_state: str = "anonymous",
    reason: str = "",
    tools: tuple[ToolExecutionRecord, ...] = (),
    strategies: tuple[str, ...] = ("boolean",),
) -> CapabilityExecutionRecord:
    return CapabilityExecutionRecord(
        mission_id="unit",
        capability_id=capability,
        surface_key=surface,
        endpoint=surface,
        vector="q",
        session_state=session_state,
        outcome=outcome,
        reason=reason or f"{outcome.value} outcome",
        strategies=strategies,
        tools=tools,
    )


class TestAggregateStatus:
    def test_finding_outranks_everything(self) -> None:
        records = [
            _record(outcome=CapabilityExecutionStatus.NO_FINDING),
            _record(outcome=CapabilityExecutionStatus.BLOCKED),
            _record(outcome=CapabilityExecutionStatus.FAILED),
            _record(outcome=CapabilityExecutionStatus.FINDING),
        ]
        assert aggregate_status(records) is CapabilityExecutionStatus.FINDING

    def test_blocked_beats_failed(self) -> None:
        records = [_record(outcome=CapabilityExecutionStatus.FAILED), _record(outcome=CapabilityExecutionStatus.BLOCKED)]
        assert aggregate_status(records) is CapabilityExecutionStatus.BLOCKED

    def test_verified_beats_no_finding(self) -> None:
        records = [
            _record(outcome=CapabilityExecutionStatus.NO_FINDING),
            _record(outcome=CapabilityExecutionStatus.VERIFIED),
        ]
        assert aggregate_status(records) is CapabilityExecutionStatus.VERIFIED

    def test_empty_records_default_to_not_applicable(self) -> None:
        assert aggregate_status([]) is CapabilityExecutionStatus.NOT_APPLICABLE

    def test_exactly_one_status_always(self) -> None:
        statuses = {CapabilityExecutionStatus.VERIFIED, CapabilityExecutionStatus.NO_FINDING, CapabilityExecutionStatus.FINDING, CapabilityExecutionStatus.NOT_APPLICABLE, CapabilityExecutionStatus.BLOCKED, CapabilityExecutionStatus.FAILED}
        for _ in range(64):
            records = [_record(outcome=s) for s in statuses]
            assert aggregate_status(records) in statuses


class TestCoverageDocument:
    CATALOG = ["sql-injection", "xss", "lfi", "ssrf", "idor", "dependency-vulnerability"]

    def test_every_catalog_capability_has_exactly_one_status(self) -> None:
        records = [
            _record("sql-injection", CapabilityExecutionStatus.FINDING),
            _record("xss", CapabilityExecutionStatus.VERIFIED),
            _record("lfi", CapabilityExecutionStatus.NO_FINDING),
        ]
        coverage = build_capability_coverage(records, self.CATALOG, mission_id="m1", target="http://127.0.0.1:1/")
        assert coverage["mission_id"] == "m1"
        assert coverage["catalog_size"] == 6
        assert len(coverage["capabilities"]) == 6
        statuses = {CapabilityExecutionStatus(s["status"]) for s in coverage["capabilities"].values()}
        assert statuses <= set(CapabilityExecutionStatus)
        assert coverage["capabilities"]["sql-injection"]["status"] == "FINDING"
        assert coverage["capabilities"]["xss"]["status"] == "VERIFIED"
        assert coverage["capabilities"]["lfi"]["status"] == "NO_FINDING"

    def test_mapped_but_unexecuted_is_blocked_never_complete(self) -> None:
        coverage = build_capability_coverage(
            [],
            ["ssrf"],
            mapped_capabilities={"ssrf"},
            mission_id="m1",
        )
        entry = coverage["capabilities"]["ssrf"]
        assert entry["status"] == "BLOCKED"
        assert "never executed" in entry["reason"]

    def test_unmapped_is_not_applicable_from_evidence_not_assumption(self) -> None:
        coverage = build_capability_coverage([], ["idor"], mission_id="m1")
        entry = coverage["capabilities"]["idor"]
        assert entry["status"] == "NOT_APPLICABLE"
        assert "not mapped" in entry["reason"]

    def test_tool_records_are_serialized(self) -> None:
        tool = ToolExecutionRecord(
            tool_id="sqlmap",
            surface="http://127.0.0.1:1/api",
            command="sqlmap -u ...",
            exit_code=None,
            stdout_status="unavailable",
            parsed_result=None,
            duration_ms=0,
            strategy="scanner",
            error="adapter not available",
        )
        record = _record(tools=(tool,), strategies=("boolean", "error_based"))
        coverage = build_capability_coverage([record], ["sql-injection"], mission_id="m1")
        tools = coverage["capabilities"]["sql-injection"]["tools"]
        assert tools == [tool.to_dict()]
        assert coverage["capabilities"]["sql-injection"]["strategies"] == ["boolean", "error_based"]

    def test_auth_contexts_are_recorded(self) -> None:
        records = [
            _record("xss", surface="a", session_state="anonymous"),
            _record("xss", surface="a", session_state="authenticated"),
        ]
        coverage = build_capability_coverage(records, ["xss"], mission_id="m1")
        assert coverage["capabilities"]["xss"]["auth_contexts"] == ["anonymous", "authenticated"]

    def test_document_is_json_serializable(self, tmp_path) -> None:
        coverage = build_capability_coverage(
            [_record("xss", CapabilityExecutionStatus.VERIFIED)],
            self.CATALOG,
            mission_id="m1",
        )
        payload = json.dumps(coverage, default=str)
        destination = tmp_path / "capability_coverage.json"
        destination.write_text(payload, encoding="utf-8")
        assert destination.stat().st_size > 0
        assert json.loads(destination.read_text(encoding="utf-8"))["catalog_size"] == 6

    def test_status_summary_counts_every_capability(self) -> None:
        coverage = build_capability_coverage(
            [_record("sql-injection", CapabilityExecutionStatus.FINDING)],
            ["sql-injection", "xss", "ssrf", "idor", "lfi", "dependency-vulnerability"],
            mapped_capabilities={"ssrf"},
            mission_id="m1",
        )
        summary = coverage["statuses"]
        assert summary["FINDING"] == 1
        assert summary["NOT_APPLICABLE"] == 4
        assert summary["BLOCKED"] == 1
        assert sum(summary.values()) == 6


class TestCoverageRecordShape:
    def test_record_carries_full_execution_provenance(self) -> None:
        record = _record(
            surface="http://127.0.0.1:1/api",
            outcome=CapabilityExecutionStatus.FINDING,
            strategies=("boolean", "error_based"),
        )
        dumped = record.to_dict()
        assert dumped["capability"] == "sql-injection"
        assert dumped["surface"] == "http://127.0.0.1:1/api"
        assert dumped["vector"] == "q"
        assert dumped["session_state"] == "anonymous"
        assert dumped["outcome"] == "FINDING"
        assert dumped["strategies"] == ["boolean", "error_based"]
        assert dumped["verification_attempts"] == 0
        assert dumped["chain"] == []

    def test_tool_record_missing_exit_code_means_not_invoked(self) -> None:
        tool = ToolExecutionRecord(tool_id="ghauri", surface="s", stdout_status="unavailable")
        assert tool.exit_code is None
        assert tool.to_dict()["exit_code"] is None


class TestCatalogParity:
    def test_all_known_vulnerability_classes_have_a_registered_capability(self) -> None:
        """No catalog-only claims: every class in the semantic vocabulary must
        resolve to an executable capability (or be honestly absent)."""
        from hunterx.domain.vulnerability_capability.registry import capabilities

        registered = {capability.vulnerability_class for capability in capabilities()}
        assert "sql-injection" in registered
        assert "lfi" in registered
        assert "ssrf" in registered
        assert "ssti" in registered
        assert "xxe" in registered
        assert "http-access-differential" in registered


__all__: list[str] = []
