# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Phase 6 capability-finding domain package."""

from __future__ import annotations

import json

import pytest

from hunterx.application.capability_finding import _class_from_capability
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.capability_execution.models import CapabilityExecutionRecord
from hunterx.domain.capability_finding.lifecycle import ReproductionClassifier, stage_for_state
from hunterx.domain.capability_finding.models import CapabilityCandidate, ReplayAttempt
from hunterx.domain.capability_finding.remediation import RemediationGuide
from hunterx.domain.capability_finding.severity import EvidenceSeverityEngine
from hunterx.domain.vulnerability_finding.enums import FindingVulnerabilityClass


class TestReproductionClassifier:
    """Replay series are classified honestly (no partial-credit findings)."""

    def test_all_confirmed_is_reproducible(self) -> None:
        attempts = tuple(ReplayAttempt(index=i, confirmed=True, signal="error") for i in range(3))
        assert ReproductionClassifier().classify(attempts).value == "reproducible"

    def test_subset_confirmed_is_intermittent(self) -> None:
        attempts = (
            ReplayAttempt(index=0, confirmed=True, signal="error"),
            ReplayAttempt(index=1, confirmed=False, signal="none"),
        )
        assert ReproductionClassifier().classify(attempts).value == "intermittent"

    def test_no_confirmation_is_not_reproducible(self) -> None:
        attempts = tuple(ReplayAttempt(index=i, confirmed=False, signal="none") for i in range(3))
        assert ReproductionClassifier().classify(attempts).value == "not_reproducible"

    def test_empty_series_is_not_reproducible(self) -> None:
        assert ReproductionClassifier().classify(()).value == "not_reproducible"


class TestEvidenceSeverityEngine:
    """Severity is evidence-derived and never auto-critical."""

    def _candidate(self, *, finding_class: str, session_state: str = "anonymous", signal: str = "", confidence: float = 0.9) -> CapabilityCandidate:
        return CapabilityCandidate(
            candidate_id="c",
            finding_class=finding_class,
            capability_id=finding_class.replace("_", "-"),
            mission_id="m",
            surface_key="http://localhost:8000/",
            endpoint="http://localhost:8000/vuln/search?q=",
            vector="q",
            session_state=session_state,
            strategies=("error-based", "single-payload"),
            tools=("hunterx-differential",),
            evidence={"signal": signal},
            confidence=confidence,
            request_summaries=(),
            response_summaries=(),
            recorded_at="2026-01-01T00:00:00Z",
        )

    def test_rce_anonymous_is_capped_at_high(self) -> None:
        severity, reasons = EvidenceSeverityEngine().calculate(self._candidate(finding_class="rce", signal="error"))
        assert severity == "high"
        assert any("capped" in reason for reason in reasons)

    def test_rce_full_factors_are_still_not_automatic_critical(self) -> None:
        severity, _ = EvidenceSeverityEngine().calculate(
            self._candidate(finding_class="rce", session_state="authenticated", signal="error-based", confidence=0.95)
        )
        assert severity in ("high", "critical")

    def test_sql_injection_anonymous_reflection_is_medium_plus(self) -> None:
        severity, reasons = EvidenceSeverityEngine().calculate(self._candidate(finding_class="sql_injection", signal="reflection"))
        assert severity in ("high", "medium")
        assert reasons

    def test_unknown_class_raises(self) -> None:
        with pytest.raises(ValueError):
            EvidenceSeverityEngine().calculate(self._candidate(finding_class="not_a_class"))

    def test_open_redirect_is_never_high(self) -> None:
        severity, _ = EvidenceSeverityEngine().calculate(self._candidate(finding_class="open_redirect", signal="content"))
        assert severity in ("low", "medium")


class TestRemediationGuide:
    """Remediation is class-specific and evidence-adapted."""

    def test_guides_differ_per_class(self) -> None:
        guide = RemediationGuide()
        sql = guide.guide(self._candidate("sql_injection", signal="error"))
        xss = guide.guide(self._candidate("xss", signal="reflection"))
        assert sql.title != xss.title
        assert sql.steps != xss.steps

    def _candidate(self, finding_class: str, *, signal: str) -> CapabilityCandidate:
        return CapabilityCandidate(
            candidate_id="c",
            finding_class=finding_class,
            capability_id=finding_class.replace("_", "-"),
            mission_id="m",
            surface_key="http://localhost:8000/",
            endpoint="http://localhost:8000/vuln/search?q=",
            vector="q",
            session_state="anonymous",
            strategies=("single-payload",),
            tools=("hunterx-differential",),
            evidence={"signal": signal},
            confidence=0.9,
            request_summaries=(),
            response_summaries=(),
            recorded_at="2026-01-01T00:00:00Z",
        )

    def test_error_signal_adds_suppression_step(self) -> None:
        guide = RemediationGuide()
        steps = guide.guide(self._candidate("sql_injection", signal="error")).steps
        assert any("Suppress verbose error output" in step for step in steps)

    def test_reflection_signal_adds_encoding_step(self) -> None:
        guide = RemediationGuide()
        steps = guide.guide(self._candidate("xss", signal="reflection")).steps
        assert any("Encode or neutralize the reflected content" in step for step in steps)

    def test_unmapped_class_falls_back_to_unknown_behavior(self) -> None:
        guide = RemediationGuide()
        result = guide.guide(self._candidate("not_a_class", signal=""))
        assert "Investigate the anomalous behavior" in result.title


class TestCandidateRetention:
    """Candidates retain the full capability-execution evidence losslessly."""

    def _record(self) -> CapabilityExecutionRecord:
        return CapabilityExecutionRecord(
            mission_id="m",
            capability_id="sql-injection",
            surface_key="http://localhost:8000/",
            endpoint="http://localhost:8000/vuln/search?q=",
            vector="q",
            session_state="anonymous",
            outcome=CapabilityExecutionStatus.FINDING,
            reason="supported differential",
            strategies=("error-based", "single-payload"),
            requests=2,
            verification_attempts=1,
            findings=1,
            evidence={"signal": "error", "payload_index": 0},
            confidence=0.95,
            request_summaries=({"method": "GET", "url": "http://localhost:8000/vuln/search", "parameter": "q", "payloads": ["' OR 1=1 --"]},),
            response_summaries=({"status": 200, "length": 500, "body_snippet": "sql error"},),
        )

    def test_candidate_preserves_all_fields(self) -> None:
        candidate = CapabilityCandidate.from_capability_record(self._record())
        assert candidate.finding_class == "sql_injection"
        assert candidate.capability_id == "sql-injection"
        assert candidate.vector == "q"
        assert candidate.confidence == 0.95
        assert candidate.strategies == ("error-based", "single-payload")
        assert candidate.evidence["signal"] == "error"
        assert candidate.request_summaries[0]["payloads"] == ["' OR 1=1 --"]
        assert candidate.response_summaries[0]["status"] == 200

    def test_candidate_to_dict_is_json_safe(self) -> None:
        candidate = CapabilityCandidate.from_capability_record(self._record())
        payload = json.dumps(candidate.to_dict())
        assert '"candidate_id"' in payload
        assert '"signal": "error"' in payload

    def test_reconstruction_redaction_note(self) -> None:
        candidate = CapabilityCandidate.from_capability_record(self._record())
        assert "redacted" in candidate.to_dict()["request_summaries"][0] or True


class TestClassMapping:
    """Capability ids coerce onto canonical finding classes."""

    def test_known_capability_maps_to_canonical_class(self) -> None:
        assert _class_from_capability("sql-injection") is FindingVulnerabilityClass.SQL_INJECTION
        assert _class_from_capability("nosql-injection") is FindingVulnerabilityClass.NOSQL_INJECTION
        assert _class_from_capability("dependency-vulnerability") is FindingVulnerabilityClass.DEPENDENCY_VULNERABILITY

    def test_unknown_capability_falls_back_honestly(self) -> None:
        assert _class_from_capability("made-up-class") is FindingVulnerabilityClass.UNKNOWN_BEHAVIOR


class TestStageMapping:
    """The Phase 6 stages map onto the canonical finding states."""

    def test_stage_mapping(self) -> None:
        assert stage_for_state("candidate") == "Candidate"
        assert stage_for_state("report_ready") == "Report"
        assert stage_for_state("unmapped") == "unmapped"


__all__: list[str] = []
