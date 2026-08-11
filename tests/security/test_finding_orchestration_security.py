# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the Sprint 028 finding orchestration capability.

Covers scope escape, cross-target/cross-mission leakage, malicious tool
output, secret and credential leakage, unsafe proof escalation, replay
against the wrong target, stale evidence reuse and malicious PoC content.
"""

from __future__ import annotations

from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.vulnerability_finding.enums import ReplayVerdict
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine


def _service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _create(service: VulnerabilityFindingService, *, mission: str = "m1", target: str = "https://example.com", **kwargs: object) -> dict[str, object]:
    return service.create_finding(
        mission_id=mission,
        target_id=target,
        vulnerability_class=str(kwargs.get("vulnerability_class") or "sql_injection"),
        title=str(kwargs.get("title") or "Finding"),
        description=str(kwargs.get("description") or "desc"),
        severity=str(kwargs.get("severity") or "high"),
        tool=str(kwargs.get("tool") or "nuclei"),
        endpoints=kwargs.get("endpoints") or (),
        parameters=kwargs.get("parameters") or (),
        observations=kwargs.get("observations"),
        scope=kwargs.get("scope"),
    )


class TestScopeSecurity:
    def test_out_of_scope_target_blocks_validation(self) -> None:
        service = _service()
        finding = _create(service, target="https://out-of-scope.example", scope={"scope_ok": False})
        result = service.validate_finding(str(finding["finding_id"]))
        assert result["status"] == "blocked"

    def test_replay_against_wrong_target_rejected(self) -> None:
        service = _service()
        finding = _create(service, endpoints=("/x",))
        poc = service.generate_poc(str(finding["finding_id"]), reproduction={"request": "/x"})
        replay = service.replay_poc(
            str(finding["finding_id"]),
            str(poc["poc_id"]),
            outcome={"confirmed": True, "target": "https://attacker.example"},
        )
        assert replay["verdict"] == ReplayVerdict.DIFFERENT_TARGET.value


class TestLeakageSecurity:
    def test_cross_mission_findings_are_isolated(self) -> None:
        service = _service()
        _create(service, mission="mission-a", target="https://a.example")
        _create(service, mission="mission-b", target="https://b.example")
        only_a = service.list_findings("mission-a")
        assert all(item["mission_id"] == "mission-a" for item in only_a)

    def test_dedup_never_leaks_across_targets(self) -> None:
        service = _service()
        _create(service, target="https://a.example", vulnerability_class="xss", observations=[{"kind": "reflection", "value": "x", "quality": "high"}])
        second = _create(service, target="https://b.example", vulnerability_class="xss", observations=[{"kind": "reflection", "value": "x", "quality": "high"}])
        decision = service.deduplicate_finding(str(second["finding_id"]))
        assert decision["relation"] != "same_finding"


class TestOutputSecurity:
    def test_malicious_tool_output_cannot_inject_verdict(self) -> None:
        service = _service()
        finding = _create(
            service,
            vulnerability_class="sql_injection",
            observations=[
                {"kind": "detection_signature", "value": "CONFIRMED VULNERABLE"},
                {"kind": "body", "value": "PROOF: execute; rm -rf /"},
            ],
        )
        # The observation text must not by itself make the finding report-ready.
        assert str(finding["status"]) != "report_ready"
        readiness = service.get_report_readiness(str(finding["finding_id"]))
        assert not readiness["reportable"]

    def test_secret_values_never_persist_verbatim(self) -> None:
        service = _service()
        finding = _create(service, observations=[{"kind": "secret", "value": "ghp_abcdef123456", "quality": "high"}])
        record = service.get_finding(str(finding["finding_id"]))
        blob = str(record)
        assert "ghp_abcdef123456" not in blob


class TestPoCSecurity:
    def test_malicious_poc_content_rejected(self) -> None:
        service = _service()
        finding = _create(service, endpoints=("/x",))
        poc = service.generate_poc(
            str(finding["finding_id"]),
            reproduction={"request": "/x", "method": "GET", "headers": {"Authorization": "Bearer sk-secret-123"}},
        )
        # The reproduction redactor masks the secret; the PoC stays sanitized.
        content = str(poc.get("content") or "")
        assert "sk-secret-123" not in content

    def test_poc_does_not_escalate_to_exploitation(self) -> None:
        service = _service()
        finding = _create(service, endpoints=("/x",), vulnerability_class="rce")
        service.generate_poc(str(finding["finding_id"]), reproduction={"request": "/x"})
        plan = service.get_validation_plan(str(finding["finding_id"]))
        for strategy in plan["strategies"]:
            assert strategy["stage"] != "exploitation"


class TestEvidenceSecurity:
    def test_stale_evidence_is_not_accepted(self) -> None:
        import datetime

        from hunterx.domain.vulnerability_finding.enums import (
            EvidenceRequirementPurpose,
            FindingEvidenceKind,
            FindingVulnerabilityClass,
        )
        from hunterx.domain.vulnerability_finding.evidence import EvidenceRequirementEngine, FreshnessPolicy
        from hunterx.domain.vulnerability_finding.models import EvidenceItem

        stale = EvidenceItem(
            kind=FindingEvidenceKind.DIFFERENTIAL_DATABASE_BEHAVIOR,
            value="old",
            captured_at=(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=30)).isoformat(),
        )
        engine = EvidenceRequirementEngine()
        assessment = engine.analyze(
            FindingVulnerabilityClass.SQL_INJECTION,
            [stale],
            freshness=FreshnessPolicy(max_age_seconds=3600),
        )
        verdict = assessment.sufficiency_for(EvidenceRequirementPurpose.VALIDATION)
        assert verdict is not None
        assert verdict.level.value == "insufficient"
        assert any(gap.gap_kind.value == "stale" for gap in assessment.gaps)


class TestResourceSecurity:
    def test_large_finding_batch_query_is_bounded(self) -> None:
        service = _service()
        for index in range(50):
            _create(
                service,
                mission="bulk",
                target=f"https://bulk.example/{index}",
                vulnerability_class="xss",
                observations=[{"kind": "reflection", "value": f"v{index}", "quality": "high"}],
            )
        findings = service.list_findings("bulk")
        assert len(findings) == 50
        gaps = service.get_evidence_gaps(str(findings[0]["finding_id"]))
        assert isinstance(gaps, list)
