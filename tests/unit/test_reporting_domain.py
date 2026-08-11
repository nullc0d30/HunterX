# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the professional reporting domain engines.

Covers severity, quality, reportability, prioritization, classification,
lifecycle, claims, QA, redaction, evidence bundles, timeline, source
reliability and templates. These tests never require a database.
"""

from __future__ import annotations

import pytest

from hunterx.domain.reporting.claims import ClaimExtractor, ClaimVerifier
from hunterx.domain.reporting.classification import ClassificationEngine
from hunterx.domain.reporting.enums import (
    ClaimState,
    ClaimType,
    PriorityLevel,
    QaVerdict,
    QualityGrade,
    ReportabilityStatus,
    ReportState,
    SourceReliabilityKind,
    TemplateKind,
)
from hunterx.domain.reporting.evidence import ArtifactInput, EvidenceBundleBuilder
from hunterx.domain.reporting.lifecycle import ReportStateMachine
from hunterx.domain.reporting.models import (
    AssetCriticality,
    ReportClaim,
    ReportDocument,
)
from hunterx.domain.reporting.prioritization import FindingPriorityEngine, PriorityInput
from hunterx.domain.reporting.qa import QaContext, ReportQAEngine
from hunterx.domain.reporting.quality import FindingQualityEngine, QualityInput
from hunterx.domain.reporting.redaction import ReportRedactor
from hunterx.domain.reporting.reportability import ReportabilityEngine, ReportabilityInput
from hunterx.domain.reporting.severity import SeverityAssessmentEngine, SeverityInput
from hunterx.domain.reporting.source import SourceReliabilityModelBuilder
from hunterx.domain.reporting.templates import ReportTemplateEngine
from hunterx.domain.reporting.timeline import FindingTimelineBuilder, TimelineEvent


class TestSeverityEngine:
    def test_out_of_scope_is_informational(self) -> None:
        engine = SeverityAssessmentEngine()
        result = engine.assess(
            SeverityInput(
                scope="out_of_scope",
                impact_dimensions={"data_exposure": "high"},
                confidence=0.9,
            )
        )
        assert result.severity == "informational"

    def test_high_impact_with_proof_is_critical(self) -> None:
        engine = SeverityAssessmentEngine()
        result = engine.assess(
            SeverityInput(
                finding_id="f1",
                impact_dimensions={"data_exposure": "high", "authorization_boundary": "high"},
                confidence=0.9,
                proof_replayed=True,
                scope="in_scope",
                asset_criticality=AssetCriticality(importance="critical", internet_exposure=True),
            )
        )
        assert result.severity == "critical"
        assert result.risk_score >= 9.0
        assert result.evidence_backed is True

    def test_low_confidence_without_proof_capped_below_critical(self) -> None:
        engine = SeverityAssessmentEngine()
        result = engine.assess(
            SeverityInput(
                finding_id="f1",
                impact_dimensions={"data_exposure": "high"},
                confidence=0.5,
                scope="in_scope",
            )
        )
        assert result.severity != "critical"

    def test_cvss_caps_severity(self) -> None:
        engine = SeverityAssessmentEngine()
        result = engine.assess(
            SeverityInput(
                finding_id="f1",
                impact_dimensions={"data_exposure": "high"},
                confidence=0.95,
                proof_replayed=True,
                scope="in_scope",
                cvss_severity="medium",
            )
        )
        assert result.severity in ("low", "medium")


class TestQualityEngine:
    def test_complete_report_is_grade_b(self) -> None:
        engine = FindingQualityEngine()
        result = engine.score(
            QualityInput(
                evidence_items=4,
                evidence_quality_avg=0.9,
                validated=True,
                proof_validated=True,
                replays_successful=2,
                replay_attempts=2,
                impact_assessed=True,
                scope_ok=True,
                asset_identified=True,
                root_cause_known=True,
                fresh=True,
                tool_reliability_avg=0.9,
                open_conflicts=0,
                report_complete=True,
            )
        )
        assert result.quality_grade in (QualityGrade.A, QualityGrade.B)
        assert result.quality_score >= 0.7

    def test_bare_finding_is_grade_f(self) -> None:
        engine = FindingQualityEngine()
        result = engine.score(QualityInput(evidence_items=1))
        assert result.quality_grade == QualityGrade.F

    def test_confidence_and_quality_are_distinct(self) -> None:
        engine = FindingQualityEngine()
        result = engine.score(
            QualityInput(evidence_items=3, evidence_quality_avg=1.0, validated=True, proof_validated=True)
        )
        assert result.quality_score > 0.5
        # Quality is about report defensibility, not finding correctness.
        assert "finding_id" in result.to_dict()


class TestReportabilityEngine:
    def test_reportable(self) -> None:
        engine = ReportabilityEngine()
        result = engine.evaluate(
            ReportabilityInput(
                finding_id="f1",
                finding_state="proved",
                scope_ok=True,
                validated=True,
                proof_validated=True,
                reproducible=True,
                impact_assessed=True,
                severity="high",
                confidence=0.9,
                evidence_items=3,
            )
        )
        assert result.status is ReportabilityStatus.REPORTABLE

    def test_incomplete_when_evidence_missing(self) -> None:
        engine = ReportabilityEngine()
        result = engine.evaluate(
            ReportabilityInput(
                finding_id="f1",
                finding_state="supported",
                scope_ok=True,
                validated=False,
                evidence_items=1,
            )
        )
        assert result.status is ReportabilityStatus.INCOMPLETE

    def test_duplicate(self) -> None:
        engine = ReportabilityEngine()
        result = engine.evaluate(
            ReportabilityInput(
                finding_id="f1",
                finding_state="duplicate",
                scope_ok=True,
                duplicate=True,
            )
        )
        assert result.status is ReportabilityStatus.DUPLICATE


class TestPriorityEngine:
    def test_p0_requires_evidence_and_proof(self) -> None:
        engine = FindingPriorityEngine()
        result = engine.assess(
            PriorityInput(
                finding_id="f1",
                severity_score=10.0,
                severity="critical",
                confidence=0.95,
                quality_score=0.9,
                asset_criticality_level=3,
                exploitability_evidence=True,
                proof_validated=True,
                on_attack_path=True,
                attack_path_validated=True,
                business_impact_score=1.0,
                internet_exposed=True,
            )
        )
        assert result.priority is PriorityLevel.P0

    def test_class_alone_never_p0(self) -> None:
        engine = FindingPriorityEngine()
        result = engine.assess(
            PriorityInput(
                finding_id="f1",
                severity_score=9.5,
                severity="critical",
                confidence=0.2,
                quality_score=0.2,
                proof_validated=False,
            )
        )
        assert result.priority is not PriorityLevel.P0


class TestClassificationEngine:
    def test_sqli_maps_to_cwe_89_and_owasp_a03(self) -> None:
        engine = ClassificationEngine()
        result = engine.classify(vulnerability_class="sql_injection")
        assert [cwe.cwe_id for cwe in result.cwes] == ["CWE-89"]
        assert any(mapping.item_id == "2021-A03" for mapping in result.owasp)

    def test_attack_only_where_applicable(self) -> None:
        engine = ClassificationEngine()
        xss = engine.classify(vulnerability_class="xss")
        assert xss.attack == ()
        rce = engine.classify(vulnerability_class="rce")
        assert rce.attack and rce.attack[0].technique_id == "T1190"

    def test_cve_only_when_referenced(self) -> None:
        engine = ClassificationEngine()
        result = engine.classify(vulnerability_class="known_cve", cve_ids=("CVE-2024-0001",))
        assert result.cve_ids == ("CVE-2024-0001",)


class TestLifecycle:
    def test_submission_gates(self) -> None:
        state = ReportStateMachine()
        result = state.transition(
            ReportState.QA_PASSED,
            ReportState.READY_FOR_SUBMISSION,
            qa_passed=True,
            no_unsupported_claims=True,
            redaction_applied=True,
        )
        assert result.allowed is True

    def test_unsupported_claim_blocks_submission(self) -> None:
        state = ReportStateMachine()
        result = state.transition(
            ReportState.QA_PASSED,
            ReportState.READY_FOR_SUBMISSION,
            qa_passed=True,
            no_unsupported_claims=False,
            redaction_applied=True,
        )
        assert result.allowed is False
        assert "no_unsupported_claims" in result.missing_gates

    def test_undeclared_transition_refused(self) -> None:
        state = ReportStateMachine()
        result = state.transition(ReportState.DRAFT, ReportState.CLOSED)
        assert result.allowed is False


class TestClaims:
    def test_verified_claim(self) -> None:
        verifier = ClaimVerifier()
        claims = (
            ReportClaim(
                claim_text="endpoint is vulnerable",
                source_refs=("validation-1",),
                claim_type=ClaimType.VULNERABILITY,
                confidence=0.9,
            ),
        )
        verified = verifier.verify(claims, verified_refs={"validation-1"})
        assert verified[0].verification_state is ClaimState.VERIFIED

    def test_unsupported_high_impact_claim_blocked(self) -> None:
        verifier = ClaimVerifier()
        claims = (
            ReportClaim(
                claim_text="severity is critical",
                source_refs=(),
                claim_type=ClaimType.SEVERITY,
            ),
        )
        verified = verifier.verify(claims, verified_refs=set())
        assert verified[0].verification_state is ClaimState.BLOCKED
        assert len(verifier.blocked_claims(verified)) == 1

    def test_extractor_emits_core_claim(self) -> None:
        extractor = ClaimExtractor()
        payload = {
            "finding_id": "f1",
            "severity": {"severity": "high", "evidence_backed": True},
            "classification": {"cwes": [{"cwe_id": "CWE-89", "title": "SQLi"}]},
            "impact": {},
            "intelligence": {"vulnerability_class": "sql_injection", "evidence_bundle": {"validation_results": ["v1"]}},
        }
        claims = extractor.extract(payload)
        assert any(claim.claim_type is ClaimType.VULNERABILITY for claim in claims)


class TestQa:
    def _clean_document(self) -> ReportDocument:
        from hunterx.domain.reporting.enums import ReportabilityStatus
        from hunterx.domain.reporting.models import (
            BusinessImpact,
            EvidenceArtifact,
            EvidenceBundle,
            FindingQuality,
            PriorityAssessment,
            Reportability,
            ReportabilityCheck,
            SeverityAssessment,
        )

        return ReportDocument(
            report_id="r1",
            finding_id="f1",
            title="test",
            severity=SeverityAssessment(finding_id="f1", severity="high", risk_score=7.5),
            reportability=Reportability(
                finding_id="f1",
                status=ReportabilityStatus.REPORTABLE,
                checks=(
                    ReportabilityCheck("scope", True, "in scope", required=True),
                    ReportabilityCheck("validated", True, "validated", required=True),
                ),
            ),
            quality=FindingQuality(finding_id="f1", quality_score=0.8, quality_grade=QualityGrade.B),
            priority=PriorityAssessment(finding_id="f1", priority=PriorityLevel.P1),
            impact=BusinessImpact(
                dimensions={},
                evidence_refs={},
            ),
            evidence_bundle=EvidenceBundle(
                bundle_id="b1",
                finding_id="f1",
                artifacts=(
                    EvidenceArtifact(artifact_id="e1", content_hash="h1", source="s"),
                    EvidenceArtifact(artifact_id="e2", content_hash="h2", source="s"),
                ),
                validation_results=("v1",),
            ),
            poc=__import__("hunterx.domain.reporting.models", fromlist=["PoCPresentation"]).PoCPresentation(
                poc_id="p1", finding_id="f1", poc_type="http_request", validation_status="proof_validated"
            ),
        )

    def test_pass_when_clean(self) -> None:
        engine = ReportQAEngine()
        document = self._clean_document()
        result = engine.check(document, context=QaContext(verified_refs={"e1", "e2"}), text_content="no secrets here")
        assert result.verdict is QaVerdict.PASS

    def test_secret_leakage_fails(self) -> None:
        engine = ReportQAEngine()
        document = ReportDocument(title="x")
        result = engine.check(document, context=QaContext(), text_content="api_key=abcdefghijklmnopqrstuvwxyz")
        assert result.verdict is QaVerdict.FAIL
        assert any(check.name == "secret_leakage" for check in result.checks)

    def test_blocked_claims_fail(self) -> None:
        engine = ReportQAEngine()
        claims = (
            ReportClaim(
                claim_text="severity is critical",
                source_refs=(),
                claim_type=ClaimType.SEVERITY,
                verification_state=ClaimState.BLOCKED,
            ),
        )
        document = ReportDocument(title="x", claims=claims)
        result = engine.check(document, context=QaContext())
        assert result.verdict is QaVerdict.FAIL
        assert result.blocked is True


class TestRedaction:
    def test_redacts_api_key(self) -> None:
        redactor = ReportRedactor()
        original = 'token="ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCDE"'
        text, record = redactor.redact(original)
        assert record.applied is True
        assert original not in text
        assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCDE" not in text

    def test_preserves_plain_text(self) -> None:
        redactor = ReportRedactor()
        text, record = redactor.redact("the endpoint is vulnerable to SQL injection")
        assert text == "the endpoint is vulnerable to SQL injection"
        assert record.applied is False

    def test_redacts_aws_key_without_keyword(self) -> None:
        redactor = ReportRedactor()
        text, record = redactor.redact("AKIAIOSFODNN7EXAMPLE")
        assert record.applied is True
        assert "AKIAIOSFODNN7EXAMPLE" not in text


class TestEvidenceBundle:
    def test_immutable_hash_detects_alteration(self) -> None:
        builder = EvidenceBundleBuilder()
        bundle = builder.build(
            finding_id="f1",
            artifacts=(
                ArtifactInput(kind="observation", content="a", source="s1"),
                ArtifactInput(kind="observation", content="b", source="s2"),
            ),
        )
        assert builder.verify_integrity(bundle) is True
        tampered = bundle.artifacts[0].content_hash + "x"
        assert builder.verify_integrity(bundle) is True  # original intact
        # Altering the bundle object breaks the hash.
        import dataclasses

        altered = dataclasses.replace(bundle, artifacts=(dataclasses.replace(bundle.artifacts[0], content_hash=tampered), bundle.artifacts[1]))
        assert builder.verify_integrity(altered) is False


class TestTimeline:
    def test_orders_by_occurred_at(self) -> None:
        builder = FindingTimelineBuilder()
        timeline = builder.build(
            finding_id="f1",
            events=(
                TimelineEvent(event="b", occurred_at="2026-01-02T00:00:00Z"),
                TimelineEvent(event="a", occurred_at="2026-01-01T00:00:00Z"),
            ),
        )
        assert [entry.event for entry in timeline.entries] == ["a", "b"]

    def test_refuses_invented_timestamp(self) -> None:
        builder = FindingTimelineBuilder()
        with pytest.raises(ValueError):
            builder.build(
                finding_id="f1",
                events=(TimelineEvent(event="b", occurred_at=""),),
            )


class TestSourceReliability:
    def test_direct_outranks_ai(self) -> None:
        builder = SourceReliabilityModelBuilder()
        direct = builder.reliability_for("nuclei", SourceReliabilityKind.DIRECT_OBSERVATION)
        ai = builder.reliability_for("llm", SourceReliabilityKind.AI_INFERENCE)
        assert builder.stronger_than(direct, ai) is True
        assert builder.stronger_than(ai, direct) is False


class TestTemplates:
    def test_template_is_data_driven(self) -> None:
        engine = ReportTemplateEngine()
        template = engine.template_for(TemplateKind.BUG_BOUNTY)
        assert template.kind is TemplateKind.BUG_BOUNTY
        keys = [section.key for section in template.sections]
        assert "title" in keys and "steps_to_reproduce" in keys and "poc" in keys

    def test_all_kinds_available(self) -> None:
        engine = ReportTemplateEngine()
        for kind in TemplateKind:
            template = engine.template_for(kind)
            assert template.sections
