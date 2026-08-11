# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Sprint 028 confidence, impact, dedup and reporting engines."""

from __future__ import annotations

from hunterx.domain.vulnerability_finding.confidence import ConfidenceEngine, ConfidenceInput
from hunterx.domain.vulnerability_finding.deduplication import (
    DedupCandidate,
    FindingDeduplicationEngine,
)
from hunterx.domain.vulnerability_finding.enums import (
    ConfidenceFactor,
    ConfidenceLevel,
    DuplicateRelation,
    EvidenceQuality,
    FindingEvidenceKind,
    FindingState,
    FindingVulnerabilityClass,
    ImpactDimension,
    ImpactLevel,
    PocLifecycleState,
    UnknownBehaviorClassification,
)
from hunterx.domain.vulnerability_finding.impact import ImpactAssessmentEngine
from hunterx.domain.vulnerability_finding.models import EvidenceItem
from hunterx.domain.vulnerability_finding.redaction import Redactor
from hunterx.domain.vulnerability_finding.reporting import (
    ChecklistInput,
    FindingPackageBuilder,
    ReportReadinessChecker,
)
from hunterx.domain.vulnerability_finding.unknown import KnownSignature, UnknownBehaviorClassifier


def _item(kind: FindingEvidenceKind, *, quality: EvidenceQuality = EvidenceQuality.HIGH, source: str = "validation") -> EvidenceItem:
    return EvidenceItem(kind=kind, value=f"{kind.value}-value", quality=quality, source=source)


class TestConfidenceEngine:
    def test_proven_requires_validated_poc(self) -> None:
        evidence = (
            _item(FindingEvidenceKind.DETECTION_SIGNATURE, source="scanner"),
            _item(FindingEvidenceKind.DIFFERENTIAL_DATABASE_BEHAVIOR),
            _item(FindingEvidenceKind.REPLAY, quality=EvidenceQuality.PROOF, source="proof_replay"),
            _item(FindingEvidenceKind.INDEPENDENT_REPRODUCTION),
        )
        impact = ImpactAssessmentEngine().assess(
            FindingVulnerabilityClass.SQL_INJECTION, list(evidence)
        )
        assessment = ConfidenceEngine().calculate(
            ConfidenceInput(
                finding_id="f",
                finding_state=FindingState.PROVED,
                evidence=evidence,
                impact=impact,
                poc_state=PocLifecycleState.PROOF_VALIDATED,
                replay_successes=2,
                replay_attempts=2,
            )
        )
        assert assessment.score >= 0.9
        assert assessment.level is ConfidenceLevel.PROVEN

    def test_contradictions_reduce_confidence(self) -> None:
        clean = ConfidenceEngine().calculate(
            ConfidenceInput(finding_id="f", evidence=(_item(FindingEvidenceKind.BEHAVIORAL_DIFFERENTIAL),))
        )
        conflicted = ConfidenceEngine().calculate(
            ConfidenceInput(
                finding_id="f",
                evidence=(_item(FindingEvidenceKind.BEHAVIORAL_DIFFERENTIAL),),
                open_conflicts=2,
            )
        )
        assert conflicted.score < clean.score
        factor = conflicted.factor(ConfidenceFactor.CONTRADICTIONS)
        assert factor is not None
        assert factor.score < 1.0

    def test_explanation_is_evidence_driven(self) -> None:
        assessment = ConfidenceEngine().calculate(
            ConfidenceInput(finding_id="f", evidence=(_item(FindingEvidenceKind.REFLECTION),))
        )
        assert len(assessment.factors) == 10
        detection = assessment.factor(ConfidenceFactor.DETECTION_EVIDENCE)
        assert detection is not None and detection.score < 0.5


class TestImpactEngine:
    def test_no_impact_without_evidence(self) -> None:
        assessment = ImpactAssessmentEngine().assess(
            FindingVulnerabilityClass.RCE,
            [_item(FindingEvidenceKind.REFLECTION)],
        )
        assert not assessment.any_impact()

    def test_rce_proof_implies_remote_execution(self) -> None:
        assessment = ImpactAssessmentEngine().assess(
            FindingVulnerabilityClass.RCE,
            [_item(FindingEvidenceKind.CONTROLLED_PROOF, quality=EvidenceQuality.PROOF)],
        )
        assert assessment.impact_level(ImpactDimension.REMOTE_EXECUTION) is ImpactLevel.HIGH
        assert assessment.impact_level(ImpactDimension.INTEGRITY) is not ImpactLevel.NONE

    def test_secret_exposure_implies_data_exposure(self) -> None:
        assessment = ImpactAssessmentEngine().assess(
            FindingVulnerabilityClass.SECRET_EXPOSURE,
            [_item(FindingEvidenceKind.SECRET, quality=EvidenceQuality.HIGH)],
        )
        assert assessment.impact_level(ImpactDimension.DATA_EXPOSURE) is not ImpactLevel.NONE


class TestDeduplicationEngine:
    def test_identical_findings_deduplicate(self) -> None:
        engine = FindingDeduplicationEngine()
        a = DedupCandidate(finding_id="a", target="t", asset="x", vulnerability_class=FindingVulnerabilityClass.XSS)
        b = DedupCandidate(finding_id="b", target="t", asset="x", vulnerability_class=FindingVulnerabilityClass.XSS)
        decision = engine.correlate(a, b)
        assert decision.relation is DuplicateRelation.SAME_FINDING

    def test_independent_findings_stay_independent(self) -> None:
        engine = FindingDeduplicationEngine()
        a = DedupCandidate(finding_id="a", target="t1", asset="x1", vulnerability_class=FindingVulnerabilityClass.XSS)
        b = DedupCandidate(finding_id="b", target="t2", asset="x2", vulnerability_class=FindingVulnerabilityClass.SSRF)
        decision = engine.correlate(a, b)
        assert decision.relation is DuplicateRelation.INDEPENDENT_FINDING

    def test_same_vuln_across_endpoints(self) -> None:
        engine = FindingDeduplicationEngine()
        a = DedupCandidate(
            finding_id="a", target="t", asset="x", vulnerability_class=FindingVulnerabilityClass.XSS,
            endpoints=("/a",), evidence=(_item(FindingEvidenceKind.REFLECTION),),
        )
        b = DedupCandidate(
            finding_id="b", target="t", asset="x", vulnerability_class=FindingVulnerabilityClass.XSS,
            endpoints=("/b",), evidence=(_item(FindingEvidenceKind.REFLECTION),),
        )
        decision = engine.correlate(a, b)
        assert decision.relation is DuplicateRelation.SAME_VULNERABILITY_ACROSS_ENDPOINTS


class TestUnknownBehavior:
    def test_known_signature_classifies_as_known_class(self) -> None:
        classifier = UnknownBehaviorClassifier()
        profile = classifier.characterize(
            observations=[{"kind": "reflection", "value": "stack trace leaked"}],
            evidence=[],
            known_signatures=[
                KnownSignature(signature_id="s", class_name="error_handling", indicators=("stack trace",))
            ],
        )
        assert profile.classification is UnknownBehaviorClassification.KNOWN_CLASS

    def test_novel_behavior_not_labeled_zero_day(self) -> None:
        classifier = UnknownBehaviorClassifier()
        profile = classifier.characterize(
            observations=[{"kind": "unknown", "value": "unexpected controlled callback"}],
            evidence=[_item(FindingEvidenceKind.CONTROLLED_CALLBACK, quality=EvidenceQuality.PROOF)],
            reproducible=True,
        )
        assert profile.classification is UnknownBehaviorClassification.NOVEL_BEHAVIOR
        # The enum offers no zero-day classification; novel behavior is the ceiling.
        assert all(member.value != "zero_day" for member in UnknownBehaviorClassification)


class TestRedaction:
    def test_redacts_secrets_preserves_reproduction(self) -> None:
        redactor = Redactor()
        text = "Authorization: Bearer sk-abcdef1234567890"
        assert "sk-abcdef1234567890" not in redactor.redact_text(text)
        mapping = redactor.redact_mapping({"Cookie": "sid=secret123", "Host": "example.com"})
        assert "secret123" not in mapping["Cookie"]
        assert mapping["Host"] == "example.com"


class TestReportReadiness:
    def test_incomplete_finding_is_not_reportable(self) -> None:
        checklist = ReportReadinessChecker().check(
            ChecklistInput(
                finding_id="f",
                title="T",
                description="D",
                severity="high",
                asset_present=True,
                location_present=True,
            )
        )
        assert not checklist.complete
        assert not checklist.reportable

    def test_complete_finding_is_reportable(self) -> None:
        evidence = (
            _item(FindingEvidenceKind.DETECTION_SIGNATURE, source="scanner"),
            _item(FindingEvidenceKind.CONTROLLED_PROOF, quality=EvidenceQuality.PROOF),
        )
        impact = ImpactAssessmentEngine().assess(
            FindingVulnerabilityClass.SQL_INJECTION, list(evidence)
        )
        confidence = ConfidenceEngine().calculate(
            ConfidenceInput(finding_id="f", evidence=evidence, impact=impact)
        )
        from hunterx.domain.vulnerability_finding.models import FindingScope, Reproduction

        checklist = ReportReadinessChecker().check(
            ChecklistInput(
                finding_id="f",
                title="T",
                description="D",
                severity="high",
                asset_present=True,
                location_present=True,
                scope=FindingScope(target="https://example.com"),
                evidence=evidence,
                reproduction=Reproduction(reproduction_id="r", finding_id="f", request="/x"),
                impact=impact,
                proof_validated=True,
                validation_status="validated",
                confidence=confidence,
                provenance_present=True,
                redaction_applied=True,
            )
        )
        assert checklist.complete
        assert checklist.reportable
        proof = checklist.check("proof")
        assert proof is not None and proof.passed


class TestFindingPackage:
    def test_package_carries_full_lifecycle(self) -> None:
        from hunterx.domain.vulnerability_finding.models import FindingScope, RedactionMetadata

        package = FindingPackageBuilder().build(
            finding_id="f",
            finding_state=FindingState.REPORT_READY,
            title="SQLi",
            description="desc",
            severity="high",
            scope=FindingScope(target="https://example.com"),
            evidence=(_item(FindingEvidenceKind.REPLAY, quality=EvidenceQuality.PROOF),),
            redaction=RedactionMetadata(),
        )
        payload = package.to_dict()
        assert payload["finding_state"] == "report_ready"
        assert payload["finding_id"] == "f"
        assert len(payload["evidence"]) == 1
        assert payload["redaction"]["policy_version"]
