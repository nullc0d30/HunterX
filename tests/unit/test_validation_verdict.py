# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the verdict engine, evidence builder and history/differential."""

from __future__ import annotations

from hunterx.domain.vulnerability_validation.enums import (
    DifferentialChange,
    EvidenceComparison,
    EvidenceKind,
    ValidationClass,
    VerdictResult,
    VulnerabilityState,
)
from hunterx.domain.vulnerability_validation.evidence import EvidenceBuilder, EvidenceContext
from hunterx.domain.vulnerability_validation.history import (
    HypothesisSnapshot,
    ValidationDifferencer,
    ValidationHistoryStore,
)
from hunterx.domain.vulnerability_validation.models import ValidationObservation
from hunterx.domain.vulnerability_validation.rules import ValidationRuleSet
from hunterx.domain.vulnerability_validation.verdict import VerdictEngine


def _observation(kind: EvidenceKind, value: str, *, expected: str | None = None, confidence: float = 1.0):
    metadata = {"expected": expected} if expected else {}
    return ValidationObservation(kind=kind, value=value, confidence=confidence, metadata=metadata)


class TestEvidenceBuilder:
    def test_match_on_concrete_expected(self) -> None:
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        evidence = builder.build(
            _observation(EvidenceKind.VERSION, "1.24.0", expected="1.24.0"),
            expected_behavior="prose",
        )
        assert evidence.comparison == EvidenceComparison.MATCH
        assert evidence.input_hash
        assert evidence.output_hash
        assert evidence.provenance["producer"] == "vulnerability.validation"

    def test_partial_match_and_mismatch(self) -> None:
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        partial = builder.build(_observation(EvidenceKind.ERROR_MESSAGE, "error near marker", expected="marker"))
        assert partial.comparison == EvidenceComparison.PARTIAL_MATCH
        mismatch = builder.build(_observation(EvidenceKind.VERSION, "2.0.0", expected="1.24.0"))
        assert mismatch.comparison == EvidenceComparison.MISMATCH

    def test_no_comparison_without_concrete_expected(self) -> None:
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        evidence = builder.build(_observation(EvidenceKind.BODY, "<html>ok</html>"), expected_behavior="prose")
        assert evidence.comparison == EvidenceComparison.NO_COMPARISON

    def test_redaction_of_sensitive_metadata(self) -> None:
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        evidence = builder.build(
            _observation(EvidenceKind.HEADER, "authorization: secret-value"),
            request_metadata={"token": "supersecret", "url": "https://example.com/x"},
        )
        assert "supersecret" not in evidence.request_metadata["token"]


class TestVerdictEngine:
    def test_known_vulnerable_version_confirmed(self) -> None:
        rules = ValidationRuleSet()
        engine = VerdictEngine(rules)
        rule = rules.require(ValidationClass.KNOWN_VULNERABLE_SOFTWARE)
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        evidence = [builder.build(_observation(EvidenceKind.VERSION, "1.24.0", expected="1.24.0"))]
        verdict = engine.evaluate(hypothesis_id="h1", validation_id="v1", rule=rule, evidence=evidence)
        assert verdict.result == VerdictResult.CONFIRMED
        assert verdict.confidence >= rule.minimum_confidence
        assert "validation.known-vulnerable-software" in verdict.rule_ids

    def test_fixed_version_false_positive(self) -> None:
        rules = ValidationRuleSet()
        engine = VerdictEngine(rules)
        rule = rules.require(ValidationClass.KNOWN_VULNERABLE_SOFTWARE)
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        evidence = [builder.build(_observation(EvidenceKind.VERSION, "1.25.0", expected="1.24.0"))]
        verdict = engine.evaluate(hypothesis_id="h1", validation_id="v1", rule=rule, evidence=evidence)
        assert verdict.result == VerdictResult.FALSE_POSITIVE

    def test_validated_when_rule_forbids_confirmation(self) -> None:
        rules = ValidationRuleSet()
        engine = VerdictEngine(rules)
        rule = rules.require(ValidationClass.SQL_INJECTION)
        assert rule.permits_confirmation is False
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        evidence = [builder.build(_observation(EvidenceKind.ERROR_MESSAGE, "error near marker", expected="marker"))]
        verdict = engine.evaluate(hypothesis_id="h1", validation_id="v1", rule=rule, evidence=evidence)
        assert verdict.result == VerdictResult.VALIDATED

    def test_inconclusive_without_comparison(self) -> None:
        rules = ValidationRuleSet()
        engine = VerdictEngine(rules)
        rule = rules.require(ValidationClass.SQL_INJECTION)
        context = EvidenceContext(validation_id="v1", hypothesis_id="h1")
        builder = EvidenceBuilder(context)
        evidence = [builder.build(_observation(EvidenceKind.BODY, "<html>ok</html>"))]
        verdict = engine.evaluate(hypothesis_id="h1", validation_id="v1", rule=rule, evidence=evidence)
        assert verdict.result == VerdictResult.INCONCLUSIVE

    def test_blocked_verdict_is_first_class(self) -> None:
        rules = ValidationRuleSet()
        engine = VerdictEngine(rules)
        rule = rules.require(ValidationClass.KNOWN_VULNERABLE_SOFTWARE)
        verdict = engine.evaluate(
            hypothesis_id="h1",
            validation_id="v1",
            rule=rule,
            evidence=(),
            blocked=VerdictResult.SCOPE_BLOCKED,
            blocked_reason="scope-expired",
        )
        assert verdict.result == VerdictResult.SCOPE_BLOCKED
        assert "scope-expired" in verdict.reason

    def test_state_for_verdict(self) -> None:
        engine = VerdictEngine()
        assert engine.state_for(VerdictResult.CONFIRMED) == VulnerabilityState.CONFIRMED


class TestHistoryAndDifferential:
    def _snapshot(self, key: str, state: VulnerabilityState, confidence: float = 0.8) -> HypothesisSnapshot:
        return HypothesisSnapshot(
            key=key,
            hypothesis_id="h1",
            mission_id="m1",
            asset_id="app.example.com",
            vulnerability_id="CVE-1",
            technology_id="",
            state=state,
            confidence=confidence,
        )

    def test_new_hypothesis_detected(self) -> None:
        differencer = ValidationDifferencer()
        current = [self._snapshot("hypothesis:app.example.com|CVE-1|", VulnerabilityState.CONFIRMED)]
        differentials = differencer.diff(current, [])
        assert len(differentials) == 1
        assert differentials[0].changes == (DifferentialChange.NEW,)

    def test_fixed_detected(self) -> None:
        differencer = ValidationDifferencer()
        previous = [self._snapshot("hypothesis:app.example.com|CVE-1|", VulnerabilityState.CONFIRMED, 0.9)]
        current = [self._snapshot("hypothesis:app.example.com|CVE-1|", VulnerabilityState.FALSE_POSITIVE)]
        differentials = differencer.diff(current, previous)
        assert len(differentials) == 1
        assert DifferentialChange.FIXED in differentials[0].changes

    def test_unchanged_produces_no_differential(self) -> None:
        differencer = ValidationDifferencer()
        previous = [self._snapshot("hypothesis:app.example.com|CVE-1|", VulnerabilityState.CONFIRMED, 0.9)]
        current = [self._snapshot("hypothesis:app.example.com|CVE-1|", VulnerabilityState.CONFIRMED, 0.9)]
        assert differencer.diff(current, previous) == []

    def test_history_store_tracks_first_and_last_seen(self) -> None:
        store = ValidationHistoryStore()
        entry = store.record(
            target_id="t1",
            asset_id="app.example.com",
            hypothesis_id="h1",
            vulnerability_id="CVE-1",
            state=VulnerabilityState.CONFIRMED,
            verdict="confirmed",
        )
        assert entry.first_seen
        assert entry.last_seen
        assert store.get("t1", "h1") is not None
        assert store.get("t1", "h1").confirmed is True
