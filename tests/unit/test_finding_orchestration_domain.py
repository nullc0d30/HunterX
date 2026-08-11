# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Sprint 028 finding lifecycle domain engines."""

from __future__ import annotations

from hunterx.domain.vulnerability_finding.enums import (
    EvidenceRequirementPurpose,
    EvidenceSufficiencyLevel,
    FindingEvidenceKind,
    FindingState,
    FindingVulnerabilityClass,
    ReplayVerdict,
    ValidationStrategyFamily,
)
from hunterx.domain.vulnerability_finding.evidence import EvidenceRequirementEngine
from hunterx.domain.vulnerability_finding.lifecycle import FindingLifecycleStateMachine
from hunterx.domain.vulnerability_finding.models import EvidenceItem
from hunterx.domain.vulnerability_finding.poc import (
    PoCGenerator,
    PoCReplayVerifier,
    PoCStaticValidator,
    ReplayContext,
    ReplayOutcome,
)
from hunterx.domain.vulnerability_finding.reproduction import (
    ReproducibilityEngine,
    ReproductionInput,
)
from hunterx.domain.vulnerability_finding.strategy import (
    StrategyInput,
    ValidationStrategyEngine,
)


def _item(kind: FindingEvidenceKind, *, quality: str = "high", contradictory: bool = False) -> EvidenceItem:
    return EvidenceItem(
        kind=kind,
        value=f"{kind.value}-value",
        quality=quality,
        source="validation",
        contradictory=contradictory,
    )


class TestFindingLifecycle:
    def test_candidate_to_supported_requires_hypothesis_evidence(self) -> None:
        machine = FindingLifecycleStateMachine()
        assert machine.allowed(FindingState.CANDIDATE, FindingState.SUPPORTED)
        blocked = machine.transition(FindingState.CANDIDATE, FindingState.SUPPORTED)
        assert not blocked.allowed
        assert "hypothesis" in blocked.reason

    def test_validation_requires_validation_evidence(self) -> None:
        machine = FindingLifecycleStateMachine()
        assert not machine.allowed(FindingState.CANDIDATE, FindingState.VALIDATED)
        assert machine.allowed(FindingState.VALIDATING, FindingState.VALIDATED)

    def test_report_ready_requires_reportable_flag(self) -> None:
        machine = FindingLifecycleStateMachine()
        assessment = EvidenceRequirementEngine().analyze(
            FindingVulnerabilityClass.SQL_INJECTION,
            [_item(FindingEvidenceKind.REPLAY)],
        )
        result = machine.transition(
            FindingState.PROVED, FindingState.REPORT_READY, assessment=assessment, reportable=False
        )
        assert not result.allowed
        assert result.reportable_required

    def test_open_conflict_blocks_progress(self) -> None:
        machine = FindingLifecycleStateMachine()
        assessment = EvidenceRequirementEngine().analyze(
            FindingVulnerabilityClass.SQL_INJECTION,
            [_item(FindingEvidenceKind.BEHAVIORAL_DIFFERENTIAL)],
        )
        result = machine.transition(
            FindingState.VALIDATING, FindingState.VALIDATED, assessment=assessment, open_conflict=True
        )
        assert not result.allowed
        assert result.contradiction_detected

    def test_terminal_states(self) -> None:
        machine = FindingLifecycleStateMachine()
        assert machine.is_terminal(FindingState.REPORT_READY)
        assert machine.is_terminal(FindingState.DISPROVED)
        assert not machine.is_terminal(FindingState.VALIDATED)


class TestEvidenceRequirementEngine:
    def test_reflection_alone_is_insufficient_for_sqli(self) -> None:
        engine = EvidenceRequirementEngine()
        assessment = engine.analyze(
            FindingVulnerabilityClass.SQL_INJECTION,
            [_item(FindingEvidenceKind.REFLECTION)],
        )
        verdict = assessment.sufficiency_for(EvidenceRequirementPurpose.VALIDATION)
        assert verdict is not None
        assert verdict.level is EvidenceSufficiencyLevel.INSUFFICIENT

    def test_differential_database_behavior_strengthens_sqli(self) -> None:
        engine = EvidenceRequirementEngine()
        assessment = engine.analyze(
            FindingVulnerabilityClass.SQL_INJECTION,
            [
                _item(FindingEvidenceKind.REFLECTION),
                _item(FindingEvidenceKind.DIFFERENTIAL_DATABASE_BEHAVIOR),
            ],
        )
        verdict = assessment.sufficiency_for(EvidenceRequirementPurpose.VALIDATION)
        assert verdict is not None
        assert verdict.level is EvidenceSufficiencyLevel.SUFFICIENT_FOR_VALIDATION

    def test_independent_reproduction_is_validation_evidence(self) -> None:
        engine = EvidenceRequirementEngine()
        assessment = engine.analyze(
            FindingVulnerabilityClass.XSS,
            [_item(FindingEvidenceKind.INDEPENDENT_REPRODUCTION)],
        )
        verdict = assessment.sufficiency_for(EvidenceRequirementPurpose.VALIDATION)
        assert verdict is not None
        assert verdict.level is EvidenceSufficiencyLevel.SUFFICIENT_FOR_VALIDATION

    def test_contradictory_evidence_marks_assessment(self) -> None:
        engine = EvidenceRequirementEngine()
        assessment = engine.analyze(
            FindingVulnerabilityClass.SSRF,
            [_item(FindingEvidenceKind.CONTROLLED_CALLBACK, contradictory=True)],
        )
        assert assessment.contradictory
        verdict = assessment.sufficiency_for(EvidenceRequirementPurpose.VALIDATION)
        assert verdict is not None
        assert verdict.level is EvidenceSufficiencyLevel.INSUFFICIENT

    def test_gaps_detected_for_missing_evidence(self) -> None:
        engine = EvidenceRequirementEngine()
        assessment = engine.analyze(FindingVulnerabilityClass.SQL_INJECTION, [])
        assert assessment.gaps
        assert any(gap.purpose is EvidenceRequirementPurpose.VALIDATION for gap in assessment.gaps)


class TestValidationStrategyEngine:
    def test_rank_returns_class_strategy_first(self) -> None:
        engine = ValidationStrategyEngine()
        ranked = engine.rank(
            StrategyInput(
                vulnerability_class=FindingVulnerabilityClass.SQL_INJECTION,
                tool_capabilities=("sql_injection", "vulnerability_scanning"),
            )
        )
        assert ranked
        assert ranked[0].family is ValidationStrategyFamily.SQL_INJECTION

    def test_scope_blocked_returns_empty(self) -> None:
        engine = ValidationStrategyEngine()
        ranked = engine.rank(
            StrategyInput(
                vulnerability_class=FindingVulnerabilityClass.SQL_INJECTION,
                scope_ok=False,
            )
        )
        assert ranked == ()

    def test_strategy_policy_is_safe(self) -> None:
        engine = ValidationStrategyEngine()
        ranked = engine.rank(
            StrategyInput(vulnerability_class=FindingVulnerabilityClass.RCE)
        )
        assert ranked
        policy = ranked[0].policy
        assert policy.stop_conditions
        assert policy.rollback_requirements


class TestPoCLifecycle:
    def test_generated_poc_is_not_valid(self) -> None:
        reproduction = ReproducibilityEngine().build(
            ReproductionInput(finding_id="f", request="/x", method="GET")
        )
        poc = PoCGenerator().generate(reproduction)
        from hunterx.domain.vulnerability_finding.enums import PocLifecycleState

        assert poc.lifecycle_state is PocLifecycleState.GENERATED

    def test_static_validation_advances_to_static_validated(self) -> None:
        reproduction = ReproducibilityEngine().build(
            ReproductionInput(finding_id="f", request="/x", method="GET")
        )
        poc = PoCGenerator().generate(reproduction)
        validated, reason = PoCStaticValidator().validate(poc, allowed_targets=("/x",))
        from hunterx.domain.vulnerability_finding.enums import PocLifecycleState

        assert validated.lifecycle_state is PocLifecycleState.STATIC_VALIDATED
        assert "passed" in reason

    def test_secret_value_pattern_rejects_poc(self) -> None:
        from hunterx.domain.vulnerability_finding.enums import PocLifecycleState

        reproduction = ReproducibilityEngine().build(
            ReproductionInput(finding_id="f", request="/x", method="GET")
        )
        poc = PoCGenerator().generate(reproduction)
        poisoned = type(poc)(**{**poc.to_dict(), "content": "Authorization: Bearer sk-123456"})
        rejected, reason = PoCStaticValidator().validate(poisoned)
        assert rejected.lifecycle_state is PocLifecycleState.REJECTED
        assert "secret" in reason

    def test_replay_verifies_conditions_not_http_200(self) -> None:
        poc = PoCGenerator().generate(
            ReproducibilityEngine().build(ReproductionInput(finding_id="f", request="/x", method="GET"))
        )
        context = ReplayContext(
            finding_id="f",
            poc_id=poc.poc_id,
            expected_target="https://example.com",
            expected_input_hash=poc.content_hash,
            expected_evidence_class="xss",
        )
        # Same target but non-confirmed behavior must NOT be CONFIRMED.
        outcome = ReplayOutcome(
            target="https://example.com",
            confirmed=False,
            input_hash=poc.content_hash,
            evidence_class="xss",
        )
        assert PoCReplayVerifier().verdict(context, outcome) is ReplayVerdict.NOT_REPRODUCIBLE

    def test_replay_confirmed_advances_to_proof_validated(self) -> None:
        poc = PoCGenerator().generate(
            ReproducibilityEngine().build(ReproductionInput(finding_id="f", request="/x", method="GET"))
        )
        context = ReplayContext(
            finding_id="f",
            poc_id=poc.poc_id,
            expected_target="https://example.com",
            expected_input_hash=poc.content_hash,
            expected_evidence_class="xss",
        )
        outcome = ReplayOutcome(
            target="https://example.com",
            confirmed=True,
            input_hash=poc.content_hash,
            evidence_class="xss",
        )
        advanced = PoCReplayVerifier().verify(poc, context, outcome)
        from hunterx.domain.vulnerability_finding.enums import PocLifecycleState

        assert advanced.lifecycle_state is PocLifecycleState.PROOF_VALIDATED

    def test_replay_wrong_target_rejected(self) -> None:
        poc = PoCGenerator().generate(
            ReproducibilityEngine().build(ReproductionInput(finding_id="f", request="/x", method="GET"))
        )
        context = ReplayContext(
            finding_id="f",
            poc_id=poc.poc_id,
            expected_target="https://example.com",
            expected_input_hash=poc.content_hash,
            expected_evidence_class="xss",
        )
        outcome = ReplayOutcome(
            target="https://attacker.example",
            confirmed=True,
            input_hash=poc.content_hash,
            evidence_class="xss",
        )
        assert PoCReplayVerifier().verdict(context, outcome) is ReplayVerdict.DIFFERENT_TARGET


class TestReproducibility:
    def test_reproduction_redacts_secrets(self) -> None:
        engine = ReproducibilityEngine()
        reproduction = engine.build(
            ReproductionInput(
                finding_id="f",
                request="/x",
                method="GET",
                headers={"Authorization": "Bearer sk-1234567890", "Host": "example.com"},
            )
        )
        assert reproduction.redacted
        assert "sk-1234567890" not in reproduction.headers["Authorization"]
        assert reproduction.headers["Host"] == "example.com"
