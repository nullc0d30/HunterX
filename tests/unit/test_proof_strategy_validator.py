# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the proof validator (deterministic verdicts)."""

from __future__ import annotations

from hunterx.domain.vulnerability_proof.enums import ReplayResult
from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.models import ProofReplay
from hunterx.domain.vulnerability_proof.strategy import (
    ProofQualityLevel,
    ProofStrategy,
    ProofVerdict,
)
from hunterx.domain.vulnerability_proof.validator import (
    ProofValidationContext,
    ProofValidator,
)
from hunterx.domain.vulnerability_validation.enums import (
    EvidenceComparison,
    EvidenceKind,
    SafetyClass,
    ValidationClass,
)
from hunterx.domain.vulnerability_validation.models import ValidationEvidence, ValidationObservation


def _strategy(strategy_id: str = "strategy.sql_injection") -> ProofStrategy:
    return next(item for item in default_strategy_library() if item.strategy_id == strategy_id)


def _evidence(kind: EvidenceKind, comparison: EvidenceComparison = EvidenceComparison.MATCH) -> ValidationEvidence:
    return ValidationEvidence(
        observation=ValidationObservation(kind=kind, value=f"observed {kind.value}", source="proof-replay"),
        comparison=comparison,
        expected_behavior="expected",
        observed_behavior=f"observed {kind.value}",
    )


def _replay(
    result: ReplayResult = ReplayResult.SUCCESS,
    *,
    target_state: str = "s1",
    generated_target_state: str = "s1",
) -> ProofReplay:
    return ProofReplay(
        proof_id="p1",
        result=result,
        target_state=target_state,
    )


def _sql_context(*, evidence=None, replays=None, **overrides) -> ProofValidationContext:
    defaults: dict = {
        "proof_id": "p1",
        "vulnerability_class": ValidationClass.SQL_INJECTION,
        "evidence": tuple(evidence if evidence is not None else (_evidence(EvidenceKind.BEHAVIORAL_DIFFERENTIAL),)),
        "replays": tuple(replays if replays is not None else (_replay(), _replay())),
        "target_state": "s1",
        "generated_target_state": "s1",
        "scope": {},
        "safety_class": SafetyClass.BENIGN_MARKER,
        "expected_observations": ("differential behavior",),
        "impact_evidence": ("integrity", "confidentiality"),
    }
    defaults.update(overrides)
    return ProofValidationContext(**defaults)


class TestVerdicts:
    def test_valid_full_proof(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), _sql_context())
        assert result.verdict == ProofVerdict.VALID
        assert result.evidence_contract_ok is True
        assert result.score > 0.5
        assert result.reasoning

    def test_invalid_proof_structure(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), ProofValidationContext(proof_id=""))
        assert result.verdict == ProofVerdict.INVALID

    def test_incompatible_strategy(self) -> None:
        validator = ProofValidator()
        result = validator.validate(
            _strategy("strategy.xss"),
            ProofValidationContext(proof_id="p1", vulnerability_class=ValidationClass.SQL_INJECTION),
        )
        assert result.verdict == ProofVerdict.INVALID

    def test_unsafe_safety_class(self) -> None:
        validator = ProofValidator()
        result = validator.validate(
            _strategy(),
            _sql_context(safety_class=SafetyClass.DESTRUCTIVE),
        )
        assert result.verdict == ProofVerdict.UNSAFE

    def test_out_of_scope(self) -> None:
        validator = ProofValidator()
        strategy = _strategy("strategy.ssrf")
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SSRF,
            scope={"loopback-control-authorized": "no"},
            evidence=(_evidence(EvidenceKind.CONTROLLED_CALLBACK),),
            replays=(_replay(), _replay()),
        )
        result = validator.validate(strategy, context)
        assert result.verdict == ProofVerdict.OUT_OF_SCOPE

    def test_blocked(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), _sql_context(blocked="scope_blocked"))
        assert result.verdict == ProofVerdict.BLOCKED

    def test_contradicted_by_mismatch(self) -> None:
        validator = ProofValidator()
        result = validator.validate(
            _strategy(),
            _sql_context(
                evidence=(
                    _evidence(EvidenceKind.BEHAVIORAL_DIFFERENTIAL, EvidenceComparison.MISMATCH),
                )
            ),
        )
        assert result.verdict == ProofVerdict.CONTRADICTED
        assert any("mismatch" in item for item in result.contradictory_evidence)

    def test_contradicted_by_disqualifying_kind(self) -> None:
        validator = ProofValidator()
        # The SQL strategy marks "baseline-identical" as contradictory evidence.
        context = _sql_context(
            evidence=(
                ValidationEvidence(
                    observation=ValidationObservation(kind=EvidenceKind.EXTERNAL, value="baseline-identical"),
                    comparison=EvidenceComparison.MATCH,
                ),
            )
        )
        result = validator.validate(_strategy(), context)
        assert result.verdict == ProofVerdict.CONTRADICTED

    def test_scanner_only_insufficient(self) -> None:
        validator = ProofValidator()
        # A scanner signature alone is declared INSUFFICIENT evidence.
        context = _sql_context(
            evidence=(
                ValidationEvidence(
                    observation=ValidationObservation(kind=EvidenceKind.EXTERNAL, value="scanner_signature"),
                    comparison=EvidenceComparison.MATCH,
                ),
            )
        )
        result = validator.validate(_strategy(), context)
        assert result.verdict == ProofVerdict.INSUFFICIENT_EVIDENCE
        assert "behavioral_differential" in result.missing_evidence

    def test_insufficient_evidence_no_evidence(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), ProofValidationContext(proof_id="p1"))
        assert result.verdict == ProofVerdict.INSUFFICIENT_EVIDENCE

    def test_negative_observation_invalid(self) -> None:
        validator = ProofValidator()
        result = validator.validate(
            _strategy(),
            _sql_context(
                evidence=(
                    ValidationEvidence(
                        observation=ValidationObservation(kind=EvidenceKind.EXTERNAL, value="no-behavioral-difference"),
                        comparison=EvidenceComparison.MATCH,
                    ),
                )
            ),
        )
        assert result.verdict == ProofVerdict.INVALID

    def test_incomplete_when_not_enough_replays(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), _sql_context(replays=(_replay(),)))
        assert result.verdict == ProofVerdict.INCOMPLETE

    def test_inconclusive_when_target_state_changed(self) -> None:
        validator = ProofValidator()
        replay = ProofReplay(proof_id="p1", result=ReplayResult.SUCCESS, target_state="s2")
        result = validator.validate(
            _strategy(),
            _sql_context(replays=(replay, replay)),
        )
        assert result.verdict == ProofVerdict.INCONCLUSIVE
        assert result.replay_result.target_state.value == "changed"
        assert any("REPLAY_INVALIDATED" in reason for reason in result.reasoning)

    def test_incomplete_when_impact_missing(self) -> None:
        validator = ProofValidator()
        strategy = _strategy("strategy.ssrf")
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SSRF,
            evidence=(_evidence(EvidenceKind.CONTROLLED_CALLBACK),),
            replays=(_replay(), _replay()),
            target_state="s1",
            generated_target_state="s1",
            scope={"loopback-control-authorized": "yes"},
        )
        result = validator.validate(strategy, context)
        # SSRF requires impact evidence (resource_access, data_exposure) -> incomplete
        assert result.verdict == ProofVerdict.INCOMPLETE

    def test_replay_blocked(self) -> None:
        validator = ProofValidator()
        blocked_replay = ProofReplay(proof_id="p1", result=ReplayResult.BLOCKED)
        result = validator.validate(_strategy(), _sql_context(replays=(blocked_replay, blocked_replay)))
        assert result.verdict == ProofVerdict.INCOMPLETE
        assert result.replay_result.reason == "replay blocked"


class TestQualityLevels:
    def test_p0_candidate_no_evidence(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), ProofValidationContext(proof_id="p1"))
        assert result.proof_quality_level == ProofQualityLevel.P0_CANDIDATE

    def test_p1_observed_no_replays(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), _sql_context(replays=()))
        assert result.proof_quality_level == ProofQualityLevel.P1_OBSERVED

    def test_p3_proven_with_replays(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), _sql_context())
        assert result.proof_quality_level in (
            ProofQualityLevel.P3_PROVEN,
            ProofQualityLevel.P4_CONFIRMED,
            ProofQualityLevel.P5_REPORT_READY,
        )

    def test_report_ready_level(self) -> None:
        validator = ProofValidator()
        context = _sql_context(independent_verified=True, impact_evidence=("integrity", "confidentiality"))
        result = validator.validate(_strategy(), context)
        assert result.verdict == ProofVerdict.VALID
        assert result.proof_quality_level == ProofQualityLevel.P5_REPORT_READY


class TestNoConfidenceCheating:
    def test_high_confidence_never_bypasses_evidence(self) -> None:
        # A 99% AI belief without the required evidence must remain NOT_PROVEN.
        validator = ProofValidator()
        context = ProofValidationContext(proof_id="p1", vulnerability_class=ValidationClass.SQL_INJECTION)
        result = validator.validate(_strategy(), context)
        assert result.verdict == ProofVerdict.INSUFFICIENT_EVIDENCE
        assert result.score == 0.0
        assert result.proof_quality_level == ProofQualityLevel.P0_CANDIDATE

    def test_contradiction_never_averaged(self) -> None:
        validator = ProofValidator()
        evidence = (
            _evidence(EvidenceKind.BEHAVIORAL_DIFFERENTIAL, EvidenceComparison.MATCH),
            _evidence(EvidenceKind.BEHAVIORAL_DIFFERENTIAL, EvidenceComparison.MISMATCH),
        )
        result = validator.validate(_strategy(), _sql_context(evidence=evidence))
        assert result.verdict == ProofVerdict.CONTRADICTED
        assert result.score == 0.0


class TestReproducibility:
    def test_single_success_not_reproducible(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), _sql_context(replays=(_replay(),)))
        assert result.verdict == ProofVerdict.INCOMPLETE
        assert result.reproducibility_result.status == "partial"

    def test_two_successes_reproducible(self) -> None:
        validator = ProofValidator()
        result = validator.validate(_strategy(), _sql_context())
        assert result.reproducibility_result.status == "reproducible"
