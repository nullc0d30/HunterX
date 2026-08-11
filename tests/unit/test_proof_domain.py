# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the vulnerability proof & PoC domain."""

from __future__ import annotations

import pytest

from hunterx.domain.vulnerability_proof.confidence import ConfidenceEngine, ConfidencePolicy
from hunterx.domain.vulnerability_proof.contracts import ProofContractRegistry, default_proof_contracts
from hunterx.domain.vulnerability_proof.enums import (
    FindingLifecycleState,
    ProofState,
    ProofType,
    ReplayResult,
    ReplayVerdict,
    ReproducibilityStatus,
)
from hunterx.domain.vulnerability_proof.generation import SafeProofGenerator, UnsafeProofInputError
from hunterx.domain.vulnerability_proof.impact import ImpactAssessor
from hunterx.domain.vulnerability_proof.models import (
    ProofOfConcept,
    ProofPlan,
    VulnerabilityProof,
    proof_from_dict,
    proof_key,
)
from hunterx.domain.vulnerability_proof.planning import ProofPlanner
from hunterx.domain.vulnerability_proof.quality import ProofQualityScorer
from hunterx.domain.vulnerability_proof.reasoning import ProofReasoningLoop
from hunterx.domain.vulnerability_proof.replay import ReplayEngine
from hunterx.domain.vulnerability_proof.state import (
    FindingLifecycleStateMachine,
    ProofStateMachine,
)
from hunterx.domain.vulnerability_proof.temporal import (
    ProofSnapshot,
    ProofTemporalDifferencer,
)
from hunterx.domain.vulnerability_validation.enums import (
    EvidenceComparison,
    EvidenceKind,
    SafetyClass,
    ValidationClass,
)
from hunterx.domain.vulnerability_validation.models import (
    ValidationEvidence,
    ValidationObservation,
    VulnerabilityHypothesis,
)


def _hypothesis(**kwargs) -> VulnerabilityHypothesis:
    defaults = dict(
        hypothesis_id="h1",
        mission_id="m1",
        target_id="app.example.com",
        asset_id="app.example.com",
        vulnerability_id="CVE-2024-0001",
        type=ValidationClass.SQL_INJECTION,
        expected_behavior="marker reflected differently",
    )
    defaults.update(kwargs)
    return VulnerabilityHypothesis(**defaults)


def _proof(**kwargs) -> VulnerabilityProof:
    defaults = dict(
        proof_id="p1",
        hypothesis_id="h1",
        mission_id="m1",
        target_id="app.example.com",
        asset_id="app.example.com",
        vulnerability_id="CVE-2024-0001",
        proof_type=ProofType.DIFFERENTIAL_PROOF,
        proof_status=ProofState.CANDIDATE,
    )
    defaults.update(kwargs)
    return VulnerabilityProof(**defaults)


def _observation(kind, value, *, expected=None, confidence=1.0) -> ValidationObservation:
    metadata = {}
    if expected is not None:
        metadata["expected"] = expected
    return ValidationObservation(kind=kind, value=value, confidence=confidence, metadata=metadata)


class TestProofKey:
    def test_key_stability(self) -> None:
        assert proof_key(asset="app.example.com", hypothesis_id="h1") == proof_key(
            asset="app.example.com", hypothesis_id="h1"
        )


class TestProofModel:
    def test_round_trip(self) -> None:
        proof = _proof(confidence=0.7, evidence_ids=("e1", "e2"))
        restored = proof_from_dict(proof.to_dict())
        assert restored.proof_id == proof.proof_id
        assert restored.proof_type == ProofType.DIFFERENTIAL_PROOF
        assert restored.confidence == 0.7
        assert restored.evidence_ids == ("e1", "e2")

    def test_generated_never_validated(self) -> None:
        proof = _proof(proof_status=ProofState.GENERATED)
        assert proof.proof_status == ProofState.GENERATED
        assert proof.proof_status != ProofState.VALIDATED


class TestProofStateMachine:
    @pytest.mark.parametrize(
        ("current", "target", "expected"),
        [
            (ProofState.CANDIDATE, ProofState.PLANNED, True),
            (ProofState.GENERATED, ProofState.EXECUTED, True),
            (ProofState.EXECUTED, ProofState.REPLAYED, True),
            (ProofState.REPLAYED, ProofState.VALIDATED, True),
            (ProofState.GENERATED, ProofState.VALIDATED, False),
            (ProofState.EXECUTED, ProofState.VALIDATED, False),
            (ProofState.PLANNED, ProofState.VALIDATED, False),
            (ProofState.VALIDATED, ProofState.SUPERSEDED, True),
        ],
    )
    def test_transitions(self, current, target, expected) -> None:
        machine = ProofStateMachine()
        assert machine.can(current, target) is expected

    def test_invalid_transition_rejected(self) -> None:
        machine = ProofStateMachine()
        transition = machine.transition(ProofState.GENERATED, ProofState.VALIDATED, reason="attempt")
        assert transition.allowed is False


class TestFindingLifecycleStateMachine:
    def test_validated_to_proven(self) -> None:
        machine = FindingLifecycleStateMachine()
        assert machine.can(FindingLifecycleState.VALIDATED, FindingLifecycleState.PROVEN)
        assert machine.can(FindingLifecycleState.PROVEN, FindingLifecycleState.CONFIRMED)
        assert machine.can(FindingLifecycleState.CONFIRMED, FindingLifecycleState.REPORT_READY)

    def test_detected_never_proven(self) -> None:
        machine = FindingLifecycleStateMachine()
        assert not machine.can(FindingLifecycleState.DETECTED, FindingLifecycleState.PROVEN)

    def test_false_positive_distinct_from_inconclusive(self) -> None:
        machine = FindingLifecycleStateMachine()
        assert machine.can(FindingLifecycleState.VALIDATED, FindingLifecycleState.FALSE_POSITIVE)
        assert machine.can(FindingLifecycleState.VALIDATED, FindingLifecycleState.INCONCLUSIVE)


class TestProofContracts:
    def test_default_contracts_cover_core_classes(self) -> None:
        contracts = ProofContractRegistry(default_proof_contracts())
        for cls in (
            ValidationClass.SQL_INJECTION,
            ValidationClass.XSS,
            ValidationClass.SSRF,
            ValidationClass.PATH_TRAVERSAL,
            ValidationClass.BROKEN_ACCESS_CONTROL,
            ValidationClass.AUTHENTICATION,
            ValidationClass.DEPENDENCY_VULNERABILITY,
            ValidationClass.UNKNOWN_BEHAVIOR,
        ):
            assert contracts.supports(cls), cls

    def test_sql_injection_contract_permits_confirmation(self) -> None:
        contracts = ProofContractRegistry()
        contract = contracts.require(ValidationClass.SQL_INJECTION)
        assert contract.permits_confirmation is True
        assert contract.required_evidence
        assert ProofType.DIFFERENTIAL_PROOF in contract.proof_types

    def test_novel_contract_never_confirms_or_reports(self) -> None:
        contracts = ProofContractRegistry()
        contract = contracts.require(ValidationClass.UNKNOWN_BEHAVIOR)
        assert contract.permits_confirmation is False
        assert contract.reportable is False

    def test_no_destructive_actions_allowed(self) -> None:
        from hunterx.domain.vulnerability_proof.contracts import FORBIDDEN_PROOF_ACTIONS

        contracts = ProofContractRegistry()
        for contract in contracts.contracts:
            for forbidden in FORBIDDEN_PROOF_ACTIONS:
                assert forbidden in contract.forbidden_actions


class TestProofPlanner:
    def test_plan_steps_are_minimal_safe(self) -> None:
        planner = ProofPlanner()
        proof = _proof()
        plan = planner.plan(proof, _hypothesis())
        assert plan.proof_plan_id
        assert plan.proof_id == proof.proof_id
        assert plan.steps
        assert all(step.safety_class != SafetyClass.DESTRUCTIVE for step in plan.steps)
        assert plan.replay_requirements
        assert plan.evidence_requirements

    def test_plan_rejects_unsupported_class(self) -> None:
        planner = ProofPlanner()
        hypothesis = _hypothesis(type=ValidationClass.KNOWN_VULNERABLE_SOFTWARE)
        proof = _proof()
        with pytest.raises(KeyError):
            planner.plan(proof, hypothesis)


class TestSafeProofGenerator:
    def test_generates_structured_poc(self) -> None:
        planner = ProofPlanner()
        proof = _proof()
        hypothesis = _hypothesis()
        plan = planner.plan(proof, hypothesis)
        contracts = ProofContractRegistry()
        contract = contracts.require(hypothesis.type)
        generator = SafeProofGenerator()
        poc = generator.generate(plan, contract, inputs={"target": "https://app.example.com/x?id=1", "marker": "hx_abc"})
        assert poc.proof_id == proof.proof_id
        assert poc.expected_result == "hx_abc observed"
        assert poc.inputs
        assert poc.steps
        assert poc.status.value == "candidate"

    def test_refuses_unsafe_inputs(self) -> None:
        generator = SafeProofGenerator()
        from hunterx.domain.vulnerability_proof.contracts import ProofContractRegistry

        contracts = ProofContractRegistry()
        contract = contracts.require(ValidationClass.SQL_INJECTION)
        with pytest.raises(UnsafeProofInputError):
            generator.generate(
                ProofPlan(proof_id="p1", hypothesis_id="h1"),
                contract,
                inputs={"param": "1; rm -rf /"},
            )

    def test_poc_versioning(self) -> None:
        generator = SafeProofGenerator()
        contracts = ProofContractRegistry()
        contract = contracts.require(ValidationClass.SQL_INJECTION)
        plan = ProofPlan(proof_id="p1", hypothesis_id="h1")
        poc = generator.generate(plan, contract, inputs={"marker": "a"})
        v2 = generator.new_version(poc, reason="changed marker", changes=("marker",), inputs={"marker": "b"})
        assert v2.poc_id == poc.poc_id
        assert v2.version == "1.1.0"
        assert v2.parent_version == poc.version


class TestReplayEngine:
    def test_match_success(self) -> None:
        engine = ReplayEngine()
        replay = engine.replay(
            ProofOfConcept(proof_id="p1", expected_result="marker observed"),
            _proof(),
            observed_behavior="marker observed",
            expected_behavior="marker observed",
        )
        assert replay.result == ReplayResult.SUCCESS
        assert replay.verdict == ReplayVerdict.SUCCESS
        assert replay.input_hash
        assert replay.evidence_hash

    def test_mismatch_failed(self) -> None:
        engine = ReplayEngine()
        replay = engine.replay(
            ProofOfConcept(proof_id="p1", expected_result="marker observed"),
            _proof(),
            observed_behavior="no marker",
            expected_behavior="marker observed",
        )
        assert replay.result == ReplayResult.FAILED
        assert replay.verdict == ReplayVerdict.FAILED

    def test_empty_inconclusive(self) -> None:
        engine = ReplayEngine()
        replay = engine.replay(
            ProofOfConcept(proof_id="p1", expected_result="marker observed"),
            _proof(),
            observed_behavior="",
            expected_behavior="marker observed",
        )
        assert replay.result == ReplayResult.INCONCLUSIVE

    def test_reproducibility_requires_repeated_success(self) -> None:
        engine = ReplayEngine()
        poc = ProofOfConcept(proof_id="p1", expected_result="marker observed")
        proof = _proof()
        one = [engine.replay(poc, proof, observed_behavior="marker observed")]
        assert engine.reproducibility(one) == ReproducibilityStatus.PARTIAL
        two = [
            engine.replay(poc, proof, observed_behavior="marker observed"),
            engine.replay(poc, proof, observed_behavior="marker observed"),
        ]
        assert engine.reproducibility(two) == ReproducibilityStatus.REPRODUCIBLE
        assert engine.reproducibility([]) == ReproducibilityStatus.NOT_ASSESSED


class TestImpactAssessor:
    def test_evidence_backed_level(self) -> None:
        assessor = ImpactAssessor()
        evidence = [
            ValidationEvidence(
                evidence_id="e1",
                observation=_observation(EvidenceKind.BEHAVIORAL_DIFFERENTIAL, "marker reflected differently"),
                comparison=EvidenceComparison.MATCH,
                confidence=0.9,
            )
        ]
        impact = assessor.assess(
            proof_id="p1",
            finding_id="f1",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=evidence,
        )
        assert impact.evidence_ids == ("e1",)
        assert impact.impact_level.value != "none"
        assert impact.confidence == 0.9

    def test_no_evidence_means_none(self) -> None:
        assessor = ImpactAssessor()
        impact = assessor.assess(
            proof_id="p1",
            finding_id="f1",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=[],
        )
        assert impact.impact_level.value == "none"


class TestConfidenceEngine:
    def test_weights_must_sum_to_one(self) -> None:
        with pytest.raises(ValueError):
            ConfidencePolicy(weights={"a": 0.5, "b": 0.25})

    def test_evidence_driven_confidence(self) -> None:
        engine = ConfidenceEngine()
        evidence = [
            ValidationEvidence(
                evidence_id="e1",
                observation=_observation(EvidenceKind.BEHAVIORAL_DIFFERENTIAL, "marker reflected differently"),
                comparison=EvidenceComparison.MATCH,
                confidence=0.9,
            )
        ]
        replay_engine = ReplayEngine()
        poc = ProofOfConcept(proof_id="p1", expected_result="marker observed")
        proof = _proof()
        replays = [replay_engine.replay(poc, proof, observed_behavior="marker observed", expected_behavior="marker observed") for _ in range(2)]
        assessment = engine.calculate(
            proof_id="p1", finding_id="f1",
            evidence=evidence, replays=replays,
            scope_certainty=1.0, target_stability=1.0,
        )
        assert assessment.confidence > 0.0
        assert assessment.confidence_policy_id == "confidence-policy/1.0.0"
        assert assessment.weights
        assert assessment.factor_scores
        assert assessment.evidence_ids == ("e1",)

    def test_no_evidence_low_confidence(self) -> None:
        engine = ConfidenceEngine()
        assessment = engine.calculate(proof_id="p1", finding_id="f1")
        # Only scope-certainty + target-stability contribute (0.075 + 0.075).
        assert assessment.confidence == pytest.approx(0.15)
        assert assessment.state.value == "low"


class TestProofQualityScorer:
    def test_score_is_explainable(self) -> None:
        scorer = ProofQualityScorer()
        proof = _proof(proof_status=ProofState.VALIDATED, reproducibility_status=ReproducibilityStatus.REPRODUCIBLE)
        quality = scorer.score(proof)
        assert 0.0 <= quality.score <= 1.0
        assert quality.factors
        assert sum(quality.factors.values()) > 0.0


class TestProofReasoningLoop:
    def test_provable_when_all_questions_hold(self) -> None:
        contracts = ProofContractRegistry()
        contract = contracts.require(ValidationClass.SQL_INJECTION)
        hypothesis = _hypothesis()
        proof = _proof(expected_behavior="marker reflected differently")
        evidence = [
            ValidationEvidence(
                evidence_id="e1",
                observation=_observation(EvidenceKind.BEHAVIORAL_DIFFERENTIAL, "marker reflected differently"),
                comparison=EvidenceComparison.MATCH,
            )
        ]
        loop = ProofReasoningLoop()
        decision = loop.can_prove(
            hypothesis=hypothesis, proof=proof, contract=contract,
            evidence=evidence, safe=True, replayable=True,
            demonstrable_impact="differential behavior",
        )
        assert decision.outcome.value == "provable"

    def test_inconclusive_when_not_replayable(self) -> None:
        contracts = ProofContractRegistry()
        contract = contracts.require(ValidationClass.SQL_INJECTION)
        loop = ProofReasoningLoop()
        decision = loop.can_prove(
            hypothesis=_hypothesis(),
            proof=_proof(expected_behavior="x"),
            contract=contract,
            safe=True, replayable=False, demonstrable_impact="x",
        )
        assert decision.outcome.value == "inconclusive"


class TestProofTemporal:
    def test_first_proven(self) -> None:
        differencer = ProofTemporalDifferencer()
        current = ProofSnapshot(
            key="proof:app|h1|CVE-1",
            proof_id="p1", hypothesis_id="h1", mission_id="m1",
            asset_id="app.example.com", vulnerability_id="CVE-1",
            state=ProofState.VALIDATED,
        )
        assert differencer.changes(current, None) == ["first_proven"]

    def test_still_proven_and_changed_evidence(self) -> None:
        differencer = ProofTemporalDifferencer()
        current = ProofSnapshot(
            key="proof:app|h1|CVE-1",
            proof_id="p1", hypothesis_id="h1", mission_id="m1",
            asset_id="app.example.com", vulnerability_id="CVE-1",
            state=ProofState.VALIDATED, evidence_ids=("e1", "e2"),
        )
        previous = ProofSnapshot(
            key="proof:app|h1|CVE-1",
            proof_id="p1", hypothesis_id="h1", mission_id="m1",
            asset_id="app.example.com", vulnerability_id="CVE-1",
            state=ProofState.VALIDATED, evidence_ids=("e1",),
        )
        changes = differencer.changes(current, previous)
        assert "still_proven" in changes
        assert "changed_evidence" in changes

    def test_fixed_when_invalidated(self) -> None:
        differencer = ProofTemporalDifferencer()
        current = ProofSnapshot(
            key="proof:app|h1|CVE-1",
            proof_id="p1", hypothesis_id="h1", mission_id="m1",
            asset_id="app.example.com", vulnerability_id="CVE-1",
            state=ProofState.INVALIDATED,
        )
        previous = ProofSnapshot(
            key="proof:app|h1|CVE-1",
            proof_id="p1", hypothesis_id="h1", mission_id="m1",
            asset_id="app.example.com", vulnerability_id="CVE-1",
            state=ProofState.VALIDATED,
        )
        assert "invalidated" in differencer.changes(current, previous)
