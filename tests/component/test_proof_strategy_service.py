# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the proof strategy service pipeline."""

from __future__ import annotations

from hunterx.application.vulnerability_proof_strategy import VulnerabilityProofStrategyService
from hunterx.domain.vulnerability_proof.enums import ReplayResult
from hunterx.domain.vulnerability_proof.models import ProofReplay
from hunterx.domain.vulnerability_proof.strategy import (
    ProofExecutability,
    ProofQualityLevel,
    ProofVerdict,
    StrategyCandidateStatus,
)
from hunterx.domain.vulnerability_proof.validator import ProofValidationContext
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
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus


def _service() -> VulnerabilityProofStrategyService:
    return VulnerabilityProofStrategyService(
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
    )


def _hypothesis() -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        mission_id="m1",
        target_id="t1",
        asset_id="https://app.example.com/endpoint?id=1",
        type=ValidationClass.SQL_INJECTION,
        hypothesis_id="h1",
    )


def _evidence(kind: EvidenceKind, comparison: EvidenceComparison = EvidenceComparison.MATCH) -> ValidationEvidence:
    return ValidationEvidence(
        evidence_id=f"ev-{kind.value}",
        validation_id="v1",
        hypothesis_id="h1",
        mission_id="m1",
        target_id="t1",
        asset_id="a1",
        tool_id="proof-replay",
        observation=ValidationObservation(kind=kind, value=f"value-{kind.value}", source="proof-replay"),
        expected_behavior="expected",
        observed_behavior=f"value-{kind.value}",
        comparison=comparison,
    )


def _replay() -> ProofReplay:
    return ProofReplay(proof_id="p1", poc_id="poc1", result=ReplayResult.SUCCESS, target_state="s1")


class TestServiceSelection:
    def test_select_strategy_with_hypothesis(self) -> None:
        service = _service()
        selection = service.select_strategy(
            ValidationClass.SQL_INJECTION,
            hypothesis=_hypothesis(),
            available_evidence=("behavioral_differential",),
            authorization_level="authorized",
        )
        assert selection.strategy.strategy_id == "strategy.sql_injection"
        assert selection.executability == ProofExecutability.EXECUTABLE
        assert service.strategy("strategy.sql_injection") is not None

    def test_select_blocked_for_unsupported_class(self) -> None:
        service = _service()
        selection = service.select_strategy(ValidationClass.INJECTION, hypothesis=_hypothesis())
        assert selection.executability == ProofExecutability.PROOF_NOT_EXECUTABLE

    def test_strategy_registration_is_persisted(self) -> None:
        service = _service()
        strategy = service.strategy("strategy.xss")
        assert strategy is not None
        assert service.strategies()


class TestServiceValidation:
    def test_validate_full_proof_persists_result(self) -> None:
        service = _service()
        strategy = service.strategy("strategy.sql_injection")
        assert strategy is not None
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=(_evidence(EvidenceKind.BEHAVIORAL_DIFFERENTIAL),),
            replays=(_replay(), _replay()),
            target_state="s1",
            generated_target_state="s1",
            safety_class=SafetyClass.BENIGN_MARKER,
            expected_observations=("differential behavior",),
            impact_evidence=("integrity", "confidentiality"),
            independent_verified=True,
        )
        result = service.validate_proof(strategy, context)
        assert result.verdict == ProofVerdict.VALID
        assert result.proof_quality_level == ProofQualityLevel.P5_REPORT_READY
        persisted = service.validation_results(proof_id="p1")
        assert len(persisted) == 1
        assert persisted[0].verdict == ProofVerdict.VALID

    def test_validate_contradiction_persists(self) -> None:
        service = _service()
        strategy = service.strategy("strategy.sql_injection")
        assert strategy is not None
        context = ProofValidationContext(
            proof_id="p2",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=(_evidence(EvidenceKind.BEHAVIORAL_DIFFERENTIAL, EvidenceComparison.MISMATCH),),
            replays=(_replay(), _replay()),
        )
        result = service.validate_proof(strategy, context)
        assert result.verdict == ProofVerdict.CONTRADICTED


class TestServiceCandidates:
    def test_propose_approve_reject_flow(self) -> None:
        service = _service()
        strategy = service.strategy("strategy.unknown_behavior")
        assert strategy is not None
        candidate = service.propose_candidate(
            vulnerability_class=ValidationClass.UNKNOWN_BEHAVIOR,
            observed_behavior="marker echoed in error page",
            evidence=("behavioral_differential",),
            reasoning="novel reflection behavior",
            proposed_strategy=strategy,
            hypothesis_id="h1",
            mission_id="m1",
        )
        assert candidate.status == StrategyCandidateStatus.PROPOSED
        fetched = service.get_candidate(candidate.candidate_id)
        assert fetched is not None
        assert fetched.candidate_id == candidate.candidate_id

        approved = service.approve_candidate(candidate.candidate_id, strategy=candidate.proposed_strategy)
        assert approved.status == StrategyCandidateStatus.APPROVED
        candidates = service.candidates(status="approved")
        assert any(item.candidate_id == candidate.candidate_id for item in candidates)

        second = service.propose_candidate(
            vulnerability_class=ValidationClass.UNKNOWN_BEHAVIOR,
            observed_behavior="another novel behavior",
            reasoning="to be rejected",
            proposed_strategy=strategy,
        )
        rejected = service.reject_candidate(second.candidate_id, reason="not reproducible")
        assert rejected.status == StrategyCandidateStatus.REJECTED

    def test_approve_requires_strategy(self) -> None:
        service = _service()
        candidate = service.propose_candidate(
            vulnerability_class=ValidationClass.UNKNOWN_BEHAVIOR,
            observed_behavior="behavior",
            reasoning="reason",
        )
        try:
            service.approve_candidate(candidate.candidate_id, strategy=None)
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestServiceManual:
    def test_build_manual_instruction(self) -> None:
        service = _service()
        strategy = service.strategy("strategy.unknown_behavior")
        assert strategy is not None
        instruction = service.build_manual_instruction(
            strategy,
            proof_id="p9",
            hypothesis=_hypothesis(),
            objective="confirm the novel behavior manually",
        )
        assert instruction.strategy_id == strategy.strategy_id
        assert instruction.objective == "confirm the novel behavior manually"
        persisted = service.manual_instructions(proof_id="p9")
        assert len(persisted) == 1
        assert persisted[0].completion_criteria == strategy.confirmation_conditions


class TestServiceReport:
    def test_build_report(self) -> None:
        service = _service()
        service.select_strategy(ValidationClass.SQL_INJECTION, hypothesis=_hypothesis())
        report = service.build_report(mission_id="m1")
        assert report["strategy_count"] >= 1
        assert report["evidence_matrix"]["version"] == "1.0.0"
        assert report["registry_version"] == "1.0.0"


class TestServiceMatrix:
    def test_evidence_matrix_versioned(self) -> None:
        service = _service()
        matrix = service.evidence_matrix()
        assert matrix.version() == "1.0.0"
        assert matrix.required_for(ValidationClass.SQL_INJECTION) == ("behavioral_differential",)
