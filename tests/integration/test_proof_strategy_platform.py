# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the proof strategy platform wiring."""

from __future__ import annotations

from hunterx.domain.events.catalog import build_registry
from hunterx.domain.vulnerability_proof.enums import ReplayResult
from hunterx.domain.vulnerability_proof.models import ProofReplay
from hunterx.domain.vulnerability_proof.strategy import ProofVerdict
from hunterx.domain.vulnerability_proof.validator import ProofValidationContext
from hunterx.domain.vulnerability_validation.enums import (
    EvidenceComparison,
    EvidenceKind,
    ValidationClass,
)
from hunterx.domain.vulnerability_validation.models import (
    ValidationEvidence,
    ValidationObservation,
    VulnerabilityHypothesis,
)
from hunterx.platform.assembler import build_platform


class TestPlatformWiring:
    def test_platform_builds_and_exposes_strategy_service(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_proof_strategy_service
        assert service is not None
        strategies = service.strategies()
        assert strategies
        assert any(item.strategy_id == "strategy.sql_injection" for item in strategies)

    def test_event_catalog_registers_strategy_events(self) -> None:
        registry = build_registry()
        for event_type in (
            "proof.strategy.selected",
            "proof.strategy.blocked",
            "proof.strategy.missing_evidence",
            "proof.validation.started",
            "proof.validation.completed",
            "proof.validation.failed",
            "proof.validation.inconclusive",
            "proof.validation.contradicted",
            "proof.manual_required",
            "proof.strategy.candidate_created",
            "proof.strategy.approved",
            "proof.strategy.rejected",
        ):
            assert registry.has(event_type), event_type

    def test_platform_resolves_strategy_service_from_container(self) -> None:
        platform = build_platform()
        from hunterx.application.vulnerability_proof_strategy import VulnerabilityProofStrategyService

        resolved = platform.resolve(VulnerabilityProofStrategyService)
        assert resolved is platform.vulnerability_proof_strategy_service

    def test_evidence_matrix_via_platform(self) -> None:
        platform = build_platform()
        matrix = platform.vulnerability_proof_strategy_service.evidence_matrix()
        assert matrix.supports(ValidationClass.XSS)
        assert matrix.required_for(ValidationClass.SSRF) == ("controlled_callback",)


class TestEndToEnd:
    def test_select_then_validate_full_flow(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_proof_strategy_service
        hypothesis = VulnerabilityHypothesis(
            mission_id="m1",
            target_id="https://app.example.com",
            asset_id="https://app.example.com/endpoint?id=1",
            type=ValidationClass.SQL_INJECTION,
            hypothesis_id="h1",
        )
        selection = service.select_strategy(
            ValidationClass.SQL_INJECTION,
            hypothesis=hypothesis,
            available_evidence=("behavioral_differential",),
            authorization_level="authorized",
        )
        assert selection.strategy.strategy_id == "strategy.sql_injection"

        evidence = ValidationEvidence(
            evidence_id="ev1",
            observation=ValidationObservation(
                kind=EvidenceKind.BEHAVIORAL_DIFFERENTIAL, value="differential observed", source="proof-replay"
            ),
            expected_behavior="expected",
            observed_behavior="differential observed",
            comparison=EvidenceComparison.MATCH,
        )
        replays = tuple(
            ProofReplay(proof_id="p1", poc_id="poc1", result=ReplayResult.SUCCESS, target_state="s1")
            for _ in range(2)
        )
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=(evidence,),
            replays=replays,
            target_state="s1",
            generated_target_state="s1",
            expected_observations=("differential behavior",),
            impact_evidence=("integrity", "confidentiality"),
            independent_verified=True,
        )
        result = service.validate_proof(selection.strategy, context, mission_id="m1")
        assert result.verdict == ProofVerdict.VALID
        persisted = service.validation_results(proof_id="p1")
        assert persisted and persisted[0].verdict == ProofVerdict.VALID

    def test_strategy_candidate_persisted_through_platform(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_proof_strategy_service
        candidate = service.propose_candidate(
            vulnerability_class=ValidationClass.UNKNOWN_BEHAVIOR,
            observed_behavior="novel marker echo",
            reasoning="needs review",
        )
        fetched = service.get_candidate(candidate.candidate_id)
        assert fetched is not None
        assert fetched.observed_behavior == "novel marker echo"
