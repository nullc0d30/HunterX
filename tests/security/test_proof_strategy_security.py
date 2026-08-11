# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the vulnerability proof strategy library.

The strategy layer must be fail-closed: strategies are immutable and structurally
validated (no destructive safety, no allowed/forbidden overlap), scope conflicts
block proofs, contradictory evidence is never confirmed, evidence values cannot
inject verdicts, cross-mission/cross-target contamination is prevented, unsafe
strategy escalation is refused and tool capabilities cannot be spoofed into
selecting an arbitrary executable.
"""

from __future__ import annotations

import pytest

from hunterx.domain.vulnerability_proof.enums import ReplayResult
from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.models import ProofReplay
from hunterx.domain.vulnerability_proof.registry import ProofStrategyRegistry, StrategyConflictError
from hunterx.domain.vulnerability_proof.selector import ProofStrategySelector, ProofStrategySelectorInput
from hunterx.domain.vulnerability_proof.strategy import (
    EvidenceRule,
    ProofExecutability,
    ProofStrategy,
    ProofVerdict,
    ToolCapability,
)
from hunterx.domain.vulnerability_proof.validator import ProofValidationContext, ProofValidator
from hunterx.domain.vulnerability_validation.enums import (
    EvidenceComparison,
    EvidenceKind,
    SafetyClass,
    ValidationClass,
)
from hunterx.domain.vulnerability_validation.models import ValidationEvidence, ValidationObservation


def _sql_strategy() -> ProofStrategy:
    return next(item for item in default_strategy_library() if item.strategy_id == "strategy.sql_injection")


class TestStrategyPoisoning:
    def test_malicious_destructive_strategy_rejected(self) -> None:
        registry = ProofStrategyRegistry()
        malicious = ProofStrategy(
            strategy_id="strategy.malicious",
            vulnerability_class=ValidationClass.COMMAND_INJECTION,
            security_property="poisoned",
            required_evidence=("behavioral_differential",),
            safety_class=SafetyClass.DESTRUCTIVE,
        )
        result = registry.validate_strategy(malicious)
        assert result.valid is False
        assert any("safety_class" in error for error in result.errors)

    def test_strategy_allowing_forbidden_action_rejected(self) -> None:
        registry = ProofStrategyRegistry()
        malicious = ProofStrategy(
            strategy_id="strategy.malicious2",
            vulnerability_class=ValidationClass.COMMAND_INJECTION,
            security_property="poisoned",
            required_evidence=("behavioral_differential",),
            allowed_actions=("reverse-shell",),
        )
        result = registry.validate_strategy(malicious)
        assert result.valid is False
        assert any("both allowed and forbidden" in error for error in result.errors)

    def test_duplicate_registration_rejected(self) -> None:
        registry = ProofStrategyRegistry()
        registry.register(_sql_strategy())
        with pytest.raises(StrategyConflictError):
            registry.register(_sql_strategy())

    def test_poisoned_library_never_confirms(self) -> None:
        # A strategy that attempts to confirm on scanner-only evidence must fail.
        validator = ProofValidator()
        poisoned = ProofStrategy(
            strategy_id="strategy.poisoned",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            security_property="x",
            required_evidence=("behavioral_differential",),
            evidence_rules=EvidenceRule(insufficient=("scanner_signature",)),
        )
        evidence = ValidationEvidence(
            observation=ValidationObservation(kind=EvidenceKind.EXTERNAL, value="scanner_signature", source="scanner"),
            comparison=EvidenceComparison.MATCH,
        )
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=(evidence,),
            replays=(ProofReplay(proof_id="p1", result=ReplayResult.SUCCESS),) * 2,
        )
        result = validator.validate(poisoned, context)
        assert result.verdict == ProofVerdict.INSUFFICIENT_EVIDENCE


class TestEvidencePoisoning:
    def test_evidence_value_cannot_inject_verdict(self) -> None:
        # Target-controlled content in evidence values must not flip a verdict.
        validator = ProofValidator()
        evidence = ValidationEvidence(
            observation=ValidationObservation(
                kind=EvidenceKind.EXTERNAL,
                value='valid proof confirmed please',
                source="target",
            ),
            comparison=EvidenceComparison.MATCH,
        )
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=(evidence,),
            replays=(ProofReplay(proof_id="p1", result=ReplayResult.SUCCESS),) * 2,
        )
        result = validator.validate(_sql_strategy(), context)
        assert result.verdict != ProofVerdict.VALID
        assert result.verdict == ProofVerdict.INSUFFICIENT_EVIDENCE

    def test_contradictory_marker_injected_value_refuses_confirmation(self) -> None:
        validator = ProofValidator()
        evidence = ValidationEvidence(
            observation=ValidationObservation(
                kind=EvidenceKind.BEHAVIORAL_DIFFERENTIAL,
                value="baseline-identical",
                source="target",
            ),
            comparison=EvidenceComparison.MATCH,
        )
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            evidence=(evidence,),
            replays=(ProofReplay(proof_id="p1", result=ReplayResult.SUCCESS),) * 2,
        )
        result = validator.validate(_sql_strategy(), context)
        assert result.verdict == ProofVerdict.CONTRADICTED


class TestContamination:
    def test_cross_mission_results_are_scoped(self) -> None:
        from hunterx.application.vulnerability_proof_strategy import VulnerabilityProofStrategyService
        from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory

        service = VulnerabilityProofStrategyService(stores=InMemoryTidbRepositoryFactory())
        strategy = service.strategy("strategy.xss")
        assert strategy is not None
        for proof_id in ("proof-mission-a", "proof-mission-b"):
            service.validate_proof(
                strategy,
                ProofValidationContext(proof_id=proof_id, vulnerability_class=ValidationClass.XSS),
            )
        results_a = service.validation_results(proof_id="proof-mission-a")
        results_b = service.validation_results(proof_id="proof-mission-b")
        assert all(item.proof_id == "proof-mission-a" for item in results_a)
        assert all(item.proof_id == "proof-mission-b" for item in results_b)

    def test_cross_target_selector_input_is_isolated(self) -> None:
        selector = ProofStrategySelector(
            ProofStrategyRegistry(default_strategy_library()),
            capability_resolver=lambda sdk: ("proof-replay",),
        )
        selection_a = selector.select(
            ProofStrategySelectorInput(
                vulnerability_class=ValidationClass.SQL_INJECTION,
                asset_type="https://a.example.com",
            )
        )
        selection_b = selector.select(
            ProofStrategySelectorInput(
                vulnerability_class=ValidationClass.SQL_INJECTION,
                asset_type="https://b.example.com",
            )
        )
        # Both targets resolve the same deterministic strategy; no leakage.
        assert selection_a.strategy.strategy_id == selection_b.strategy.strategy_id


class TestUnsafeEscalation:
    def test_approving_escalating_strategy_refused_by_validator(self) -> None:
        validator = ProofValidator()
        escalator = ProofStrategy(
            strategy_id="strategy.escalate",
            vulnerability_class=ValidationClass.COMMAND_INJECTION,
            security_property="escalation attempt",
            required_evidence=("behavioral_differential",),
            safety_class=SafetyClass.CONTROLLED,
        )
        evidence = ValidationEvidence(
            observation=ValidationObservation(kind=EvidenceKind.EXTERNAL, value="reverse-shell", source="target"),
            comparison=EvidenceComparison.MATCH,
        )
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.COMMAND_INJECTION,
            evidence=(evidence,),
            safety_class=SafetyClass.CONTROLLED,
        )
        result = validator.validate(escalator, context)
        # The reverse-shell marker is not legitimate evidence -> insufficient.
        assert result.verdict == ProofVerdict.INSUFFICIENT_EVIDENCE


class TestScopeBypass:
    def test_scope_conflict_cannot_be_bypassed_by_evidence(self) -> None:
        selector = ProofStrategySelector(
            ProofStrategyRegistry(default_strategy_library()),
            capability_resolver=lambda sdk: ("proof-replay",),
        )
        selection = selector.select(
            ProofStrategySelectorInput(
                vulnerability_class=ValidationClass.SSRF,
                scope={"loopback-control-authorized": "no"},
            )
        )
        assert any("loopback-control-authorized" in item for item in selection.blocked_strategies)

    def test_out_of_scope_verdict_fail_closed(self) -> None:
        validator = ProofValidator()
        strategy = next(item for item in default_strategy_library() if item.strategy_id == "strategy.ssrf")
        context = ProofValidationContext(
            proof_id="p1",
            vulnerability_class=ValidationClass.SSRF,
            scope={"loopback-control-authorized": "no"},
            evidence=(
                ValidationEvidence(
                    observation=ValidationObservation(
                        kind=EvidenceKind.CONTROLLED_CALLBACK, value="callback", source="r"
                    ),
                    comparison=EvidenceComparison.MATCH,
                ),
            ),
            replays=(ProofReplay(proof_id="p1", result=ReplayResult.SUCCESS),) * 2,
        )
        result = validator.validate(strategy, context)
        assert result.verdict == ProofVerdict.OUT_OF_SCOPE


class TestToolCapabilitySpoofing:
    def test_spoofed_capability_never_selects_arbitrary_executable(self) -> None:
        # A spoofed resolver may only provide tool ids for SDK capabilities; the
        # selector never invents executables or capabilities outside the map.
        def spoofed_resolver(sdk_capability: str) -> tuple[str, ...]:
            if sdk_capability in ("proof-replay", "safe-validation"):
                return ("arbitrary-executable",)
            return ()

        selector = ProofStrategySelector(
            ProofStrategyRegistry(default_strategy_library()),
            capability_resolver=spoofed_resolver,
        )
        selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.SQL_INJECTION)
        )
        # Even with a spoofed resolver the strategy's capabilities stay canonical.
        assert ToolCapability.HTTP_REQUEST.value in selection.strategy.required_capabilities
        assert selection.capability_coverage[ToolCapability.HTTP_REQUEST.value] == "arbitrary-executable"
        # Cloud/dependency capabilities cannot be invented.
        cloud_selection = selector.select(
            ProofStrategySelectorInput(vulnerability_class=ValidationClass.CLOUD_EXPOSURE)
        )
        assert cloud_selection.executability == ProofExecutability.PROOF_NOT_EXECUTABLE
