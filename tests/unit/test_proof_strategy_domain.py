# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the proof strategy domain models and evidence matrix."""

from __future__ import annotations

from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.matrix import (
    EvidenceMatrix,
    matrix_from_strategies,
    matrix_row_from_strategy,
)
from hunterx.domain.vulnerability_proof.strategy import (
    EvidenceRule,
    ProofExecutability,
    ProofStrategy,
    ProofVerdict,
    StrategyCandidate,
    StrategyCandidateStatus,
    TargetStateRelation,
    ToolCapability,
    evidence_rule_from_dict,
    strategy_candidate_from_dict,
    strategy_from_dict,
)
from hunterx.domain.vulnerability_validation.enums import SafetyClass, ValidationClass


class TestProofStrategyModel:
    def test_defaults_are_safe(self) -> None:
        strategy = ProofStrategy(strategy_id="strategy.x", vulnerability_class=ValidationClass.XSS)
        assert strategy.safety_class in (SafetyClass.PASSIVE, SafetyClass.READ_ONLY, SafetyClass.BENIGN_MARKER, SafetyClass.CONTROLLED)
        assert strategy.safety_class != SafetyClass.DESTRUCTIVE
        assert strategy.execution == ProofExecutability.EXECUTABLE
        assert strategy.status.value == "active"
        assert strategy.replay_requirements["minimum"] >= 1

    def test_key_identity(self) -> None:
        strategy = ProofStrategy(strategy_id="strategy.x", strategy_version="1.1.0")
        assert strategy.key() == "strategy.x@1.1.0"

    def test_to_dict_round_trip(self) -> None:
        original = ProofStrategy(
            strategy_id="strategy.x",
            strategy_version="1.0.0",
            vulnerability_class=ValidationClass.SQL_INJECTION,
            security_property="query semantics attacker-influenced",
            required_evidence=("behavioral_differential",),
            evidence_rules=EvidenceRule(
                minimum_required=("behavioral_differential",),
                contradictory=("baseline-identical",),
            ),
            required_capabilities=(ToolCapability.HTTP_REQUEST.value,),
        )
        rebuilt = strategy_from_dict(original.to_dict())
        assert rebuilt == original
        assert rebuilt.evidence_rules.minimum_required == ("behavioral_differential",)
        assert rebuilt.evidence_rules.contradictory == ("baseline-identical",)

    def test_evidence_rule_from_dict(self) -> None:
        rule = evidence_rule_from_dict(
            {"minimum_required": ["a"], "strong": ["b"], "contradictory": ["c"], "confirmation_rule": "x"}
        )
        assert rule.minimum_required == ("a",)
        assert rule.strong == ("b",)
        assert rule.contradictory == ("c",)
        assert rule.confirmation_rule == "x"

    def test_forbidden_actions_cover_universal_set(self) -> None:
        for strategy in default_strategy_library():
            assert "data-destruction" in strategy.forbidden_actions
            assert "reverse-shell" in strategy.forbidden_actions
            assert "credential-dumping" in strategy.forbidden_actions


class TestStrategyCandidate:
    def test_defaults(self) -> None:
        candidate = StrategyCandidate(observed_behavior="unexpected 500 on marker")
        assert candidate.status == StrategyCandidateStatus.PROPOSED
        assert candidate.review_required is True
        assert candidate.vulnerability_class == ValidationClass.UNKNOWN_BEHAVIOR

    def test_round_trip(self) -> None:
        candidate = StrategyCandidate(
            observed_behavior="marker echoed",
            reasoning="novel reflection",
            status=StrategyCandidateStatus.UNDER_REVIEW,
        )
        rebuilt = strategy_candidate_from_dict(candidate.to_dict())
        assert rebuilt == candidate


class TestEvidenceMatrix:
    def test_matrix_from_library_is_versioned(self) -> None:
        matrix = matrix_from_strategies(default_strategy_library())
        assert isinstance(matrix, EvidenceMatrix)
        assert matrix.version() == "1.0.0"
        assert matrix.supports(ValidationClass.SQL_INJECTION)
        assert matrix.required_for(ValidationClass.SQL_INJECTION) == ("behavioral_differential",)
        assert matrix.replay_for(ValidationClass.SQL_INJECTION)["minimum"] >= 1

    def test_matrix_round_trip(self) -> None:
        matrix = matrix_from_strategies(default_strategy_library())
        rebuilt = EvidenceMatrix.from_dict(matrix.to_dict())
        assert rebuilt.version() == matrix.version()
        assert rebuilt.required_for(ValidationClass.XSS) == matrix.required_for(ValidationClass.XSS)

    def test_matrix_row_disqualifying_evidence(self) -> None:
        strategy = next(
            item for item in default_strategy_library()
            if item.strategy_id == "strategy.sql_injection"
        )
        row = matrix_row_from_strategy(strategy)
        assert "baseline-identical" in row.disqualifying_evidence

    def test_unknown_class_returns_empty(self) -> None:
        matrix = matrix_from_strategies([])
        assert matrix.required_for(ValidationClass.XSS) == ()
        assert matrix.supports(ValidationClass.XSS) is False


class TestProofVerdictEnum:
    def test_all_verdicts_exist(self) -> None:
        expected = {
            "valid", "invalid", "incomplete", "inconclusive", "blocked",
            "unsafe", "out_of_scope", "contradicted", "insufficient_evidence",
        }
        assert {verdict.value for verdict in ProofVerdict} == expected

    def test_target_state_relations(self) -> None:
        assert TargetStateRelation.STABLE.value == "stable"
        assert TargetStateRelation.CHANGED.value == "changed"
