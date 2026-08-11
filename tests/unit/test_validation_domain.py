# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the safe validation domain contracts and state machine."""

from __future__ import annotations

import pytest

from hunterx.domain.vulnerability_validation.enums import (
    SafetyClass,
    ValidationClass,
    ValidationStrategy,
    VerdictResult,
    VulnerabilityState,
)
from hunterx.domain.vulnerability_validation.models import (
    ValidationEvidence,
    ValidationObservation,
    ValidationPlan,
    ValidationRule,
    ValidationStep,
    ValidationVerdict,
    VulnerabilityHypothesis,
    hypothesis_key,
)
from hunterx.domain.vulnerability_validation.state import VulnerabilityStateMachine


class TestVulnerabilityHypothesis:
    def test_hypothesis_key_is_stable(self) -> None:
        assert hypothesis_key(asset="a", vulnerability_id="CVE-1", technology_id="nginx") == (
            "hypothesis:a|CVE-1|nginx"
        )
        first = hypothesis_key(asset="a", vulnerability_id="CVE-1", technology_id="nginx")
        second = hypothesis_key(asset="a", vulnerability_id="CVE-1", technology_id="nginx")
        assert first == second

    def test_to_dict_round_trip(self) -> None:
        hypothesis = VulnerabilityHypothesis(
            mission_id="m1",
            target_id="t1",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            technology_id="nginx",
            type=ValidationClass.SQL_INJECTION,
            description="sqli hypothesis",
            confidence=0.8,
            safety_class=SafetyClass.BENIGN_MARKER,
            validation_strategy=ValidationStrategy.INPUT_VALIDATION,
            state=VulnerabilityState.HYPOTHESIS,
        )
        restored = VulnerabilityHypothesis.from_dict(hypothesis.to_dict())
        assert restored.hypothesis_id == hypothesis.hypothesis_id
        assert restored.type == ValidationClass.SQL_INJECTION
        assert restored.safety_class == SafetyClass.BENIGN_MARKER
        assert restored.validation_strategy == ValidationStrategy.INPUT_VALIDATION
        assert restored.state == VulnerabilityState.HYPOTHESIS
        assert restored.key() == hypothesis.key()

    def test_hypothesis_requires_vulnerability_or_description(self) -> None:
        hypothesis = VulnerabilityHypothesis(description="adhoc observation")
        assert hypothesis.vulnerability_id == ""
        assert hypothesis.description == "adhoc observation"


class TestStateMachine:
    @pytest.mark.parametrize(
        ("current", "target", "expected"),
        [
            (VulnerabilityState.SUSPECTED, VulnerabilityState.HYPOTHESIS, True),
            (VulnerabilityState.HYPOTHESIS, VulnerabilityState.VALIDATION_PLANNED, True),
            (VulnerabilityState.VALIDATION_PLANNED, VulnerabilityState.VALIDATION_RUNNING, True),
            (VulnerabilityState.VALIDATION_RUNNING, VulnerabilityState.CONFIRMED, True),
            (VulnerabilityState.VALIDATION_RUNNING, VulnerabilityState.FALSE_POSITIVE, True),
            (VulnerabilityState.VALIDATION_RUNNING, VulnerabilityState.INCONCLUSIVE, True),
            (VulnerabilityState.VALIDATION_RUNNING, VulnerabilityState.VALIDATED, True),
            (VulnerabilityState.CONFIRMED, VulnerabilityState.RESOLVED, True),
            (VulnerabilityState.RESOLVED, VulnerabilityState.REOPENED, True),
            (VulnerabilityState.REOPENED, VulnerabilityState.VALIDATION_RUNNING, True),
            (VulnerabilityState.INCONCLUSIVE, VulnerabilityState.VALIDATION_RUNNING, True),
            (VulnerabilityState.UNKNOWN, VulnerabilityState.CONFIRMED, False),
            (VulnerabilityState.CONFIRMED, VulnerabilityState.FALSE_POSITIVE, False),
            (VulnerabilityState.FALSE_POSITIVE, VulnerabilityState.CONFIRMED, False),
            (VulnerabilityState.RESOLVED, VulnerabilityState.CONFIRMED, False),
        ],
    )
    def test_transitions(self, current: VulnerabilityState, target: VulnerabilityState, expected: bool) -> None:
        machine = VulnerabilityStateMachine()
        assert machine.can(current, target) is expected

    def test_state_for_verdict_mapping(self) -> None:
        machine = VulnerabilityStateMachine()
        assert machine.state_for_verdict(VerdictResult.CONFIRMED) == VulnerabilityState.CONFIRMED
        assert machine.state_for_verdict(VerdictResult.FALSE_POSITIVE) == VulnerabilityState.FALSE_POSITIVE
        assert machine.state_for_verdict(VerdictResult.INCONCLUSIVE) == VulnerabilityState.INCONCLUSIVE
        assert machine.state_for_verdict(VerdictResult.VALIDATED) == VulnerabilityState.VALIDATED
        assert machine.state_for_verdict(VerdictResult.SCOPE_BLOCKED) == VulnerabilityState.SUSPECTED

    def test_detection_never_equals_validation(self) -> None:
        machine = VulnerabilityStateMachine()
        # A raw observation may become suspected/hypothesis but never validated/confirmed.
        assert machine.can(VulnerabilityState.OBSERVED, VulnerabilityState.VALIDATED) is False
        assert machine.can(VulnerabilityState.SUSPECTED, VulnerabilityState.CONFIRMED) is False


class TestModels:
    def test_validation_plan_serialization(self) -> None:
        step = ValidationStep(step_id="s1", plan_id="p1", order=0, action="version-verify")
        plan = ValidationPlan(
            plan_id="p1",
            hypothesis_id="h1",
            mission_id="m1",
            steps=(step,),
        )
        data = plan.to_dict()
        assert data["plan_id"] == "p1"
        assert len(data["steps"]) == 1

    def test_evidence_requires_source_value(self) -> None:
        observation = ValidationObservation(kind="version", value="1.24.0")
        evidence = ValidationEvidence(
            evidence_id="e1",
            validation_id="v1",
            hypothesis_id="h1",
            observation=observation,
        )
        assert evidence.observation is not None
        assert evidence.observation.value == "1.24.0"

    def test_verdict_carries_reproducibility_metadata(self) -> None:
        verdict = ValidationVerdict(
            validation_id="v1",
            hypothesis_id="h1",
            result=VerdictResult.CONFIRMED,
            rule_ids=("validation.known-vulnerable-software",),
            evidence_ids=("e1",),
            confidence=0.9,
        )
        assert verdict.analysis_version == "1.0.0"
        assert verdict.rule_ids == ("validation.known-vulnerable-software",)

    def test_rule_serialization(self) -> None:
        rule = ValidationRule(rule_id="r1", vulnerability_class=ValidationClass.CORS)
        data = rule.to_dict()
        assert data["vulnerability_class"] == "cors"
        assert "forbidden_actions" in data
