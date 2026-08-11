# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the safe vulnerability discovery & validation capability.

End-to-end scenario: through the assembled platform, create a hypothesis, plan
its safe validation, run the full OBSERVE → HYPOTHESIZE → PLAN → SCOPE CHECK →
SAFETY CHECK → SELECT TOOL → SAFE PROBE → NORMALIZE → COLLECT EVIDENCE → VERIFY
→ PERSIST → GRAPH → REPORT → DIFF loop, and verify deterministic verdicts
against the golden datasets, TIDB persistence, knowledge-graph integration,
event emission, temporal differentials and reporting.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.entities.tidb.validation import (
    ValidationEvidence as TidbValidationEvidence,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationExecution as TidbValidationExecution,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationPlan as TidbValidationPlan,
)
from hunterx.domain.entities.tidb.validation import (
    ValidationVerdict as TidbValidationVerdict,
)
from hunterx.domain.entities.tidb.validation import (
    VulnerabilityHypothesis as TidbVulnerabilityHypothesis,
)
from hunterx.domain.vulnerability_validation.enums import (
    ValidationClass,
    VerdictResult,
)
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import ValidationScopePolicy
from hunterx.platform.assembler import build_platform

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "validation"


def _load_scenarios() -> list[dict]:
    with (GOLDEN / "scenarios.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)["scenarios"]


SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()


class TestValidationAcceptance:
    def test_golden_scenarios_produce_expected_verdicts(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        for scenario in _load_scenarios():
            class_name = ValidationClass(scenario["class"])
            hypothesis = service.create_hypothesis(
                mission_id=f"acceptance-{scenario['name']}",
                target_id="app.example.com",
                asset_id="app.example.com",
                vulnerability_id=f"CVE-{scenario['name']}",
                class_name=class_name,
                expected_behavior=scenario["expected_behavior"],
                confidence=scenario["confidence"],
            )
            plan = service.plan_validation(hypothesis)
            result = service.run_validation(
                hypothesis,
                plan=plan,
                scope_policy=SCOPE,
                safety_policy=SAFETY,
                probe_parameters={"observations": scenario["tool_output"]["observations"]},
            )
            assert result.verdict is not None
            expected = VerdictResult(scenario["expected_verdict"])
            assert (
                result.verdict.result == expected
            ), f"{scenario['name']}: expected {expected.value}, got {result.verdict.result.value}"

    def test_detection_never_equals_validation(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        # An observed match is a hypothesis, never an immediate confirmed verdict.
        hypothesis = service.create_hypothesis(
            mission_id="acceptance-state",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.9,
        )
        assert hypothesis.state.value == "hypothesis"

    def test_persist_and_replay(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        hypothesis = service.create_hypothesis(
            mission_id="acceptance-persist",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        plan = service.plan_validation(hypothesis)
        service.run_validation(
            hypothesis, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [
                {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]},
        )
        stores = platform.tidb
        assert stores.repository_for(TidbVulnerabilityHypothesis).count() >= 1
        assert stores.repository_for(TidbValidationPlan).count() >= 1
        assert stores.repository_for(TidbValidationExecution).count() >= 1
        assert stores.repository_for(TidbValidationEvidence).count() >= 1
        assert stores.repository_for(TidbValidationVerdict).count() >= 1

    def test_temporal_differential_detects_fixed_vulnerability(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service
        # Mission A: vulnerable version confirmed.
        first = service.create_hypothesis(
            mission_id="acceptance-diff-1",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        plan1 = service.plan_validation(first)
        service.run_validation(
            first, plan=plan1, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [
                {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]},
        )
        from hunterx.domain.vulnerability_validation.history import HypothesisSnapshot

        previous = [HypothesisSnapshot.from_hypothesis(first)]

        # Mission B: fixed version → differential FIXED.
        second = service.create_hypothesis(
            mission_id="acceptance-diff-2",
            target_id="app.example.com",
            asset_id="app.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
            confidence=0.8,
        )
        plan2 = service.plan_validation(second)
        result = service.run_validation(
            second, plan=plan2, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [
                {"kind": "version", "value": "1.25.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]},
            previous=previous, previous_mission_id="acceptance-diff-1",
        )
        assert result.verdict.result == VerdictResult.FALSE_POSITIVE
        from hunterx.domain.vulnerability_validation.enums import DifferentialChange

        assert any(DifferentialChange.FIXED in diff.changes for diff in result.differentials)
        report = result.report
        assert report is not None
        assert report["risk_changes"]
        assert report["reproducibility"]["reproducible"] is True

    def test_scope_and_safety_blocked_are_distinct(self) -> None:
        platform = build_platform()
        service = platform.vulnerability_validation_service

        out_of_scope = service.create_hypothesis(
            mission_id="acceptance-scope",
            target_id="other.example.com",
            asset_id="other.example.com",
            vulnerability_id="CVE-2024-1234",
            class_name=ValidationClass.KNOWN_VULNERABLE_SOFTWARE,
        )
        plan = service.plan_validation(out_of_scope)
        result = service.run_validation(
            out_of_scope, plan=plan, scope_policy=SCOPE, safety_policy=SAFETY,
            probe_parameters={"observations": [
                {"kind": "version", "value": "1.24.0", "confidence": 1.0, "metadata": {"expected": "1.24.0"}}
            ]},
        )
        assert result.verdict.result == VerdictResult.SCOPE_BLOCKED
        assert result.verdict.result != VerdictResult.SAFETY_BLOCKED
        assert result.verdict.result != VerdictResult.INCONCLUSIVE
