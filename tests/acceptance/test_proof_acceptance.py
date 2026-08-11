# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the vulnerability proof & PoC engine (golden scenarios)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunterx.domain.vulnerability_validation.enums import ValidationClass
from hunterx.domain.vulnerability_validation.models import VulnerabilityHypothesis
from hunterx.domain.vulnerability_validation.safety import SafetyPolicy
from hunterx.domain.vulnerability_validation.scope import ValidationScopePolicy
from hunterx.platform.assembler import build_platform

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "proof"

SCOPE = ValidationScopePolicy(targets=("app.example.com",))
SAFETY = SafetyPolicy()


def _load_scenarios() -> list[dict]:
    with (GOLDEN / "scenarios.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)["scenarios"]


@pytest.fixture(scope="module")
def service():
    platform = build_platform()
    return platform.vulnerability_proof_service


def _hypothesis(scenario: dict) -> VulnerabilityHypothesis:
    target = scenario.get("target", "app.example.com")
    return VulnerabilityHypothesis(
        hypothesis_id=f"acceptance-{scenario['name']}",
        mission_id=f"acceptance-{scenario['name']}",
        target_id=target,
        asset_id=target,
        vulnerability_id=f"CVE-{scenario['name']}",
        type=ValidationClass(scenario["class"]),
        expected_behavior=scenario.get("expected_result", ""),
    )


class TestGoldenProofScenarios:
    def test_golden_scenarios_produce_expected_states(self, service) -> None:
        for scenario in _load_scenarios():
            proof_inputs = scenario.get("dangerous_inputs", scenario.get("inputs", {}))
            result = service.run_proof(
                _hypothesis(scenario),
                scope_policy=SCOPE,
                safety_policy=SAFETY,
                proof_inputs=proof_inputs,
                tool_output=scenario.get("tool_output"),
                replay_outputs=scenario.get("replay_outputs"),
                replay_count=2,
            )
            actual_state = result.proof.proof_status.value
            assert actual_state == scenario["expected_proof_state"], (
                f"{scenario['name']}: expected {scenario['expected_proof_state']} got {actual_state}"
            )
            report_ready = any(t.to_state.value == "report_ready" for t in result.transitions)
            assert report_ready == scenario["expected_report_ready"], (
                f"{scenario['name']}: report_ready mismatch"
            )
            assert result.proof.reproducibility_status.value == scenario["expected_reproducibility"], (
                f"{scenario['name']}: reproducibility mismatch"
            )

    def test_generated_never_validated(self, service) -> None:
        scenario = _load_scenarios()[0]
        hypothesis = service.create_proof(_hypothesis(scenario))
        assert hypothesis.proof_status.value == "candidate"

    def test_raw_tool_output_never_confirms(self, service) -> None:
        """A proof is validated only through replay + evidence evaluation."""
        scenario = _load_scenarios()[0]
        hypothesis = _hypothesis(scenario)
        proof = service.create_proof(hypothesis)
        assert proof.proof_status.value == "candidate"
        assert proof.proof_status.value != "validated"

    def test_scope_and_safety_blocked_are_distinct(self, service) -> None:
        scenarios = {item["name"]: item for item in _load_scenarios()}
        scope_blocked = service.run_proof(
            _hypothesis(scenarios["scope_blocked_proof"]),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs=scenarios["scope_blocked_proof"]["inputs"],
            tool_output=scenarios["scope_blocked_proof"]["tool_output"],
            replay_outputs=scenarios["scope_blocked_proof"]["replay_outputs"],
            replay_count=2,
        )
        safety_blocked = service.run_proof(
            _hypothesis(scenarios["safety_blocked_proof"]),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs=scenarios["safety_blocked_proof"]["dangerous_inputs"],
            tool_output=scenarios["safety_blocked_proof"]["tool_output"],
            replay_outputs=scenarios["safety_blocked_proof"]["replay_outputs"],
            replay_count=2,
        )
        assert scope_blocked.blocked is True
        assert safety_blocked.blocked is True
        assert "scope" in scope_blocked.block_reason
        assert "safety" in safety_blocked.block_reason
        assert scope_blocked.proof.proof_status != safety_blocked.proof.proof_status or scope_blocked.block_reason != safety_blocked.block_reason

    def test_end_to_end_report_ready_package(self, service) -> None:
        scenario = _load_scenarios()[0]
        result = service.run_proof(
            _hypothesis(scenario),
            scope_policy=SCOPE,
            safety_policy=SAFETY,
            proof_inputs=scenario["inputs"],
            tool_output=scenario["tool_output"],
            replay_outputs=scenario["replay_outputs"],
            replay_count=2,
        )
        assert result.proof.proof_status.value == "validated"
        assert result.package is not None
        package = result.package
        assert package.affected_asset == "app.example.com"
        assert package.poc
        assert package.evidence_references
        assert package.replay_instructions
        assert result.report is not None
        assert result.report["summary"]["report_ready"] is True
