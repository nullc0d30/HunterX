# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden tests for the Vulnerability Proof Strategy Library & Proof Validator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunterx.domain.vulnerability_proof.enums import ReplayResult
from hunterx.domain.vulnerability_proof.library import default_strategy_library
from hunterx.domain.vulnerability_proof.models import ProofReplay
from hunterx.domain.vulnerability_proof.strategy import ProofQualityLevel, ProofStrategy, ProofVerdict
from hunterx.domain.vulnerability_proof.validator import ProofValidationContext, ProofValidator
from hunterx.domain.vulnerability_validation.enums import (
    EvidenceComparison,
    EvidenceKind,
    SafetyClass,
    ValidationClass,
)
from hunterx.domain.vulnerability_validation.models import ValidationEvidence, ValidationObservation

_SCENARIOS_PATH = Path(__file__).parent / "proof_strategy" / "scenarios.json"


def _load_scenarios() -> list[dict]:
    with _SCENARIOS_PATH.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload["scenarios"]


def _strategy_for(scenario: dict) -> ProofStrategy:
    strategy_id = scenario["strategy_id"]
    for strategy in default_strategy_library():
        if strategy.strategy_id == strategy_id:
            return strategy
    raise KeyError(f"no built-in strategy {strategy_id}")


def _evidence_for(entries: list[dict]) -> tuple[ValidationEvidence, ...]:
    evidence: list[ValidationEvidence] = []
    for entry in entries:
        try:
            kind = EvidenceKind(entry["kind"])
        except ValueError:
            kind = EvidenceKind.EXTERNAL
        comparison = EvidenceComparison(entry.get("comparison", "no_comparison"))
        evidence.append(
            ValidationEvidence(
                evidence_id=f"ev-{len(evidence)}",
                observation=ValidationObservation(
                    kind=kind, value=entry.get("value", ""), source="golden"
                ),
                expected_behavior="expected",
                observed_behavior=entry.get("value", ""),
                comparison=comparison,
            )
        )
    return tuple(evidence)


def _replays_for(entries: list[dict]) -> tuple[ProofReplay, ...]:
    replays: list[ProofReplay] = []
    for index, entry in enumerate(entries):
        try:
            result = ReplayResult(entry.get("result", "not_run"))
        except ValueError:
            result = ReplayResult.NOT_RUN
        replays.append(
            ProofReplay(
                replay_id=f"replay-{index}",
                proof_id="golden-proof",
                poc_id="golden-poc",
                result=result,
                target_state=entry.get("target_state", ""),
            )
        )
    return tuple(replays)


def _context_for(scenario: dict) -> ProofValidationContext:
    strategy = _strategy_for(scenario)
    safety = SafetyClass(scenario.get("safety_class", "benign_marker"))
    try:
        cls = ValidationClass(scenario["vulnerability_class"])
    except ValueError:
        cls = ValidationClass.UNKNOWN_BEHAVIOR
    expected_observations = tuple(scenario.get("expected_observations", [])) or strategy.expected_observations
    return ProofValidationContext(
        proof_id=f"proof-{scenario['id']}",
        vulnerability_class=cls,
        evidence=_evidence_for(scenario.get("evidence", [])),
        replays=_replays_for(scenario.get("replays", [])),
        target_state=scenario.get("target_state", ""),
        generated_target_state=scenario.get("generated_target_state", ""),
        scope=scenario.get("scope", {}),
        safety_class=safety,
        expected_observations=expected_observations,
        impact_evidence=tuple(scenario.get("impact_evidence", [])),
        independent_verified=bool(scenario.get("independent_verified", False)),
    )


@pytest.mark.parametrize("scenario", _load_scenarios(), ids=lambda item: item["id"])
def test_golden_scenario(scenario: dict) -> None:
    validator = ProofValidator()
    strategy = _strategy_for(scenario)
    result = validator.validate(strategy, _context_for(scenario))
    expected_verdict = ProofVerdict(scenario["expected_verdict"])
    expected_quality = ProofQualityLevel(scenario["expected_quality"])
    assert result.verdict == expected_verdict, f"reasoning: {result.reasoning}"
    assert result.proof_quality_level == expected_quality, (
        f"expected {expected_quality.value} got {result.proof_quality_level.value}; "
        f"reasoning: {result.reasoning}"
    )


def test_golden_scenario_set_covers_required_classes() -> None:
    scenarios = _load_scenarios()
    classes = {item["vulnerability_class"] for item in scenarios}
    for required in (
        "sql_injection",
        "xss",
        "ssrf",
        "path_traversal",
        "broken_access_control",
        "api_authorization",
        "command_injection",
        "authentication",
        "cors",
        "csrf",
        "open_redirect",
        "dependency_vulnerability",
        "cloud_exposure",
        "unknown_behavior",
    ):
        assert required in classes, f"missing golden scenario for {required}"
