# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden scenarios for the Sprint 028 finding validation & proof orchestration.

Each scenario is a controlled fixture describing the initial observation, the
collected evidence, the validation strategy family, the expected evidence
sufficiency, the expected confidence level and the expected final finding
state. The golden test drives the deterministic domain engines and asserts the
outcome — proving that detection never equals a validated finding and that
evidence quality (not tool count) drives the lifecycle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunterx.domain.vulnerability_finding.confidence import ConfidenceEngine, ConfidenceInput
from hunterx.domain.vulnerability_finding.deduplication import (
    DedupCandidate,
    FindingDeduplicationEngine,
)
from hunterx.domain.vulnerability_finding.enums import (
    ConfidenceLevel,
    DuplicateRelation,
    EvidenceRequirementPurpose,
    EvidenceSufficiencyLevel,
    FindingEvidenceKind,
    FindingState,
    FindingVulnerabilityClass,
    PocLifecycleState,
    UnknownBehaviorClassification,
    ValidationStrategyFamily,
)
from hunterx.domain.vulnerability_finding.evidence import EvidenceRequirementEngine
from hunterx.domain.vulnerability_finding.impact import ImpactAssessmentEngine
from hunterx.domain.vulnerability_finding.lifecycle import FindingLifecycleStateMachine
from hunterx.domain.vulnerability_finding.models import EvidenceItem
from hunterx.domain.vulnerability_finding.strategy import StrategyInput, ValidationStrategyEngine
from hunterx.domain.vulnerability_finding.unknown import UnknownBehaviorClassifier

_SCENARIOS_PATH = Path(__file__).parent / "finding" / "scenarios.json"

_QUALITY_ORDER = ("low", "medium", "high", "proof")
_STATE_ORDER = tuple(FindingState)


def _load_scenarios() -> list[dict[str, object]]:
    payload = json.loads(_SCENARIOS_PATH.read_text(encoding="utf-8"))
    return list(payload["scenarios"])  # type: ignore[arg-type]


def _evidence_for(entries: list[dict[str, object]]) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for entry in entries:
        items.append(EvidenceItem.from_dict(dict(entry)))
    return items


def _class_for(scenario: dict[str, object]) -> FindingVulnerabilityClass:
    return FindingVulnerabilityClass(str(scenario["vulnerability_class"]))


def _level_for(scenario: dict[str, object]) -> ConfidenceLevel | None:
    value = scenario.get("expected_confidence_level")
    if not value:
        return None
    return ConfidenceLevel(str(value))


@pytest.mark.parametrize("scenario", _load_scenarios(), ids=lambda item: str(item["id"]))
def test_golden_scenario_deterministic_lifecycle(scenario: dict[str, object]) -> None:
    cls = _class_for(scenario)
    observations = _evidence_for(list(scenario.get("observations") or []))
    evidence = _evidence_for(list(scenario.get("evidence") or []))
    all_evidence = [*observations, *evidence]

    engine = EvidenceRequirementEngine()
    assessment = engine.analyze(cls, all_evidence, finding_id=str(scenario.get("id") or ""))

    expected_sufficiency = scenario.get("expected_sufficiency") or {}
    for purpose, level in expected_sufficiency.items():
        verdict = assessment.sufficiency_for(EvidenceRequirementPurpose(purpose))
        assert verdict is not None, f"no sufficiency verdict for {purpose}"
        assert verdict.level is EvidenceSufficiencyLevel(level), (
            f"{scenario['id']}: {purpose} expected {level}, got {verdict.level.value}"
        )

    lifecycle = FindingLifecycleStateMachine()
    inferred = lifecycle.state_for_evidence(assessment)
    assert inferred is FindingState(str(scenario["expected_state"])), (
        f"{scenario['id']}: expected state {scenario['expected_state']}, got {inferred.value}"
    )

    strategy_family = scenario.get("strategy_family")
    if strategy_family:
        strategy_engine = ValidationStrategyEngine()
        ranked = strategy_engine.rank(
            StrategyInput(
                vulnerability_class=cls,
                existing_evidence=tuple(all_evidence),
                tool_capabilities=(
                    "sql_injection",
                    "xss",
                    "ssrf",
                    "ssti",
                    "lfi",
                    "rce",
                    "idor",
                    "authorization_analysis",
                    "authentication_analysis",
                    "api_security",
                    "graphql_security",
                    "cloud_ownership_mapping",
                    "secret_detection",
                    "vulnerability_scanning",
                    "command_injection",
                    "open_redirect",
                    "csrf",
                    "cors",
                    "host_header_injection",
                    "http_smuggling",
                    "jwt",
                ),
            )
        )
        assert ranked, f"{scenario['id']}: no strategies ranked"
        assert ranked[0].family is ValidationStrategyFamily(strategy_family), (
            f"{scenario['id']}: expected top family {strategy_family}, got {ranked[0].family.value}"
        )

    confidence = ConfidenceEngine().calculate(
        ConfidenceInput(
            finding_id=str(scenario.get("id") or ""),
            finding_state=inferred,
            evidence=tuple(all_evidence),
            impact=ImpactAssessmentEngine().assess(cls, all_evidence),
            poc_state=PocLifecycleState.PROOF_VALIDATED if any(
                item.kind in (FindingEvidenceKind.REPLAY, FindingEvidenceKind.CONTROLLED_PROOF)
                for item in all_evidence
            ) else PocLifecycleState.GENERATED,
            replay_successes=1 if any(item.kind is FindingEvidenceKind.REPLAY for item in all_evidence) else 0,
            replay_attempts=1 if any(item.kind is FindingEvidenceKind.REPLAY for item in all_evidence) else 0,
            open_conflicts=1 if assessment.contradictory else 0,
            freshness_ratio=1.0,
        )
    )
    expected_level = _level_for(scenario)
    if expected_level is not None:
        assert confidence.level is expected_level, (
            f"{scenario['id']}: expected confidence level {expected_level.value}, got {confidence.level.value}"
        )


@pytest.mark.parametrize("scenario", _load_scenarios(), ids=lambda item: str(item["id"]))
def test_golden_scenario_conflict_duplicate_unknown(scenario: dict[str, object]) -> None:
    cls = _class_for(scenario)
    observations = _evidence_for(list(scenario.get("observations") or []))
    evidence = _evidence_for(list(scenario.get("evidence") or []))
    all_evidence = [*observations, *evidence]
    scenario_id = str(scenario.get("id") or "")

    duplicate_relation = scenario.get("expected_duplicate_relation")
    if duplicate_relation:
        dedup = FindingDeduplicationEngine()
        candidate = DedupCandidate(
            finding_id=f"{scenario_id}-b",
            target="https://example.com",
            asset="asset-1",
            vulnerability_class=cls,
            evidence=tuple(all_evidence),
        )
        existing = DedupCandidate(
            finding_id=f"{scenario_id}-a",
            target="https://example.com",
            asset="asset-1",
            vulnerability_class=cls,
            evidence=tuple(all_evidence),
        )
        decision = dedup.correlate(candidate, existing)
        assert decision.relation is DuplicateRelation(duplicate_relation), (
            f"{scenario_id}: expected duplicate relation {duplicate_relation}, got {decision.relation.value}"
        )

    classification = scenario.get("expected_classification")
    if classification:
        classifier = UnknownBehaviorClassifier()
        profile = classifier.characterize(
            findings=(scenario_id,),
            observations=[item.to_dict() for item in observations],
            evidence=all_evidence,
            reproducible=True,
        )
        assert profile.classification is UnknownBehaviorClassification(classification), (
            f"{scenario_id}: expected classification {classification}, got {profile.classification.value}"
        )

    rejection_reason = scenario.get("rejection_reason")
    if rejection_reason:
        from hunterx.domain.vulnerability_finding.enums import RejectionReason

        assert RejectionReason(rejection_reason).value == rejection_reason


def test_required_vulnerability_classes_covered() -> None:
    """Every required Sprint 028 class must appear in the golden dataset."""
    required = {
        "sql_injection",
        "xss",
        "ssrf",
        "ssti",
        "lfi",
        "rce",
        "idor",
        "broken_access_control",
        "graphql_authorization",
        "cloud_exposure",
        "secret_exposure",
        "known_cve",
        "unknown_behavior",
        "business_logic",
    }
    present = {str(item["vulnerability_class"]) for item in _load_scenarios()}
    missing = required - present
    assert not missing, f"golden dataset missing classes: {sorted(missing)}"


def test_evidence_sufficiency_is_not_tool_count() -> None:
    """Reflection alone must be insufficient for SQL injection validation."""
    engine = EvidenceRequirementEngine()
    reflection = [EvidenceItem(kind=FindingEvidenceKind.REFLECTION, value="reflected", quality="high")]
    assessment = engine.analyze(FindingVulnerabilityClass.SQL_INJECTION, reflection)
    verdict = assessment.sufficiency_for(EvidenceRequirementPurpose.VALIDATION)
    assert verdict is not None
    assert verdict.level is EvidenceSufficiencyLevel.INSUFFICIENT
