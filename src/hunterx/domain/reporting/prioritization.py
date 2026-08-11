# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding prioritization engine.

Priority is not severity: it combines severity, confidence, finding quality,
asset criticality, exploitability, proof strength, attack-path position,
business impact, exposure, remediation difficulty and root-cause recurrence
into a P0-P4 ranking.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.reporting.enums import PriorityLevel
from hunterx.domain.reporting.models import PriorityAssessment, PriorityFactor

#: Weighted priority factors (weights sum to 1).
_FACTORS: tuple[tuple[str, float], ...] = (
    ("severity", 0.18),
    ("confidence", 0.12),
    ("quality", 0.08),
    ("asset_criticality", 0.12),
    ("exploitability", 0.12),
    ("proof_strength", 0.10),
    ("attack_path_position", 0.08),
    ("business_impact", 0.08),
    ("exposure", 0.06),
    ("remediation_difficulty", 0.03),
    ("root_cause_recurrence", 0.03),
)


@dataclass(frozen=True, slots=True)
class PriorityInput:
    """Inputs for the finding priority engine.

    Attributes:
        finding_id: owning finding.
        severity_score: severity risk score in ``[0, 10]``.
        severity: severity band.
        confidence: evidence-driven confidence in ``[0, 1]``.
        quality_score: finding quality in ``[0, 1]``.
        asset_criticality_level: numeric asset criticality ``0..3``.
        exploitability_evidence: whether direct exploitability evidence exists.
        proof_validated: whether the proof is validated.
        on_attack_path: whether the finding sits on a validated attack path.
        attack_path_validated: whether the attack path is validated/proved.
        business_impact_score: business impact magnitude in ``[0, 1]``.
        internet_exposed: whether the asset is internet-exposed.
        remediation_difficulty: remediation difficulty in ``[0, 1]`` (higher = harder).
        root_cause_recurring: whether the same root cause affects multiple assets.

    """

    finding_id: str = ""
    severity_score: float = 0.0
    severity: str = "informational"
    confidence: float = 0.0
    quality_score: float = 0.0
    asset_criticality_level: int = 1
    exploitability_evidence: bool = False
    proof_validated: bool = False
    on_attack_path: bool = False
    attack_path_validated: bool = False
    business_impact_score: float = 0.0
    internet_exposed: bool = False
    remediation_difficulty: float = 0.5
    root_cause_recurring: bool = False


class FindingPriorityEngine:
    """Deterministic priority scorer producing a P0-P4 level."""

    def assess(self, inp: PriorityInput) -> PriorityAssessment:
        """Assess the remediation priority of a finding.

        Returns:
            An explainable :class:`PriorityAssessment`.

        """
        factors = [
            PriorityFactor("severity", inp.severity_score / 10.0, _weight("severity"), f"severity {inp.severity}"),
            PriorityFactor("confidence", inp.confidence, _weight("confidence"), f"confidence {inp.confidence:.2f}"),
            PriorityFactor("quality", inp.quality_score, _weight("quality"), f"quality {inp.quality_score:.2f}"),
            PriorityFactor(
                "asset_criticality",
                inp.asset_criticality_level / 3.0,
                _weight("asset_criticality"),
                f"asset criticality {inp.asset_criticality_level}",
            ),
            PriorityFactor(
                "exploitability",
                1.0 if inp.exploitability_evidence else 0.3,
                _weight("exploitability"),
                "exploitability evidence present" if inp.exploitability_evidence else "no exploitability evidence",
            ),
            PriorityFactor(
                "proof_strength",
                1.0 if inp.proof_validated else 0.4,
                _weight("proof_strength"),
                "proof validated" if inp.proof_validated else "proof not validated",
            ),
            PriorityFactor(
                "attack_path_position",
                1.0 if inp.on_attack_path and inp.attack_path_validated else (0.7 if inp.on_attack_path else 0.2),
                _weight("attack_path_position"),
                "on validated attack path" if inp.on_attack_path and inp.attack_path_validated else "not on validated attack path",
            ),
            PriorityFactor(
                "business_impact",
                inp.business_impact_score,
                _weight("business_impact"),
                f"business impact {inp.business_impact_score:.2f}",
            ),
            PriorityFactor(
                "exposure",
                1.0 if inp.internet_exposed else 0.3,
                _weight("exposure"),
                "internet exposed" if inp.internet_exposed else "not internet exposed",
            ),
            PriorityFactor(
                "remediation_difficulty",
                1.0 - inp.remediation_difficulty,
                _weight("remediation_difficulty"),
                f"remediation difficulty {inp.remediation_difficulty:.2f}",
            ),
            PriorityFactor(
                "root_cause_recurrence",
                1.0 if inp.root_cause_recurring else 0.3,
                _weight("root_cause_recurrence"),
                "recurring root cause" if inp.root_cause_recurring else "single root cause",
            ),
        ]
        score = round(sum(item.score * item.weight for item in factors) * 100.0) / 100.0
        priority = _priority_for(score, inp.severity_score, inp.proof_validated)
        rationale = (
            f"priority {priority.value} from composite score {score:.2f}; "
            f"drivers: {', '.join(sorted(item.name for item in factors if item.score >= 0.8))}"
        )
        return PriorityAssessment(
            finding_id=inp.finding_id,
            priority=priority,
            score=score,
            factors=tuple(factors),
            rationale=rationale,
        )


def _weight(name: str) -> float:
    """Return the configured weight for a factor name."""
    for factor, weight in _FACTORS:
        if factor == name:
            return weight
    return 0.0


def _priority_for(score: float, severity_score: float, proof_validated: bool) -> PriorityLevel:
    """Map a composite score to a priority band.

    A ``critical`` severity only lands in P0 when there is evidence and a
    validated proof; the class alone is never enough. Informational findings
    (out of scope or unverified) are always P4.
    """
    if severity_score == 0.0:
        return PriorityLevel.P4
    if score >= 0.8 and severity_score >= 9.0 and proof_validated:
        return PriorityLevel.P0
    if score >= 0.7:
        return PriorityLevel.P1
    if score >= 0.5:
        return PriorityLevel.P2
    if score >= 0.3:
        return PriorityLevel.P3
    return PriorityLevel.P4


__all__ = ["FindingPriorityEngine", "PriorityInput"]
