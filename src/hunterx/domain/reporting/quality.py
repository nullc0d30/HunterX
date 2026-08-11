# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding quality engine.

Confidence answers "how likely is this finding correct?" while quality
answers "how strong and defensible is this report?". The quality score
evaluates evidence quality, validation quality, proof quality,
reproducibility, impact evidence, scope certainty, asset certainty,
root-cause certainty, freshness, tool reliability, contradiction state and
report completeness.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.reporting.enums import QualityGrade
from hunterx.domain.reporting.models import FindingQuality, QualityFactorScore

#: Weighted quality factors (weights sum to 1).
_FACTORS: tuple[tuple[str, float], ...] = (
    ("evidence_quality", 0.12),
    ("validation_quality", 0.12),
    ("proof_quality", 0.12),
    ("reproducibility", 0.10),
    ("impact_evidence", 0.08),
    ("scope_certainty", 0.08),
    ("asset_certainty", 0.07),
    ("root_cause_certainty", 0.06),
    ("freshness", 0.07),
    ("tool_reliability", 0.06),
    ("contradiction_state", 0.07),
    ("report_completeness", 0.05),
)

_GRADE_THRESHOLDS: tuple[tuple[float, QualityGrade], ...] = (
    (0.9, QualityGrade.A),
    (0.75, QualityGrade.B),
    (0.6, QualityGrade.C),
    (0.4, QualityGrade.D),
)


@dataclass(frozen=True, slots=True)
class QualityInput:
    """Inputs for the finding quality engine.

    Attributes:
        finding_id: owning finding.
        evidence_items: number of evidence fragments.
        evidence_quality_avg: average evidence quality in ``[0, 1]``.
        validated: whether the finding reached VALIDATED.
        proof_validated: whether the proof reached PROOF_VALIDATED.
        replays_successful: number of successful controlled replays.
        replay_attempts: number of replay attempts.
        impact_assessed: whether impact was assessed with positive evidence.
        scope_ok: whether scope is certain.
        asset_identified: whether the affected asset is identified.
        root_cause_known: whether a root cause is correlated.
        fresh: whether the evidence is fresh.
        tool_reliability_avg: average tool reliability in ``[0, 1]``.
        open_conflicts: number of open evidence conflicts.
        report_complete: whether the report-readiness checklist passes.

    """

    finding_id: str = ""
    evidence_items: int = 0
    evidence_quality_avg: float = 0.0
    validated: bool = False
    proof_validated: bool = False
    replays_successful: int = 0
    replay_attempts: int = 0
    impact_assessed: bool = False
    scope_ok: bool = False
    asset_identified: bool = False
    root_cause_known: bool = False
    fresh: bool = True
    tool_reliability_avg: float = 0.5
    open_conflicts: int = 0
    report_complete: bool = False


class FindingQualityEngine:
    """Deterministic, explainable quality scorer.

    Every factor is scored in ``[0, 1]``, weighted and summed into a single
    quality score that is then mapped to a grade.
    """

    def score(self, inp: QualityInput) -> FindingQuality:
        """Score the quality of a finding report.

        Returns:
            An explainable :class:`FindingQuality` assessment.

        """
        factors: list[QualityFactorScore] = []

        evidence_score = min(1.0, (inp.evidence_items / 3.0) * 0.6 + inp.evidence_quality_avg * 0.4)
        factors.append(
            QualityFactorScore(
                "evidence_quality",
                evidence_score,
                _weight("evidence_quality"),
                f"{inp.evidence_items} evidence fragments with average quality {inp.evidence_quality_avg:.2f}",
            )
        )

        validation_score = 1.0 if inp.validated else (0.4 if inp.evidence_items else 0.0)
        factors.append(
            QualityFactorScore(
                "validation_quality",
                validation_score,
                _weight("validation_quality"),
                "finding validated" if inp.validated else "finding not validated",
            )
        )

        proof_score = 1.0 if inp.proof_validated else 0.5 if inp.replays_successful else 0.0
        factors.append(
            QualityFactorScore(
                "proof_quality",
                proof_score,
                _weight("proof_quality"),
                "proof validated" if inp.proof_validated else "no validated proof",
            )
        )

        reproducibility = (
            inp.replays_successful / inp.replay_attempts if inp.replay_attempts else 0.0
        )
        factors.append(
            QualityFactorScore(
                "reproducibility",
                reproducibility,
                _weight("reproducibility"),
                f"{inp.replays_successful}/{inp.replay_attempts} replays confirmed",
            )
        )

        factors.append(
            QualityFactorScore(
                "impact_evidence",
                1.0 if inp.impact_assessed else 0.0,
                _weight("impact_evidence"),
                "impact assessed with positive evidence" if inp.impact_assessed else "no impact evidence",
            )
        )
        factors.append(
            QualityFactorScore(
                "scope_certainty",
                1.0 if inp.scope_ok else 0.2,
                _weight("scope_certainty"),
                "scope certain" if inp.scope_ok else "scope uncertain",
            )
        )
        factors.append(
            QualityFactorScore(
                "asset_certainty",
                1.0 if inp.asset_identified else 0.2,
                _weight("asset_certainty"),
                "asset identified" if inp.asset_identified else "asset not identified",
            )
        )
        factors.append(
            QualityFactorScore(
                "root_cause_certainty",
                1.0 if inp.root_cause_known else 0.3,
                _weight("root_cause_certainty"),
                "root cause correlated" if inp.root_cause_known else "root cause unknown",
            )
        )
        factors.append(
            QualityFactorScore(
                "freshness",
                1.0 if inp.fresh else 0.4,
                _weight("freshness"),
                "evidence fresh" if inp.fresh else "evidence stale",
            )
        )
        factors.append(
            QualityFactorScore(
                "tool_reliability",
                inp.tool_reliability_avg,
                _weight("tool_reliability"),
                f"average tool reliability {inp.tool_reliability_avg:.2f}",
            )
        )
        contradiction_score = 1.0 if inp.open_conflicts == 0 else 0.2
        factors.append(
            QualityFactorScore(
                "contradiction_state",
                contradiction_score,
                _weight("contradiction_state"),
                "no open conflicts" if inp.open_conflicts == 0 else f"{inp.open_conflicts} open conflicts",
            )
        )
        factors.append(
            QualityFactorScore(
                "report_completeness",
                1.0 if inp.report_complete else 0.5,
                _weight("report_completeness"),
                "report checklist complete" if inp.report_complete else "report checklist incomplete",
            )
        )

        quality_score = round(sum(item.score * item.weight for item in factors) * 100.0) / 100.0
        grade = _grade(quality_score)
        explanation = (
            f"quality {quality_score:.2f} ({grade.value}) from {len(factors)} weighted factors; "
            f"strongest: proof/validation evidence, weakest: {_weakest(factors)}"
        )
        return FindingQuality(
            finding_id=inp.finding_id,
            quality_score=quality_score,
            quality_grade=grade,
            quality_explanation=explanation,
            factors=tuple(factors),
        )


def _weight(name: str) -> float:
    """Return the configured weight for a factor name."""
    for factor, weight in _FACTORS:
        if factor == name:
            return weight
    return 0.0


def _grade(score: float) -> QualityGrade:
    """Map a quality score to a grade band."""
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return QualityGrade.F


def _weakest(factors: list[QualityFactorScore]) -> str:
    """Return the name of the lowest-scoring factor."""
    if not factors:
        return "none"
    return min(factors, key=lambda item: item.score).name


__all__ = ["FindingQualityEngine", "QualityInput"]
