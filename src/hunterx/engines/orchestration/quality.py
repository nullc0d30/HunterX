# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission quality score.

Produces an explainable mission quality score based on scope completeness,
asset discovery completeness, technology identification, attack-surface
coverage, vulnerability intelligence coverage, validation coverage, evidence
quality, tool reliability, execution completeness and known blind spots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.engines.orchestration.coverage import CoverageReport


@dataclass(frozen=True, slots=True)
class QualityFactor:
    """A single explainable quality factor.

    Attributes:
        name: factor identifier.
        score: factor score in ``[0, 1]``.
        weight: factor weight (weights sum to ``1.0``).
        reason: human-readable explanation.

    """

    name: str
    score: float
    weight: float = 0.1
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "name": self.name,
            "score": round(self.score, 4),
            "weight": self.weight,
            "reason": self.reason,
        }


@dataclass(slots=True)
class MissionQuality:
    """The mission quality score with an explainable factor breakdown.

    Attributes:
        mission_id: owning mission.
        plan_id: the evaluated plan.
        score: overall quality in ``[0, 1]``.
        factors: per-factor breakdown.
        explainability: JSON-safe explanation.

    """

    mission_id: str = ""
    plan_id: str = ""
    score: float = 0.0
    factors: list[QualityFactor] = field(default_factory=list)
    explainability: dict[str, Any] = field(default_factory=dict)

    def factor(self, name: str) -> QualityFactor | None:
        """Return a factor by name, or ``None``."""
        for factor in self.factors:
            if factor.name == name:
                return factor
        return None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "score": round(self.score, 4),
            "factors": [factor.to_dict() for factor in self.factors],
            "explainability": dict(self.explainability),
        }


class MissionQualityScorer:
    """Computes the explainable mission quality score.

    The score is the weighted mean of the factor scores. Each factor is
    clamped to ``[0, 1]`` and carries an explanation so the score is fully
    auditable.
    """

    #: Factor weights (normalized internally).
    _WEIGHTS = {
        "scope_completeness": 0.15,
        "asset_discovery": 0.15,
        "technology_identification": 0.10,
        "attack_surface_coverage": 0.15,
        "vulnerability_intelligence": 0.10,
        "validation_coverage": 0.10,
        "evidence_quality": 0.10,
        "tool_reliability": 0.05,
        "execution_completeness": 0.05,
        "blind_spots": 0.05,
    }

    def score(
        self,
        *,
        mission_id: str,
        plan_id: str,
        coverage: CoverageReport | None = None,
        run: Any | None = None,
        executed_steps: int = 0,
        total_steps: int = 0,
        failed_steps: int = 0,
        tool_successes: int = 0,
        tool_attempts: int = 0,
    ) -> MissionQuality:
        """Compute a mission quality score.

        Args:
            mission_id: scoping mission identifier.
            plan_id: scoping plan identifier.
            coverage: an optional :class:`CoverageReport`.
            run: an optional mission run result (used when coverage is absent).
            executed_steps: steps that completed.
            total_steps: total planned steps.
            failed_steps: failed step count.
            tool_successes: successful tool executions.
            tool_attempts: total tool execution attempts.

        """
        if coverage is None and run is not None:
            from hunterx.engines.orchestration.coverage import CoverageModel

            coverage = CoverageModel().from_run(mission_id=mission_id, plan=run and _plan_of(run), run=run)

        coverage = coverage or CoverageReport(mission_id=mission_id, plan_id=plan_id)
        factors: dict[str, tuple[float, str]] = {}

        # Scope completeness.
        scope_metric = _metric(coverage, "scope")
        factors["scope_completeness"] = (
            scope_metric.fraction,
            f"scope coverage {scope_metric.covered}/{scope_metric.expected}",
        )

        asset_metric = _metric(coverage, "asset")
        factors["asset_discovery"] = (
            asset_metric.fraction,
            f"asset coverage {asset_metric.covered}/{asset_metric.expected}",
        )

        tech_metric = _metric(coverage, "technology")
        factors["technology_identification"] = (
            tech_metric.fraction,
            f"technology coverage {tech_metric.covered}/{tech_metric.expected}",
        )

        surface_metric = _metric(coverage, "endpoint")
        factors["attack_surface_coverage"] = (
            surface_metric.fraction,
            f"endpoint coverage {surface_metric.covered}/{surface_metric.expected}",
        )

        vuln_metric = _metric(coverage, "vulnerability")
        factors["vulnerability_intelligence"] = (
            vuln_metric.fraction,
            f"vulnerability intelligence coverage {vuln_metric.covered}/{vuln_metric.expected}",
        )

        validation_metric = _metric(coverage, "validation")
        factors["validation_coverage"] = (
            validation_metric.fraction,
            f"validation coverage {validation_metric.covered}/{validation_metric.expected}",
        )

        evidence_metric = _metric(coverage, "evidence")
        factors["evidence_quality"] = (
            evidence_metric.fraction,
            f"evidence coverage {evidence_metric.covered}/{evidence_metric.expected}",
        )

        reliability = tool_successes / tool_attempts if tool_attempts else 1.0
        factors["tool_reliability"] = (
            reliability,
            f"tool reliability {tool_successes}/{tool_attempts}",
        )

        completeness = executed_steps / total_steps if total_steps else 1.0
        factors["execution_completeness"] = (
            completeness,
            f"execution completeness {executed_steps}/{total_steps}",
        )

        blind_score = 1.0 - min(1.0, len(coverage.blind_spots) / 10.0)
        factors["blind_spots"] = (
            blind_score,
            f"{len(coverage.blind_spots)} documented blind spot(s)",
        )

        factor_objects: list[QualityFactor] = []
        total_weight = 0.0
        weighted = 0.0
        for name, (value, reason) in factors.items():
            weight = self._WEIGHTS.get(name, 0.1)
            score = max(0.0, min(1.0, value))
            factor_objects.append(QualityFactor(name=name, score=score, weight=weight, reason=reason))
            total_weight += weight
            weighted += score * weight

        overall = weighted / total_weight if total_weight else 0.0
        return MissionQuality(
            mission_id=mission_id,
            plan_id=plan_id,
            score=round(overall, 4),
            factors=factor_objects,
            explainability={
                "formula": "weighted mean of explainable factor scores",
                "factors": {factor.name: factor.score for factor in factor_objects},
                "failed_steps": failed_steps,
            },
        )


def _metric(report: CoverageReport, name: str) -> Any:
    """Return a coverage metric by kind name."""
    from hunterx.domain.orchestration.enums import CoverageKind

    for kind in CoverageKind:
        if kind.value == name:
            return report.metric(kind)
    return None


def _plan_of(run: Any) -> Any:
    """Extract a plan-like object from a run result (for coverage)."""
    return getattr(run, "plan", None)
