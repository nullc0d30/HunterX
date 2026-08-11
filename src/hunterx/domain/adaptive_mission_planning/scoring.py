# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Explainable action scoring.

The scoring model weights twelve explainable factors (information gain,
hypothesis relevance, coverage improvement, evidence value, proof value, asset
criticality, mission priority, tool effectiveness, execution cost, execution
risk, redundancy, dependency readiness) into a single ``[0, 1]`` score. The
model is configurable — it is never an opaque AI-only score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.adaptive_mission_planning.enums import (
    DecisionFactor,
    MissionMode,
)
from hunterx.domain.adaptive_mission_planning.models import ActionNode
from hunterx.domain.adaptive_mission_planning.objective import MODE_WEIGHTS

#: Default weights (sum ≈ 1.0) for the explainable ranking.
DEFAULT_WEIGHTS: dict[DecisionFactor, float] = {
    DecisionFactor.INFORMATION_GAIN: 0.15,
    DecisionFactor.HYPOTHESIS_RELEVANCE: 0.12,
    DecisionFactor.COVERAGE_IMPROVEMENT: 0.12,
    DecisionFactor.EVIDENCE_VALUE: 0.10,
    DecisionFactor.PROOF_VALUE: 0.10,
    DecisionFactor.ASSET_CRITICALITY: 0.08,
    DecisionFactor.MISSION_PRIORITY: 0.08,
    DecisionFactor.TOOL_EFFECTIVENESS: 0.08,
    DecisionFactor.EXECUTION_COST: 0.07,
    DecisionFactor.EXECUTION_RISK: 0.07,
    DecisionFactor.REDUNDANCY: 0.02,
    DecisionFactor.DEPENDENCY_READINESS: 0.01,
}


@dataclass(frozen=True, slots=True)
class ScoringResult:
    """A scored action with its explainable factor breakdown.

    Attributes:
        action_id: the scored action.
        score: aggregate ``[0, 1]`` score.
        factors: per-factor contribution (factor → weighted value).
        rationale: the dominant rationale.

    """

    action_id: str = ""
    score: float = 0.0
    factors: dict[str, float] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize the scoring result to a JSON-safe mapping."""
        return {
            "action_id": self.action_id,
            "score": self.score,
            "factors": self.factors,
            "rationale": self.rationale,
        }


class ScoringModel:
    """Configurable, explainable action scoring.

    Args:
        weights: optional factor weights overriding the defaults.
        mode: mission mode; applies additive mode weights (modes adjust
            priorities, never authorization or safety).

    """

    def __init__(
        self,
        *,
        weights: dict[DecisionFactor, float] | dict[str, float] | None = None,
        mode: MissionMode = MissionMode.BALANCED,
    ) -> None:
        self.weights: dict[DecisionFactor, float] = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(_coerce_weights(weights))
        self.mode = mode
        self.mode_weights = MODE_WEIGHTS.get(mode, {})

    def score(self, action: ActionNode, *, context: dict[str, object] | None = None) -> ScoringResult:
        """Compute the explainable score for ``action``.

        ``context`` may carry pre-computed inputs such as ``"asset_criticality"``,
        ``"tool_effectiveness"`` and ``"dependency_ready"``.
        """
        context = context or {}
        factors: dict[str, float] = {}

        gain = _clamp(action.expected_information_gain)
        hypothesis_relevance = 1.0 if action.hypothesis_id else 0.0
        coverage = 1.0 if action.capability else 0.0
        evidence = 1.0 if action.expected_evidence else 0.0
        proof = _clamp(action.expected_proof_value)
        criticality = _clamp(_as_float(context.get("asset_criticality"), 0.5))
        mission_priority = _clamp(_as_float(context.get("mission_priority"), 0.5))
        tool_effectiveness = _clamp(_as_float(context.get("tool_effectiveness"), 0.6))
        cost = _clamp(action.cost)
        risk = _clamp(action.risk)
        redundancy = _clamp(_as_float(context.get("redundancy"), 0.0))
        dependency_ready = 1.0 if bool(context.get("dependency_ready", True)) else 0.0

        raw: dict[DecisionFactor, float] = {
            DecisionFactor.INFORMATION_GAIN: gain,
            DecisionFactor.HYPOTHESIS_RELEVANCE: hypothesis_relevance,
            DecisionFactor.COVERAGE_IMPROVEMENT: coverage,
            DecisionFactor.EVIDENCE_VALUE: evidence,
            DecisionFactor.PROOF_VALUE: proof,
            DecisionFactor.ASSET_CRITICALITY: criticality,
            DecisionFactor.MISSION_PRIORITY: mission_priority,
            DecisionFactor.TOOL_EFFECTIVENESS: tool_effectiveness,
            DecisionFactor.EXECUTION_COST: cost,
            DecisionFactor.EXECUTION_RISK: risk,
            DecisionFactor.REDUNDANCY: redundancy,
            DecisionFactor.DEPENDENCY_READINESS: dependency_ready,
        }

        total_weight = 0.0
        aggregate = 0.0
        for factor, raw_value in raw.items():
            weight = self.weights.get(factor, 0.0)
            mode_multiplier = self.mode_weights.get(factor.value, 1.0)
            weighted = weight * raw_value * mode_multiplier
            factors[factor.value] = round(weighted, 4)
            total_weight += weight * mode_multiplier
            aggregate += weighted

        score = (aggregate / total_weight) if total_weight else 0.0
        score = max(0.0, min(1.0, score))
        dominant = max(factors, key=lambda key: factors[key]) if factors else ""
        rationale = f"dominant factor '{dominant}' contributed {factors.get(dominant, 0.0):.2f}"
        return ScoringResult(action_id=action.action_id, score=score, factors=factors, rationale=rationale)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def _as_float(value: object, default: float) -> float:
    """Return ``value`` as a float, falling back to ``default`` when unusable."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _coerce_weights(weights: dict[DecisionFactor, float] | dict[str, float]) -> dict[DecisionFactor, float]:
    coerced: dict[DecisionFactor, float] = {}
    for key, value in weights.items():
        if isinstance(key, DecisionFactor):
            coerced[key] = float(value)
        else:
            factor = _factor_by_value(key)
            if factor is not None:
                coerced[factor] = float(value)
    return coerced


def _factor_by_value(value: str) -> DecisionFactor | None:
    for factor in DecisionFactor:
        if factor.value == value:
            return factor
    return None
