# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Confidence engine.

Sprint 032. Confidence is a weighted aggregate over deterministic evidence
components — detection evidence, behavioral evidence, independent verification,
impact evidence, reproducibility, tool reliability, evidence quality,
corroboration and historical target behavior. It is never an opaque AI
probability, and it can never be inflated by a single scanner result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.mission_orchestration.enums import ConfidenceComponent
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class ConfidenceInput:
    """Deterministic inputs for a confidence computation.

    Attributes:
        detection_evidence: strength of the detection evidence in ``[0, 1]``.
        behavioral_evidence: strength of behavioral/differential evidence.
        independent_verification: ``1.0`` when an independent validator agreed.
        impact_evidence: strength of impact evidence.
        reproducibility: ``1.0`` when the behavior was reproduced.
        tool_reliability: historical reliability of the reporting tool.
        evidence_quality: quality of the evidence artifacts.
        corroboration: how many independent sources corroborate (count).
        historical_target_behavior: consistency with prior target observations.

    """

    detection_evidence: float = 0.0
    behavioral_evidence: float = 0.0
    independent_verification: float = 0.0
    impact_evidence: float = 0.0
    reproducibility: float = 0.0
    tool_reliability: float = 0.5
    evidence_quality: float = 0.0
    corroboration: int = 0
    historical_target_behavior: float = 0.0


@dataclass(frozen=True, slots=True)
class ConfidenceResult:
    """Result of a confidence computation with per-component scores.

    Attributes:
        score: aggregate confidence in ``[0, 1]``.
        components: per-component contributions.
        verdict: explainable verdict string.
        created_at: timestamp.

    """

    score: float
    components: dict[str, float] = field(default_factory=dict)
    verdict: str = ""
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "score": self.score,
            "components": self.components,
            "verdict": self.verdict,
            "created_at": self.created_at,
        }


class ConfidenceEngine:
    """Compute evidence-driven confidence scores.

    The engine is deterministic and configurable via ``weights`` (defaults are
    explainable equal-weight-ish); weights never let a single component exceed
    ``1.0`` after normalization.
    """

    _DEFAULT_WEIGHTS: dict[ConfidenceComponent, float] = {
        ConfidenceComponent.DETECTION_EVIDENCE: 0.16,
        ConfidenceComponent.BEHAVIORAL_EVIDENCE: 0.18,
        ConfidenceComponent.INDEPENDENT_VERIFICATION: 0.18,
        ConfidenceComponent.IMPACT_EVIDENCE: 0.10,
        ConfidenceComponent.REPRODUCIBILITY: 0.12,
        ConfidenceComponent.TOOL_RELIABILITY: 0.08,
        ConfidenceComponent.EVIDENCE_QUALITY: 0.08,
        ConfidenceComponent.CORROBORATION: 0.06,
        ConfidenceComponent.HISTORICAL_TARGET_BEHAVIOR: 0.04,
    }

    def compute(
        self,
        inp: ConfidenceInput,
        *,
        weights: dict[str, float] | None = None,
    ) -> ConfidenceResult:
        """Compute the aggregate confidence and per-component contributions."""
        effective = self._weights(weights)
        components: dict[str, float] = {}
        for component, weight in effective.items():
            value = self._component_value(inp, component)
            components[component.value] = round(value * weight, 4)
        score = round(sum(components.values()), 4)
        verdict = self._verdict(inp, score)
        return ConfidenceResult(score=score, components=components, verdict=verdict)

    def _weights(self, overrides: dict[str, float] | None) -> dict[ConfidenceComponent, float]:
        """Return normalized weights, applying any overrides."""
        effective = dict(self._DEFAULT_WEIGHTS)
        for key, value in (overrides or {}).items():
            try:
                effective[ConfidenceComponent(key)] = value
            except ValueError:
                continue
        total = sum(effective.values()) or 1.0
        return {component: value / total for component, value in effective.items()}

    @staticmethod
    def _component_value(inp: ConfidenceInput, component: ConfidenceComponent) -> float:
        """Return the raw ``[0, 1]`` value of a confidence component."""
        if component is ConfidenceComponent.DETECTION_EVIDENCE:
            return min(1.0, inp.detection_evidence)
        if component is ConfidenceComponent.BEHAVIORAL_EVIDENCE:
            return min(1.0, inp.behavioral_evidence)
        if component is ConfidenceComponent.INDEPENDENT_VERIFICATION:
            return min(1.0, inp.independent_verification)
        if component is ConfidenceComponent.IMPACT_EVIDENCE:
            return min(1.0, inp.impact_evidence)
        if component is ConfidenceComponent.REPRODUCIBILITY:
            return min(1.0, inp.reproducibility)
        if component is ConfidenceComponent.TOOL_RELIABILITY:
            return min(1.0, inp.tool_reliability)
        if component is ConfidenceComponent.EVIDENCE_QUALITY:
            return min(1.0, inp.evidence_quality)
        if component is ConfidenceComponent.CORROBORATION:
            return min(1.0, inp.corroboration / 3.0)
        if component is ConfidenceComponent.HISTORICAL_TARGET_BEHAVIOR:
            return min(1.0, inp.historical_target_behavior)
        return 0.0

    @staticmethod
    def _verdict(inp: ConfidenceInput, score: float) -> str:
        """Return an explainable verdict string."""
        if inp.independent_verification >= 1.0 and inp.reproducibility >= 1.0:
            return "independently verified and reproduced"
        if score >= 0.75:
            return "high evidence-driven confidence"
        if score >= 0.5:
            return "moderate evidence-driven confidence"
        if score >= 0.25:
            return "low evidence-driven confidence"
        return "insufficient evidence for confidence"


__all__ = ["ConfidenceComponent", "ConfidenceEngine", "ConfidenceInput", "ConfidenceResult"]
