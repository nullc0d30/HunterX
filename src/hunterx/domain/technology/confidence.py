# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology confidence engine.

Assigns a defensible, deterministic confidence score to every technology
observation and recomputes it when several tools corroborate the same
technology on the same asset. Confidence is a pure function of (tool
reliability, validation status, evidence strength, version evidence quality,
corroboration count, historical stability and conflict discount) — the same
inputs always yield the same score and the score is explainable through the
factors that contributed to it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from hunterx.domain.technology.models import (
    EvidenceStrength,
    TechnologyObservation,
    VersionConfidence,
)

#: Default base reliability per tool (``0.2`` unknown tools score low).
_DEFAULT_BASE: dict[str, float] = {
    "httpx": 0.9,
    "whatweb": 0.85,
    "signature": 0.7,
    "tidb": 0.75,
    "nmap": 0.9,
    "masscan": 0.85,
    "naabu": 0.85,
    "tcp-connect": 0.7,
}

#: Multiplicative factor per validation status.
_VALIDATION_FACTORS: Mapping[str, float] = {
    "valid": 1.0,
    "unknown": 0.75,
    "invalid": 0.3,
}

#: Multiplicative factor per evidence strength (best matched indicator).
_EVIDENCE_FACTORS: Mapping[EvidenceStrength, float] = {
    EvidenceStrength.STRONG: 1.0,
    EvidenceStrength.MODERATE: 0.8,
    EvidenceStrength.WEAK: 0.55,
}

#: Factor per version confidence (a weak version never boosts identity).
_VERSION_FACTORS: Mapping[VersionConfidence, float] = {
    VersionConfidence.CONFIRMED: 1.1,
    VersionConfidence.PROBABLE: 1.0,
    VersionConfidence.RANGE: 0.9,
    VersionConfidence.UNKNOWN: 0.95,
}

#: Per-tool corroboration boost applied beyond the strongest tool.
_CORROBORATION_BOOST = 0.08

#: Discount applied when the same technology is reported under conflicting
#: versions on the same asset.
_CONFLICT_DISCOUNT = 0.85


@dataclass(frozen=True, slots=True)
class TechnologyConfidencePolicy:
    """Configuration governing technology confidence scoring.

    Attributes:
        base: map of ``tool_id`` to base reliability in ``[0, 1]``.
        validation_factors: map of validation status to a multiplicative factor.
        evidence_factors: factor per :class:`EvidenceStrength`.
        version_factors: factor per :class:`VersionConfidence`.
        corroboration_boost: confidence added per corroborating tool beyond
            the strongest one.
        conflict_discount: multiplier applied when a version conflict exists.
        max_confidence: ceiling applied to every computed score.

    """

    base: Mapping[str, float] = field(default_factory=lambda: dict(_DEFAULT_BASE))
    validation_factors: Mapping[str, float] = field(default_factory=lambda: dict(_VALIDATION_FACTORS))
    evidence_factors: Mapping[EvidenceStrength, float] = field(default_factory=lambda: dict(_EVIDENCE_FACTORS))
    version_factors: Mapping[VersionConfidence, float] = field(default_factory=lambda: dict(_VERSION_FACTORS))
    corroboration_boost: float = _CORROBORATION_BOOST
    conflict_discount: float = _CONFLICT_DISCOUNT
    max_confidence: float = 1.0

    def base_for(self, tool_id: str) -> float:
        """Return the base reliability for ``tool_id`` (``0.2`` when unknown)."""
        return self.base.get(tool_id, 0.2)

    def validation_factor(self, status: str) -> float:
        """Return the factor for a validation status (``0.5`` when unset)."""
        return self.validation_factors.get(status, 0.5)

    def evidence_factor(self, strength: EvidenceStrength) -> float:
        """Return the factor for an evidence strength (``0.7`` when unset)."""
        return self.evidence_factors.get(strength, 0.7)

    def version_factor(self, confidence: VersionConfidence) -> float:
        """Return the factor for a version confidence (``1.0`` when unset)."""
        return self.version_factors.get(confidence, 1.0)


class TechnologyConfidenceEngine:
    """Compute and merge confidence scores for technology observations.

    Usage::

        engine = TechnologyConfidenceEngine()
        score = engine.observation_confidence(observation)
        merged = engine.merged_confidence(observations)
    """

    def __init__(self, policy: TechnologyConfidencePolicy | None = None) -> None:
        self._policy = policy or TechnologyConfidencePolicy()

    @property
    def policy(self) -> TechnologyConfidencePolicy:
        """Return the active policy."""
        return self._policy

    def observation_confidence(self, observation: TechnologyObservation) -> float:
        """Return the confidence of a single observation."""
        base = self._policy.base_for(observation.tool_id)
        validation = self._policy.validation_factor(observation.validation_status)
        evidence = self._evidence_factor(observation)
        version = self._version_factor(observation)
        return _clamp(base * validation * evidence * version, self._policy)

    def merged_confidence(self, observations: Sequence[TechnologyObservation], *, conflicted: bool = False) -> float:
        """Compute the confidence of a corroborated observation group.

        Uses the strongest individual score, adds a boost for every distinct
        corroborating source beyond the first and applies the conflict discount
        when the group contains conflicting versions.
        """
        if not observations:
            return 0.0
        strongest = max(self.observation_confidence(observation) for observation in observations)
        distinct_tools = {observation.tool_id for observation in observations}
        distinct_tools.discard("")
        boost = self._policy.corroboration_boost * max(0, len(distinct_tools) - 1)
        score = strongest + boost
        if conflicted:
            score *= self._policy.conflict_discount
        return _clamp(score, self._policy)

    def historical_confidence(self, base: float, *, observations: int, stable: bool) -> float:
        """Adjust a confidence for historical stability.

        Technologies seen many times or that have remained stable across runs
        are more trustworthy.
        """
        stability = 1.0 if stable else 0.9
        history = min(1.0, 0.8 + 0.05 * max(0, observations - 1))
        return _clamp(base * stability * history, self._policy)

    def freshness_confidence(self, base: float, *, age_hours: float) -> float:
        """Decay a confidence score as an observation ages."""
        if age_hours <= 0:
            return _clamp(base, self._policy)
        factor = max(0.5, 1.0 - age_hours / 24.0)
        return _clamp(base * factor, self._policy)

    def detection_score(self, evidence: Sequence[EvidenceStrength]) -> float:
        """Return a normalized score for a set of evidence strengths."""
        if not evidence:
            return 0.0
        weights = [self._policy.evidence_factor(strength) for strength in evidence]
        return _clamp(sum(weights) / len(evidence), self._policy)

    def _evidence_factor(self, observation: TechnologyObservation) -> float:
        """Return the factor for the strongest evidence fragment."""
        if not observation.evidence:
            return 0.7
        strengths = [item.strength for item in observation.evidence if isinstance(item.strength, EvidenceStrength)]
        best = max(strengths, default=EvidenceStrength.MODERATE)
        return self._policy.evidence_factor(best)

    def _version_factor(self, observation: TechnologyObservation) -> float:
        """Return the factor for the observation's version confidence."""
        version_spec = observation.version_spec
        if version_spec is None:
            return 1.0
        return self._policy.version_factor(version_spec.confidence)


def _clamp(value: float, policy: TechnologyConfidencePolicy) -> float:
    """Clamp ``value`` into ``[0, max_confidence]``."""
    return max(0.0, min(policy.max_confidence, value))
