# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization intelligence confidence engine.

Assigns a defensible, deterministic confidence score to every authorization
observation and recomputes it when several sources corroborate the same
observation. Confidence is a pure function of (source reliability, evidence
strength, corroboration count, historical stability and conflict discount) —
the same inputs always yield the same score and the score is explainable
through the factors that contributed to it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.authorization.models import EvidenceStrength

#: Default base reliability per source (``0.2`` unknown sources score low).
_DEFAULT_BASE: dict[str, float] = {
    "authorization": 0.8,
    "http": 0.9,
    "web": 0.8,
    "javascript": 0.85,
    "api": 0.9,
    "graphql": 0.85,
    "tidb": 0.75,
}

#: Multiplicative factor per evidence strength (best matched indicator).
_EVIDENCE_FACTORS: Mapping[EvidenceStrength, float] = {
    EvidenceStrength.STRONG: 1.0,
    EvidenceStrength.MODERATE: 0.8,
    EvidenceStrength.WEAK: 0.55,
}

#: Per-source corroboration boost applied beyond the strongest source.
_CORROBORATION_BOOST = 0.08

#: Discount applied when the same subject carries conflicting evidence.
_CONFLICT_DISCOUNT = 0.85


@dataclass(frozen=True, slots=True)
class AuthorizationConfidencePolicy:
    """Configuration governing authorization confidence scoring.

    Attributes:
        base: map of ``source`` to base reliability in ``[0, 1]``.
        evidence_factors: factor per :class:`EvidenceStrength`.
        corroboration_boost: confidence added per corroborating source beyond
            the strongest one.
        conflict_discount: multiplier applied when a conflict exists.
        max_confidence: ceiling applied to every computed score.

    """

    base: Mapping[str, float] = field(default_factory=lambda: dict(_DEFAULT_BASE))
    evidence_factors: Mapping[EvidenceStrength, float] = field(default_factory=lambda: dict(_EVIDENCE_FACTORS))
    corroboration_boost: float = _CORROBORATION_BOOST
    conflict_discount: float = _CONFLICT_DISCOUNT
    max_confidence: float = 1.0

    def base_for(self, source: str) -> float:
        """Return the base reliability for ``source`` (``0.2`` when unknown)."""
        return self.base.get(source, 0.2)

    def evidence_factor(self, strength: EvidenceStrength) -> float:
        """Return the factor for an evidence strength (``0.7`` when unset)."""
        return self.evidence_factors.get(strength, 0.7)


class AuthorizationConfidenceEngine:
    """Compute and merge confidence scores for authorization observations.

    Usage::

        engine = AuthorizationConfidenceEngine()
        score = engine.observation_confidence(observation)
        merged = engine.merged_confidence(observations)
    """

    def __init__(self, policy: AuthorizationConfidencePolicy | None = None) -> None:
        self._policy = policy or AuthorizationConfidencePolicy()

    @property
    def policy(self) -> AuthorizationConfidencePolicy:
        """Return the active policy."""
        return self._policy

    def observation_confidence(self, observation: Any) -> float:
        """Return the deterministic confidence of a single observation.

        Uses the declared confidence when the observation already carries one
        (the analyzer assigns evidence-aware values), scaled by the strongest
        evidence factor when evidence is attached.
        """
        declared = float(getattr(observation, "confidence", 0.5) or 0.5)
        source = str(getattr(observation, "source", "") or "")
        base = self._policy.base_for(source)
        evidence = getattr(observation, "evidence", ())
        factor = self._best_evidence_factor(evidence)
        return _clamp(declared * factor * (0.5 + 0.5 * base), self._policy)

    def merged_confidence(self, observations: Sequence[Any], *, conflicted: bool = False) -> float:
        """Compute the confidence of a corroborated observation group.

        Uses the strongest individual score and adds a boost for every distinct
        corroborating source beyond the first.
        """
        if not observations:
            return 0.0
        strongest = max(self.observation_confidence(observation) for observation in observations)
        distinct_sources = {
            str(getattr(obs, "source", "")) for obs in observations if getattr(obs, "source", "")
        }
        boost = self._policy.corroboration_boost * max(0, len(distinct_sources) - 1)
        score = strongest + boost
        if conflicted:
            score *= self._policy.conflict_discount
        return _clamp(score, self._policy)

    def historical_confidence(self, base: float, *, observations: int, stable: bool) -> float:
        """Adjust a confidence for historical stability."""
        stability = 1.0 if stable else 0.9
        history = min(1.0, 0.8 + 0.05 * max(0, observations - 1))
        return _clamp(base * stability * history, self._policy)

    def detection_score(self, evidence: Sequence[EvidenceStrength]) -> float:
        """Return a normalized score for a set of evidence strengths."""
        if not evidence:
            return 0.0
        weights = [self._policy.evidence_factor(strength) for strength in evidence]
        return _clamp(sum(weights) / len(weights), self._policy)

    def _best_evidence_factor(self, evidence: Sequence[Any]) -> float:
        strengths: list[EvidenceStrength] = []
        for item in evidence:
            strength = getattr(item, "strength", None)
            if isinstance(strength, EvidenceStrength):
                strengths.append(strength)
        if not strengths:
            return 0.8
        return self._policy.evidence_factor(max(strengths))


def _clamp(value: float, policy: AuthorizationConfidencePolicy) -> float:
    """Clamp ``value`` into ``[0, max_confidence]``."""
    return max(0.0, min(policy.max_confidence, value))
