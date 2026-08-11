# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deterministic cloud intelligence confidence scoring.

Confidence is a pure function of (source reliability, evidence strength,
corroboration count, conflict discount and historical stability). Identical
inputs always produce identical scores.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.cloud.models import EvidenceStrength

_DEFAULT_BASE: dict[str, float] = {
    "cloud": 0.8,
    "dns": 0.9,
    "http": 0.85,
    "web": 0.8,
    "javascript": 0.8,
    "technology": 0.75,
    "tls": 0.7,
    "documentation": 0.6,
    "tidb": 0.75,
    "api": 0.85,
    "tool": 0.7,
    "tipp": 0.6,
}

_EVIDENCE_FACTORS: dict[EvidenceStrength, float] = {
    EvidenceStrength.STRONG: 1.0,
    EvidenceStrength.MODERATE: 0.8,
    EvidenceStrength.WEAK: 0.55,
}


@dataclass(frozen=True, slots=True)
class CloudConfidencePolicy:
    """Scoring policy: source bases, evidence factors and boosts.

    Attributes:
        base: per-source reliability base in ``[0, 1]``.
        evidence_factors: multiplier per :class:`EvidenceStrength`.
        corroboration_boost: per additional distinct source.
        conflict_discount: multiplier applied to conflicted merges.
        max_confidence: hard ceiling.
        unknown_source_base: base for unrecognized sources.

    """

    base: Mapping[str, float] = field(default_factory=lambda: dict(_DEFAULT_BASE))
    evidence_factors: Mapping[EvidenceStrength, float] = field(default_factory=lambda: dict(_EVIDENCE_FACTORS))
    corroboration_boost: float = 0.08
    conflict_discount: float = 0.85
    max_confidence: float = 1.0
    unknown_source_base: float = 0.2

    def base_for(self, source: str) -> float:
        """Return the reliability base for ``source``."""
        return self.base.get(str(source).lower(), self.unknown_source_base)

    def evidence_factor(self, strength: EvidenceStrength) -> float:
        """Return the multiplier for an evidence strength."""
        return self.evidence_factors.get(strength, 0.7)


class CloudConfidenceEngine:
    """Deterministic confidence scoring for cloud observations."""

    def __init__(self, policy: CloudConfidencePolicy | None = None) -> None:
        self.policy = policy or CloudConfidencePolicy()

    def observation_confidence(self, observation: Any) -> float:
        """Score a single observation from its declared confidence, source and evidence."""
        declared = float(getattr(observation, "confidence", 0.5) or 0.5)
        source = str(getattr(observation, "source", "cloud") or "cloud")
        evidence = tuple(getattr(observation, "evidence", ()) or ())
        base = self.policy.base_for(source)
        factor = _best_evidence_factor(evidence, self.policy)
        return _clamp(declared * factor * (0.5 + 0.5 * base), self.policy)

    def merged_confidence(self, observations: Sequence[Any], *, conflicted: bool = False) -> float:
        """Score a merged group of observations sharing one subject.

        The strongest single observation dominates; every additional distinct
        source adds a small corroboration boost; a conflicted merge is
        discounted.
        """
        if not observations:
            return 0.0
        strongest = max(self.observation_confidence(obs) for obs in observations)
        sources = {str(getattr(obs, "source", "") or "") for obs in observations if getattr(obs, "source", "")}
        boost = self.policy.corroboration_boost * max(0, len(sources) - 1)
        score = strongest + boost
        if conflicted:
            score *= self.policy.conflict_discount
        return _clamp(score, self.policy)

    def historical_confidence(self, base: float, *, observations: int, stable: bool) -> float:
        """Adjust a base confidence for historical stability.

        More observations and stability across observations raise the score
        slightly; a change (unstable) keeps it conservative.
        """
        stability = 1.0 if stable else 0.9
        history = min(1.0, 0.8 + 0.05 * max(0, observations - 1))
        return _clamp(base * stability * history, self.policy)

    def detection_score(self, evidence: Sequence[EvidenceStrength]) -> float:
        """Return the average evidence factor for a detection."""
        if not evidence:
            return 0.0
        return _clamp(sum(self.policy.evidence_factor(strength) for strength in evidence) / len(evidence), self.policy)


def _best_evidence_factor(evidence: Sequence[Any], policy: CloudConfidencePolicy) -> float:
    """Return the factor of the strongest evidence fragment (default 0.8)."""
    best = EvidenceStrength.WEAK
    for item in evidence:
        strength = getattr(item, "strength", None)
        if isinstance(strength, EvidenceStrength) and _ORDER[strength] < _ORDER[best]:
            best = strength
        elif isinstance(strength, str):
            try:
                parsed = EvidenceStrength(strength)
                if _ORDER[parsed] < _ORDER[best]:
                    best = parsed
            except ValueError:
                continue
    return policy.evidence_factor(best)


_ORDER: dict[EvidenceStrength, int] = {
    EvidenceStrength.STRONG: 0,
    EvidenceStrength.MODERATE: 1,
    EvidenceStrength.WEAK: 2,
}


def _clamp(value: float, policy: CloudConfidencePolicy) -> float:
    return max(0.0, min(policy.max_confidence, value))
