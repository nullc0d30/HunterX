# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Confidence scoring for JavaScript intelligence.

Adjusts the confidence of findings based on evidence strength, rule baseline
confidence, evidence multiplicity and agreement across assets. The engine is
pure and deterministic: identical inputs yield identical scores.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class JSConfidencePolicy:
    """Tuning parameters for confidence adjustment.

    Attributes:
        base_floor: minimum confidence a finding can have.
        multiple_evidence_bonus: added when more than one evidence fragment
            supports a finding.
        multi_source_bonus: added when the finding is observed in more than
            one asset/execution.
        conflict_penalty: subtracted when a contradiction was recorded.
        version_unconfirmed_penalty: subtracted for version claims lacking a
            confirmed version.

    """

    base_floor: float = 0.1
    multiple_evidence_bonus: float = 0.05
    multi_source_bonus: float = 0.1
    conflict_penalty: float = 0.15
    version_unconfirmed_penalty: float = 0.1


class JSConfidenceEngine:
    """Compute adjusted confidence for JavaScript findings."""

    def __init__(self, policy: JSConfidencePolicy | None = None) -> None:
        self._policy = policy or JSConfidencePolicy()

    @property
    def policy(self) -> JSConfidencePolicy:
        """Return the active policy."""
        return self._policy

    def for_rule(self, base: float, *, evidence_count: int = 1) -> float:
        """Adjust a rule baseline confidence for the evidence present."""
        confidence = base
        if evidence_count > 1:
            confidence += self._policy.multiple_evidence_bonus
        return self._clamp(confidence)

    def combine(self, *confidences: float) -> float:
        """Combine several independent confidences for the same finding."""
        if not confidences:
            return 0.0
        score = 1.0
        for confidence in confidences:
            score *= 1.0 - self._clamp(confidence)
        return self._clamp(1.0 - score)

    def adjust(
        self,
        confidence: float,
        *,
        evidence_count: int = 1,
        source_count: int = 1,
        conflicted: bool = False,
        version_confirmed: bool = True,
    ) -> float:
        """Return ``confidence`` adjusted for the given context."""
        value = confidence
        if evidence_count > 1:
            value += self._policy.multiple_evidence_bonus
        if source_count > 1:
            value += self._policy.multi_source_bonus
        if conflicted:
            value -= self._policy.conflict_penalty
        if not version_confirmed:
            value -= self._policy.version_unconfirmed_penalty
        return self._clamp(value)

    def _clamp(self, value: float) -> float:
        return max(self._policy.base_floor, min(1.0, value))
