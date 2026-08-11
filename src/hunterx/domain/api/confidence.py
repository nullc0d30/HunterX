# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence confidence engine.

Assigns a defensible, deterministic confidence score to every API observation
and recomputes it when several sources corroborate the same endpoint or host.
Confidence is a pure function of (tool reliability, evidence strength,
documentation status, corroboration count and conflict discount) — the same
inputs always yield the same score and the score is explainable through the
factors that contributed to it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from hunterx.domain.api.models import (
    APIHostObservation,
    ApiOperationObservation,
    APISpecObservation,
    EvidenceStrength,
)

#: Default base reliability per source tool (``0.2`` for unknown tools).
_DEFAULT_BASE: dict[str, float] = {
    "api-openapi": 0.95,
    "api-swagger": 0.95,
    "api-graphql": 0.9,
    "api-websocket": 0.85,
    "api-soap": 0.9,
    "api-hints": 0.7,
    "web.crawl": 0.75,
    "javascript": 0.7,
    "technology": 0.65,
    "tidb": 0.8,
    "crawler": 0.75,
}

#: Multiplicative factor per evidence strength (best matched indicator).
_EVIDENCE_FACTORS: Mapping[EvidenceStrength, float] = {
    EvidenceStrength.STRONG: 1.0,
    EvidenceStrength.MODERATE: 0.8,
    EvidenceStrength.WEAK: 0.55,
}

#: Multiplicative factor for documentation status.
_DOCUMENTED_FACTOR = 1.0
_UNDOCUMENTED_FACTOR = 0.85

#: Corroboration bonus per additional independent source (capped).
_CORROBORATION_BONUS = 0.05
_CORROBORATION_CAP = 0.15

#: Conflict discount applied when a subject is under dispute.
_CONFLICT_DISCOUNT = 0.75


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


class ApiConfidenceEngine:
    """Compute deterministic confidence scores for API intelligence.

    Usage::

        engine = ApiConfidenceEngine()
        score = engine.score_spec(spec)
        score = engine.score_operation(operation, corroborated_by=3)
    """

    def score_spec(self, spec: APISpecObservation) -> float:
        """Score a located spec document."""
        base = _DEFAULT_BASE.get(spec.tool_id, 0.6)
        evidence_factor = self._best_evidence_factor(spec.evidence)
        documented = _DOCUMENTED_FACTOR if spec.operation_count else _UNDOCUMENTED_FACTOR
        return _clamp(base * evidence_factor * documented)

    def score_host(self, host: APIHostObservation) -> float:
        """Score a correlated API host."""
        base = _DEFAULT_BASE.get(host.tool_id, 0.6)
        evidence_factor = self._best_evidence_factor(host.evidence)
        documented = _DOCUMENTED_FACTOR if host.documented else _UNDOCUMENTED_FACTOR
        corroboration = min(_CORROBORATION_BONUS * max(0, len(host.evidence) - 1), _CORROBORATION_CAP)
        return _clamp((base + corroboration) * evidence_factor * documented)

    def score_operation(
        self,
        operation: ApiOperationObservation,
        *,
        corroborated_by: int = 1,
        conflicted: bool = False,
    ) -> float:
        """Score a correlated endpoint operation."""
        base = _DEFAULT_BASE.get(operation.tool_id, 0.6)
        evidence_factor = self._best_evidence_factor(operation.evidence)
        documented = _DOCUMENTED_FACTOR if operation.documented else _UNDOCUMENTED_FACTOR
        corroboration = min(
            _CORROBORATION_BONUS * max(0, corroborated_by - 1),
            _CORROBORATION_CAP,
        )
        score = (base + corroboration) * evidence_factor * documented
        if conflicted:
            score *= _CONFLICT_DISCOUNT
        return _clamp(score)

    def aggregate(
        self,
        base: float,
        *,
        sources: int = 1,
        best_evidence: EvidenceStrength | None = None,
        documented: bool | None = None,
        conflicted: bool = False,
    ) -> float:
        """Aggregate a confidence from explicit factors (generic entry point)."""
        evidence_factor = _EVIDENCE_FACTORS.get(
            best_evidence or EvidenceStrength.MODERATE,
            _EVIDENCE_FACTORS[EvidenceStrength.MODERATE],
        )
        documented_factor = _DOCUMENTED_FACTOR if documented is None or documented else _UNDOCUMENTED_FACTOR
        corroboration = min(_CORROBORATION_BONUS * max(0, sources - 1), _CORROBORATION_CAP)
        score = (base + corroboration) * evidence_factor * documented_factor
        if conflicted:
            score *= _CONFLICT_DISCOUNT
        return _clamp(score)

    def _best_evidence_factor(self, evidence: Sequence[object]) -> float:
        """Return the factor of the strongest evidence fragment."""
        best: EvidenceStrength = EvidenceStrength.WEAK
        for item in evidence:
            strength = getattr(item, "strength", None)
            if isinstance(strength, EvidenceStrength):
                best = max(best, strength)
            elif strength is not None:
                try:
                    best = max(best, EvidenceStrength(str(strength).lower()))
                except ValueError:
                    continue
        return _EVIDENCE_FACTORS[best]
