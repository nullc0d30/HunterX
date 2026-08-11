# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Confidence scoring for web crawl observations.

Deterministic and explainable: an observation starts from a base confidence
assigned by its artifact type and upstream source, then receives small boosts
for corroborating evidence. Every score carries the rules that produced it so
auditors can reproduce the decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Base confidence per artifact type.
_BASE_CONFIDENCE: Mapping[str, float] = {
    "url": 0.9,
    "redirect": 0.9,
    "api_endpoint": 0.7,
    "websocket": 0.7,
    "graphql": 0.7,
    "auth_boundary": 0.6,
}

#: Confidence multiplier per upstream source.
_SOURCE_CONFIDENCE: Mapping[str, float] = {
    "crawl": 1.0,
    "katana": 0.95,
    "sitemap": 0.9,
    "robots": 0.8,
    "passive": 0.6,
    "historical": 0.5,
}

#: Per-evidence-type confidence boost (evidence of strong provenance).
_EVIDENCE_BOOST: Mapping[str, float] = {
    "html": 0.0,
    "header": 0.05,
    "script": 0.05,
    "response": 0.05,
    "robots": 0.0,
    "sitemap": 0.0,
}


class WebConfidenceEngine:
    """Assign and adjust confidence scores for web observations."""

    def artifact_base(self, artifact_type: str) -> float:
        """Return the base confidence for an artifact type."""
        return _BASE_CONFIDENCE.get(artifact_type, 0.7)

    def source_weight(self, source: str) -> float:
        """Return the confidence weight of an upstream source."""
        return _SOURCE_CONFIDENCE.get((source or "").strip().lower(), 0.7)

    def score(
        self,
        artifact_type: str,
        source: str,
        *,
        evidence_count: int = 0,
        status_code: int | None = None,
    ) -> float:
        """Compute a confidence score for one observation.

        Args:
            artifact_type: ``url``, ``redirect``, ``api_endpoint``,
                ``websocket``, ``graphql`` or ``auth_boundary``.
            source: upstream source (``crawl``, ``katana``, ``sitemap``,
                ``robots``, ``passive``, ``historical``).
            evidence_count: number of corroborating evidence fragments.
            status_code: observed HTTP status (2xx responses lift URL
                confidence; 4xx/5xx lower it).

        Returns:
            A confidence score in ``[0, 1]``.

        """
        base = self.artifact_base(artifact_type)
        weight = self.source_weight(source)
        score = base * weight
        score += min(0.1, 0.02 * max(0, evidence_count))
        if status_code is not None:
            if 200 <= status_code < 300:
                score += 0.05
            elif status_code in (301, 302, 303, 307, 308):
                score += 0.0
            elif status_code in (401, 403):
                score -= 0.05
            elif status_code >= 400:
                score -= 0.1
        return max(0.1, min(1.0, round(score, 4)))

    def explain(self, artifact_type: str, source: str, **kwargs: Any) -> dict[str, Any]:
        """Return an audit trail for a :meth:`score` call."""
        return {
            "artifact_type": artifact_type,
            "source": source,
            "base": self.artifact_base(artifact_type),
            "source_weight": self.source_weight(source),
            "evidence_count": kwargs.get("evidence_count", 0),
            "status_code": kwargs.get("status_code"),
            "score": self.score(artifact_type, source, **kwargs),
        }
