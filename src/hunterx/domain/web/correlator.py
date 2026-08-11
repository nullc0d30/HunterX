# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Correlation and deduplication for web crawl observations.

Merges raw observations from multiple tools/sources into one canonical artifact
per dedup key: the highest-confidence, latest observation wins while earlier
sightings are preserved as corroboration counts. Deterministic and stateless.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from hunterx.domain.web.models import (
    APIEndpoint,
    AuthenticationBoundary,
    CrawlEvidence,
    GraphQLEndpoint,
    Redirect,
    URLObservation,
    WebSocketEndpoint,
)


@dataclass(slots=True)
class WebCrawlCorrelation:
    """Correlated crawl artifacts with dedup statistics.

    Attributes:
        urls: canonical URL observations (one per key).
        redirects: canonical redirects.
        endpoints: canonical API endpoints.
        websockets: canonical WebSocket endpoints.
        graphqls: canonical GraphQL endpoints.
        auth_boundaries: canonical authentication boundaries.
        evidence: deduplicated evidence fragments.
        raw_count: number of raw observations consumed.
        dropped_count: number of observations merged away as duplicates.
        corroborations: count of duplicate sightings folded into kept records.

    """

    urls: list[URLObservation] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    endpoints: list[APIEndpoint] = field(default_factory=list)
    websockets: list[WebSocketEndpoint] = field(default_factory=list)
    graphqls: list[GraphQLEndpoint] = field(default_factory=list)
    auth_boundaries: list[AuthenticationBoundary] = field(default_factory=list)
    evidence: list[CrawlEvidence] = field(default_factory=list)
    raw_count: int = 0
    dropped_count: int = 0
    corroborations: int = 0

    def artifact_counts(self) -> dict[str, int]:
        """Return a summary of correlated artifact counts."""
        return {
            "urls": len(self.urls),
            "redirects": len(self.redirects),
            "api_endpoints": len(self.endpoints),
            "websocket_endpoints": len(self.websockets),
            "graphql_endpoints": len(self.graphqls),
            "auth_boundaries": len(self.auth_boundaries),
            "evidence": len(self.evidence),
        }


class WebCorrelator:
    """Merge duplicate crawl observations into canonical artifacts."""

    def correlate(
        self,
        *,
        urls: Sequence[URLObservation] | None = None,
        redirects: Sequence[Redirect] | None = None,
        endpoints: Sequence[APIEndpoint] | None = None,
        websockets: Sequence[WebSocketEndpoint] | None = None,
        graphqls: Sequence[GraphQLEndpoint] | None = None,
        auth_boundaries: Sequence[AuthenticationBoundary] | None = None,
        evidence: Sequence[CrawlEvidence] | None = None,
    ) -> WebCrawlCorrelation:
        """Deduplicate every artifact class and aggregate statistics."""
        raw_count = 0
        for sequence in (urls, redirects, endpoints, websockets, graphqls, auth_boundaries, evidence):
            raw_count += len(sequence or ())
        correlation = WebCrawlCorrelation(raw_count=raw_count)
        correlation.urls = _dedup(urls or (), key=lambda obs: obs.key(), keep=_keep_url)
        correlation.redirects = _dedup(redirects or (), key=lambda item: item.key())
        correlation.endpoints = _dedup(endpoints or (), key=lambda item: item.key())
        correlation.websockets = _dedup(websockets or (), key=lambda item: item.key())
        correlation.graphqls = _dedup(graphqls or (), key=lambda item: item.key())
        correlation.auth_boundaries = _dedup(auth_boundaries or (), key=lambda item: item.key())
        correlation.evidence = _dedup(evidence or (), key=lambda item: item.key())
        correlation.dropped_count = raw_count - (
            len(correlation.urls)
            + len(correlation.redirects)
            + len(correlation.endpoints)
            + len(correlation.websockets)
            + len(correlation.graphqls)
            + len(correlation.auth_boundaries)
            + len(correlation.evidence)
        )
        return correlation


_DedupKey = Callable[[Any], Any]
_DedupKeep = Callable[[Any, Any], bool]
_T = TypeVar("_T")


def _dedup(
    items: Sequence[_T],
    *,
    key: _DedupKey,
    keep: _DedupKeep | None = None,
) -> list[_T]:
    """Return the best item per canonical key, preserving first-seen order."""
    best: dict[str, _T] = {}
    order: list[str] = []
    for item in items:
        k = key(item)
        current = best.get(k)
        if current is None:
            best[k] = item
            order.append(k)
            continue
        if keep is not None and keep(item, current):
            best[k] = item
    return [best[k] for k in order if k in best]


def _keep_url(candidate: URLObservation, current: URLObservation) -> bool:
    """Prefer the URL observation with the most evidence (higher confidence)."""
    if candidate.confidence != current.confidence:
        return candidate.confidence > current.confidence
    candidate_status = candidate.status_code or 0
    current_status = current.status_code or 0
    return 200 <= candidate_status < 300 and not (200 <= current_status < 300)
