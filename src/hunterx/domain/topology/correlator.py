# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology correlator.

Merges raw relationship observations into canonical, deduplicated graph edges.
Correlation preserves provenance (source list), merges evidence per source,
combines confidence deterministically and tracks the first/last observation
window. Deterministic ordering guarantees stable output across runs.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.models import GraphRelationship, RelationshipObservation
from hunterx.domain.topology.scope import TopologyScopeEnforcer


class TopologyCorrelator:
    """Correlate observations into canonical graph edges."""

    def __init__(
        self,
        confidence: TopologyConfidenceEngine | None = None,
        scope: TopologyScopeEnforcer | None = None,
    ) -> None:
        self._confidence = confidence or TopologyConfidenceEngine()
        self._scope = scope

    def correlate(
        self,
        observations: Sequence[RelationshipObservation],
        *,
        mission_id: str = "",
        correlation_id: str = "",
    ) -> list[GraphRelationship]:
        """Merge ``observations`` into canonical edges grouped by key."""
        groups: dict[str, list[RelationshipObservation]] = {}
        for observation in observations:
            groups.setdefault(observation.key, []).append(observation)

        edges: list[GraphRelationship] = []
        for key in sorted(groups):
            edge = self._merge(groups[key], mission_id=mission_id, correlation_id=correlation_id)
            if edge is not None:
                edges.append(edge)
        return edges

    def _merge(
        self,
        group: list[RelationshipObservation],
        *,
        mission_id: str,
        correlation_id: str,
    ) -> GraphRelationship | None:
        first = group[0]
        latest = max(group, key=lambda obs: obs.observed_at or "")

        sources: list[str] = []
        evidence: dict[str, list[object]] = {}
        confidences: list[float] = []
        source_names: list[str] = []
        for observation in group:
            source_name = observation.source_name or "unknown"
            if source_name not in sources:
                sources.append(source_name)
            evidence.setdefault(source_name, []).append(observation.evidence or {})
            confidences.append(float(observation.confidence))
            source_names.append(source_name)

        in_scope = all(observation.in_scope for observation in group)
        if self._scope is not None:
            decision = self._scope.relationship(first.source.key, first.target.key)
            in_scope = in_scope and decision.in_scope

        stamps = [obs.observed_at for obs in group if obs.observed_at]
        return GraphRelationship(
            rel_type=first.rel_type,
            source=first.source,
            target=first.target,
            sources=sources,
            evidence=evidence,
            confidence=self._confidence.combine(confidences, source_names=source_names),
            first_seen=min(stamps) if stamps else "",
            last_seen=max(stamps) if stamps else "",
            mission_id=mission_id or latest.mission_id or first.mission_id,
            execution_id=latest.execution_id or first.execution_id,
            correlation_id=correlation_id or latest.correlation_id or first.correlation_id,
            in_scope=in_scope,
            source_id=first.source.entity_id,
            target_id=first.target.entity_id,
        )
