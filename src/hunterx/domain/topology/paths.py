# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology path & relationship queries.

Safe, read-only graph navigation over the correlated topology: neighbors,
ancestors, descendants, shortest relationship paths, related assets and shared
infrastructure. These are infrastructure-intelligence queries only — no
exploitation, no state mutation.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from hunterx.domain.topology.enums import RelationshipType
from hunterx.domain.topology.graph import TopologyGraph
from hunterx.domain.topology.models import GraphRelationship


class TopologyPathFinder:
    """Navigate the correlated topology graph."""

    def __init__(self, graph: TopologyGraph) -> None:
        self._graph = graph

    @property
    def graph(self) -> TopologyGraph:
        """Return the underlying graph index."""
        return self._graph

    def neighbors(self, key: str) -> list[dict]:
        """Return adjacent nodes of ``key``."""
        return self._graph.neighbors(key)

    def ancestors(self, key: str, *, rel_types: Iterable[str] | None = None, max_depth: int = 0) -> set[str]:
        """Return ancestors of ``key`` (nodes leading to it)."""
        return self._graph.ancestors(key, rel_types=rel_types, max_depth=max_depth)

    def descendants(self, key: str, *, rel_types: Iterable[str] | None = None, max_depth: int = 0) -> set[str]:
        """Return descendants of ``key`` (nodes reachable from it)."""
        return self._graph.descendants(key, rel_types=rel_types, max_depth=max_depth)

    def shortest_path(
        self,
        source_key: str,
        target_key: str,
        *,
        rel_types: Iterable[str] | None = None,
        max_depth: int = 0,
    ) -> list[str]:
        """Return the shortest relationship path or ``[]`` when unreachable."""
        return self._graph.shortest_path(source_key, target_key, rel_types=rel_types, max_depth=max_depth)

    def related_assets(self, key: str, *, max_depth: int = 3) -> set[str]:
        """Return assets connected to ``key`` within ``max_depth`` hops."""
        return self._graph.descendants(key, max_depth=max_depth) | self._graph.ancestors(key, max_depth=max_depth)

    def shared_infrastructure(self, keys: Iterable[str]) -> list[GraphRelationship]:
        """Return SHARES_* edges connecting the given asset keys.

        Any SHARES_* relationship whose source or target appears in ``keys`` is
        returned; this surfaces co-hosted/co-certificate/co-nameserver overlap.
        """
        wanted = set(keys)
        shared_types = {
            RelationshipType.SHARES_INFRASTRUCTURE_WITH.value,
            RelationshipType.SHARES_CERTIFICATE_WITH.value,
            RelationshipType.SHARES_IP_WITH.value,
            RelationshipType.SHARES_NAMESERVER_WITH.value,
        }
        results: list[GraphRelationship] = []
        for edge in self._graph.edges():
            if edge.rel_type.value not in shared_types:
                continue
            if edge.source.key in wanted or edge.target.key in wanted:
                results.append(edge)
        return results

    def path_edges(self, path: Sequence[str]) -> list[GraphRelationship]:
        """Return the edges along a node path (best-effort adjacency)."""
        edges: list[GraphRelationship] = []
        by_pair: dict[tuple[str, str], GraphRelationship] = {}
        for edge in self._graph.edges():
            by_pair[(edge.source.key, edge.target.key)] = edge
        for left, right in zip(path, path[1:], strict=False):
            edge = by_pair.get((left, right))
            if edge is not None:
                edges.append(edge)
        return edges
