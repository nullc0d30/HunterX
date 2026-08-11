# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology graph.

An in-memory adjacency index over correlated graph edges. It powers queries
(neighbors, ancestors, descendants, shortest paths) and analysis without a
dedicated graph database — the graph is always rebuilt from canonical TIDB
relationships and never holds the source of truth.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Sequence
from typing import Any

from hunterx.domain.topology.models import GraphRelationship


class TopologyGraph:
    """Directed, typed adjacency index over graph edges."""

    def __init__(self, relationships: Sequence[GraphRelationship] | None = None) -> None:
        self._edges: dict[str, GraphRelationship] = {}
        self._out: dict[str, list[str]] = {}
        self._in: dict[str, list[str]] = {}
        self._edge_by_key: dict[str, GraphRelationship] = {}
        if relationships:
            for edge in relationships:
                self.add(edge)

    # -- mutation -----------------------------------------------------------

    def add(self, edge: GraphRelationship) -> None:
        """Add or replace an edge in the index."""
        self._edges[edge.key] = edge
        self._edge_by_key[edge.key] = edge
        self._out.setdefault(edge.source.key, []).append(edge.key)
        self._in.setdefault(edge.target.key, []).append(edge.key)

    def remove(self, key: str) -> None:
        """Remove an edge by its relationship key."""
        edge = self._edges.pop(key, None)
        if edge is None:
            return
        self._edge_by_key.pop(key, None)
        self._out[edge.source.key] = [k for k in self._out.get(edge.source.key, []) if k != key]
        self._in[edge.target.key] = [k for k in self._in.get(edge.target.key, []) if k != key]

    def clear(self) -> None:
        """Drop every edge (fresh graph)."""
        self._edges.clear()
        self._edge_by_key.clear()
        self._out.clear()
        self._in.clear()

    # -- read ---------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._edges)

    def edges(self) -> list[GraphRelationship]:
        """Return all edges sorted by relationship key."""
        return [self._edges[key] for key in sorted(self._edges)]

    def edge(self, key: str) -> GraphRelationship | None:
        """Return the edge for ``key`` or ``None``."""
        return self._edge_by_key.get(key)

    def nodes(self) -> set[str]:
        """Return the set of node keys incident to any edge."""
        return set(self._out) | set(self._in)

    def outgoing(self, key: str) -> list[GraphRelationship]:
        """Return edges leaving ``key``, sorted by key."""
        return [self._edges[k] for k in sorted(self._out.get(key, []))]

    def incoming(self, key: str) -> list[GraphRelationship]:
        """Return edges entering ``key``, sorted by key."""
        return [self._edges[k] for k in sorted(self._in.get(key, []))]

    def neighbors(self, key: str) -> list[dict[str, Any]]:
        """Return all adjacent nodes with direction and edge type.

        Each entry: ``{"key", "kind", "name", "rel_type", "direction"}`` where
        direction is ``outgoing``/``incoming``/``both``.
        """
        results: dict[str, dict[str, Any]] = {}
        for edge in self.outgoing(key):
            entry = results.setdefault(
                edge.target.key,
                {
                    "key": edge.target.key,
                    "kind": edge.target.kind.value,
                    "name": edge.target.name,
                    "direction": "outgoing",
                    "rel_type": edge.rel_type.value,
                },
            )
            entry["direction"] = "both" if entry["direction"] == "incoming" else "outgoing"
            entry["rel_type"] = edge.rel_type.value
        for edge in self.incoming(key):
            entry = results.setdefault(
                edge.source.key,
                {
                    "key": edge.source.key,
                    "kind": edge.source.kind.value,
                    "name": edge.source.name,
                    "direction": "incoming",
                    "rel_type": edge.rel_type.value,
                },
            )
            entry["direction"] = "both" if entry["direction"] == "outgoing" else "incoming"
            entry["rel_type"] = edge.rel_type.value
        return [results[key] for key in sorted(results)]

    def _walk(self, start: str, *, follow: callable, rel_types: set[str] | None, max_depth: int) -> set[str]:
        """BFS over edges selected by ``follow`` (outgoing/incoming)."""
        reached: set[str] = set()
        if start not in self.nodes():
            return reached
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        visited: set[str] = {start}
        while queue:
            node, depth = queue.popleft()
            if max_depth and depth >= max_depth:
                continue
            for edge in follow(node):
                if rel_types is not None and edge.rel_type.value not in rel_types:
                    continue
                neighbor = edge.target.key if edge.source.key == node else edge.source.key
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                reached.add(neighbor)
                queue.append((neighbor, depth + 1))
        return reached

    def descendants(self, key: str, *, rel_types: Iterable[str] | None = None, max_depth: int = 0) -> set[str]:
        """Return nodes reachable by following outgoing edges from ``key``."""
        selected = set(rel_types) if rel_types is not None else None
        return self._walk(key, follow=self.outgoing, rel_types=selected, max_depth=max_depth)

    def ancestors(self, key: str, *, rel_types: Iterable[str] | None = None, max_depth: int = 0) -> set[str]:
        """Return nodes that can reach ``key`` by following incoming edges."""
        selected = set(rel_types) if rel_types is not None else None
        return self._walk(key, follow=self.incoming, rel_types=selected, max_depth=max_depth)

    def shortest_path(
        self,
        source_key: str,
        target_key: str,
        *,
        rel_types: Iterable[str] | None = None,
        max_depth: int = 0,
    ) -> list[str]:
        """Return the shortest node path ``source → target`` or ``[]``.

        BFS over undirected adjacency (edges are traversable in both
        directions) so hierarchy paths like ``domain → hostname → ip`` work
        regardless of edge orientation. Returns a list of node keys including
        both endpoints, or an empty list when unreachable.
        """
        if source_key == target_key:
            return [source_key]
        if source_key not in self.nodes() or target_key not in self.nodes():
            return []
        selected = set(rel_types) if rel_types is not None else None
        queue: deque[tuple[str, list[str]]] = deque([(source_key, [source_key])])
        visited: set[str] = {source_key}
        while queue:
            node, path = queue.popleft()
            if max_depth and len(path) - 1 >= max_depth:
                continue
            for neighbor_entry in self.neighbors(node):
                if selected is not None and neighbor_entry["rel_type"] not in selected:
                    continue
                neighbor = neighbor_entry["key"]
                if neighbor in visited:
                    continue
                next_path = path + [neighbor]
                if neighbor == target_key:
                    return next_path
                visited.add(neighbor)
                queue.append((neighbor, next_path))
        return []

    def components(self) -> list[set[str]]:
        """Return undirected connected components as node-key sets."""
        seen: set[str] = set()
        components: list[set[str]] = []
        for start in sorted(self.nodes()):
            if start in seen:
                continue
            queue: deque[str] = deque([start])
            seen.add(start)
            component: set[str] = set()
            while queue:
                node = queue.popleft()
                component.add(node)
                for neighbor_entry in self.neighbors(node):
                    neighbor = neighbor_entry["key"]
                    if neighbor not in seen:
                        seen.add(neighbor)
                        queue.append(neighbor)
            components.append(component)
        return components

    def to_dict(self) -> dict[str, Any]:
        """Serialize the graph to a JSON-safe mapping."""
        return {
            "nodes": sorted(self.nodes()),
            "relationships": [edge.as_dict() for edge in self.edges()],
        }
