# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Graph storage adapters.

Provides an in-memory reference implementation of
:class:`~hunterx.domain.ports.KnowledgeGraphPort` suitable for development and
tests. A Neo4j adapter would implement the same port.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.ports.stores import KnowledgeGraphPort


class InMemoryKnowledgeGraph(KnowledgeGraphPort):
    """Thread-safe in-memory graph store.

    Nodes and relationships live in plain dictionaries keyed by identifier.
    Used for development, tests, and as the default when no graph backend is
    configured.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._relationships: list[dict[str, Any]] = []

    def upsert_node(self, node_id: str, *, labels: list[str], properties: dict[str, Any]) -> None:
        """Create or update a graph node with labels and properties."""
        existing = self._nodes.get(node_id, {})
        existing.update(properties)
        existing["labels"] = list(labels)
        self._nodes[node_id] = existing

    def upsert_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        *,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Create or update a typed edge between two nodes."""
        self._relationships.append(
            {
                "type": rel_type,
                "source": source_id,
                "target": target_id,
                "properties": properties or {},
            }
        )

    def query_neighbors(self, node_id: str, *, depth: int = 1, limit: int = 100) -> list[dict[str, Any]]:
        """Return neighbor nodes reachable from ``node_id`` within ``depth`` hops."""
        depth = max(1, depth)
        frontier = {node_id}
        visited: set[str] = set()
        results: list[dict[str, Any]] = []
        for _ in range(depth):
            next_frontier: set[str] = set()
            for rel in self._relationships:
                if rel["source"] in frontier and rel["target"] not in visited:
                    next_frontier.add(rel["target"])
                    results.append(
                        {
                            "type": rel["type"],
                            "source": rel["source"],
                            "target": rel["target"],
                            "properties": rel["properties"],
                        }
                    )
                elif rel["target"] in frontier and rel["source"] not in visited:
                    next_frontier.add(rel["source"])
                    results.append(
                        {
                            "type": rel["type"],
                            "source": rel["source"],
                            "target": rel["target"],
                            "properties": rel["properties"],
                        }
                    )
                if len(results) >= limit:
                    return results
            visited.update(frontier)
            frontier = next_frontier
        return results

    def delete_node(self, node_id: str) -> None:
        """Delete the node and all edges incident to it."""
        self._nodes.pop(node_id, None)
        self._relationships = [
            rel for rel in self._relationships if rel["source"] != node_id and rel["target"] != node_id
        ]
