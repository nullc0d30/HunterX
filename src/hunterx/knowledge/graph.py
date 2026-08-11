# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge graph.

A domain-level wrapper over the graph storage port. The wrapper owns the node
labeling and relationship conventions used by the platform; the underlying
port is swappable (in-memory, Neo4j, ...).
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.ports.stores import KnowledgeGraphPort


class KnowledgeGraph:
    """Domain-facing graph operations over a :class:`KnowledgeGraphPort`."""

    def __init__(self, store: KnowledgeGraphPort) -> None:
        self._store = store

    def add_asset(self, asset_id: str, *, properties: dict[str, Any] | None = None) -> None:
        """Upsert an ``Asset`` node."""
        self._store.upsert_node(asset_id, labels=["Asset"], properties=properties or {})

    def add_finding(self, finding_id: str, *, properties: dict[str, Any] | None = None) -> None:
        """Upsert a ``Finding`` node."""
        self._store.upsert_node(finding_id, labels=["Finding"], properties=properties or {})

    def add_knowledge(self, record_id: str, *, category: str, properties: dict[str, Any] | None = None) -> None:
        """Upsert a knowledge node labeled by ``category``."""
        self._store.upsert_node(
            record_id,
            labels=["Knowledge", category.capitalize()],
            properties=properties or {},
        )

    def add_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        *,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Upsert a relationship between two nodes."""
        self._store.upsert_relationship(rel_type, source_id, target_id, properties=properties)

    def neighbors(self, node_id: str, *, depth: int = 1, limit: int = 100) -> list[dict[str, Any]]:
        """Return neighbor relationships of a node."""
        return self._store.query_neighbors(node_id, depth=depth, limit=limit)
