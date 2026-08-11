# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack Surface Graph.

Sprint 026. The AttackSurfaceGraph is the continuously evolving representation
of everything HunterX knows about a target's attack surface: assets as nodes
and typed relationships as edges. It composes with the existing topology
abstraction (:class:`TopologyGraph`) and adds intelligence-specific queries:
assets by kind, sub-graph extraction, change-driven re-analysis and coverage
lookups.

The graph is always *derived* from canonical state (assets + relationships) and
never holds the source of truth. It supports in-memory and SQL-backed ports and
can be swapped for a dedicated graph database behind the same interface.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from hunterx.domain.target_intelligence.models import IntelligenceAsset, IntelligenceChange
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.graph import TopologyGraph
from hunterx.domain.topology.models import GraphRelationship, TopologyEntity


class AttackSurfaceGraph:
    """A typed graph over assets with intelligence queries.

    Attributes:
        assets_by_key: canonical key → asset.
        topology: the underlying topology graph.
        changes: recently detected changes.

    """

    def __init__(
        self,
        *,
        assets: Sequence[IntelligenceAsset] | None = None,
        relationships: Sequence[GraphRelationship] | None = None,
        changes: Sequence[IntelligenceChange] | None = None,
        topology: TopologyGraph | None = None,
    ) -> None:
        self.assets_by_key: dict[str, IntelligenceAsset] = {
            asset.key: asset for asset in (assets or ())
        }
        self._relationships: dict[str, GraphRelationship] = {
            edge.key: edge for edge in (relationships or ())
        }
        self.topology = topology if topology is not None else TopologyGraph(relationships)
        self.changes: list[IntelligenceChange] = list(changes or ())

    # -- mutation -----------------------------------------------------------

    def upsert_asset(self, asset: IntelligenceAsset) -> None:
        """Add or refresh an asset node."""
        self.assets_by_key[asset.key] = asset

    def add_relationship(self, edge: GraphRelationship) -> None:
        """Add or replace a relationship edge."""
        self._relationships[edge.key] = edge
        self.topology.add(edge)

    def record_changes(self, changes: Sequence[IntelligenceChange]) -> None:
        """Append detected changes (used for analysis hints)."""
        self.changes.extend(changes)

    def clear_changes(self) -> None:
        """Drop recorded changes after they are consumed."""
        self.changes.clear()

    # -- reads --------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.assets_by_key)

    def asset(self, key: str) -> IntelligenceAsset | None:
        """Return an asset by canonical key or ``None``."""
        return self.assets_by_key.get(key)

    def assets(self) -> list[IntelligenceAsset]:
        """Return all assets sorted by key."""
        return [self.assets_by_key[key] for key in sorted(self.assets_by_key)]

    def assets_of_kind(self, kind: EntityKind | str) -> list[IntelligenceAsset]:
        """Return assets of a given :class:`EntityKind`."""
        expected = kind.value if isinstance(kind, EntityKind) else str(kind)
        return [asset for asset in self.assets() if (asset.kind.value if isinstance(asset.kind, EntityKind) else str(asset.kind)) == expected]

    def relationships(self) -> list[GraphRelationship]:
        """Return all edges sorted by key."""
        return [self._relationships[key] for key in sorted(self._relationships)]

    def relationship(self, key: str) -> GraphRelationship | None:
        """Return an edge by key or ``None``."""
        return self._relationships.get(key)

    def neighbors(self, key: str) -> list[dict[str, Any]]:
        """Return adjacent nodes with direction and relationship type."""
        return self.topology.neighbors(key)

    def descendants(self, key: str, *, rel_types: Iterable[str] | None = None, max_depth: int = 0) -> set[str]:
        """Return keys reachable by following outgoing edges from ``key``."""
        return self.topology.descendants(key, rel_types=rel_types, max_depth=max_depth)

    def ancestors(self, key: str, *, rel_types: Iterable[str] | None = None, max_depth: int = 0) -> set[str]:
        """Return keys that can reach ``key`` by following incoming edges."""
        return self.topology.ancestors(key, rel_types=rel_types, max_depth=max_depth)

    def subtree(self, key: str, *, max_depth: int = 0) -> list[IntelligenceAsset]:
        """Return the asset sub-graph rooted at ``key``.

        Discovers the connected component around ``key`` (undirected) so a
        service graph can be pulled for a host, endpoint or cloud resource.
        """
        seen: set[str] = {key}
        frontier: set[str] = self.topology.descendants(key, max_depth=max_depth) | self.topology.ancestors(
            key, max_depth=max_depth
        )
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            seen.add(current)
            frontier |= self.topology.descendants(current, max_depth=max_depth)
            frontier |= self.topology.ancestors(current, max_depth=max_depth)
        return [asset for asset in self.assets() if asset.key in seen]

    def by_kind_map(self) -> dict[str, list[IntelligenceAsset]]:
        """Return assets grouped by entity kind."""
        grouped: dict[str, list[IntelligenceAsset]] = {}
        for asset in self.assets():
            kind = asset.kind.value if isinstance(asset.kind, EntityKind) else str(asset.kind)
            grouped.setdefault(kind, []).append(asset)
        return grouped

    def coverage_targets(self) -> list[IntelligenceAsset]:
        """Return the assets that should receive coverage cells.

        Only leaf-ish, testable assets (URLs, endpoints, services, ports,
        APIs, cloud resources) are coverage targets — domain nodes are
        structural.
        """
        testable = {
            EntityKind.URL.value,
            EntityKind.API_ENDPOINT.value,
            EntityKind.GRAPHQL_ENDPOINT.value,
            EntityKind.WEBSOCKET_ENDPOINT.value,
            EntityKind.AUTH_ENDPOINT.value,
            EntityKind.AUTH_SURFACE.value,
            EntityKind.ADMIN_SURFACE.value,
            EntityKind.SERVICE.value,
            EntityKind.PORT.value,
            EntityKind.CLOUD_RESOURCE.value,
            EntityKind.CLOUD_ENDPOINT.value,
            EntityKind.SAAS_INTEGRATION.value,
            EntityKind.WEBHOOK.value,
            EntityKind.STORAGE_RESOURCE.value,
            EntityKind.COMPUTE_RESOURCE.value,
            EntityKind.KUBERNETES_RESOURCE.value,
        }
        return [asset for asset in self.assets() if _kind_str(asset.kind) in testable]

    def subgraph_dict(self, key: str, *, max_depth: int = 0) -> dict[str, Any]:
        """Return a JSON-safe sub-graph view rooted at ``key``."""
        subtree = self.subtree(key, max_depth=max_depth)
        keys = {asset.key for asset in subtree}
        assets = [asset.to_dict() for asset in subtree]
        edges = [
            edge.as_dict()
            for edge in self.relationships()
            if edge.source.key in keys and edge.target.key in keys
        ]
        return {"root": key, "assets": assets, "relationships": edges}

    def to_dict(self) -> dict[str, Any]:
        """Serialize the whole graph to a JSON-safe mapping."""
        return {
            "assets": [asset.to_dict() for asset in self.assets()],
            "relationships": [edge.as_dict() for edge in self.relationships()],
            "changes": [change.to_dict() for change in self.changes],
        }


def asset_to_entity(asset: IntelligenceAsset) -> TopologyEntity:
    """Convert an asset to a topology entity node."""
    return TopologyEntity(
        kind=asset.kind,
        name=asset.name,
        key=asset.key,
        label=asset.label or asset.name,
        meta=dict(asset.properties),
    )


def _kind_str(kind: EntityKind | str) -> str:
    """Return the canonical kind string of an entity kind value."""
    return kind.value if isinstance(kind, EntityKind) else str(kind)


def relationship_for(
    rel_type: RelationshipType | str,
    source: IntelligenceAsset,
    target: IntelligenceAsset,
    *,
    mission_id: str = "",
    source_name: str = "",
    confidence: float = 1.0,
    evidence: dict[str, Any] | None = None,
) -> GraphRelationship:
    """Build a graph edge between two assets."""
    return GraphRelationship(
        rel_type=rel_type,
        source=asset_to_entity(source),
        target=asset_to_entity(target),
        sources=[source_name] if source_name else [],
        evidence=evidence or {},
        confidence=confidence,
        mission_id=mission_id,
        in_scope=source.in_scope and target.in_scope,
    )


__all__ = [
    "AttackSurfaceGraph",
    "asset_to_entity",
    "relationship_for",
]
