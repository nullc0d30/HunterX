# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology view builder.

Projects the correlated graph into the canonical attack-surface views: asset
inventory, network, DNS, service, certificate, organization infrastructure,
external attack surface and shared infrastructure. Views are serializable
mappings suitable for reporting and rendering; they never mutate state.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunterx.domain.topology.enums import RelationshipType
from hunterx.domain.topology.models import GraphRelationship, TopologyAnalysis, TopologyChange, TopologyCluster


class TopologyViewBuilder:
    """Build serializable attack-surface views from a topology."""

    #: Relationship types grouped by view scope.
    _NETWORK_TYPES = {
        RelationshipType.PART_OF.value,
        RelationshipType.ANNOUNCED_BY.value,
        RelationshipType.EXPOSES.value,
        RelationshipType.SERVES.value,
        RelationshipType.HOSTED_ON.value,
        RelationshipType.ROUTES_TO.value,
        RelationshipType.SHARES_INFRASTRUCTURE_WITH.value,
        RelationshipType.SHARES_IP_WITH.value,
    }
    _DNS_TYPES = {
        RelationshipType.RESOLVES_TO.value,
        RelationshipType.POINTS_TO.value,
        RelationshipType.DELEGATED_TO.value,
        RelationshipType.MAILS_TO.value,
        RelationshipType.PART_OF.value,
    }
    _SERVICE_TYPES = {
        RelationshipType.EXPOSES.value,
        RelationshipType.SERVES.value,
        RelationshipType.HOSTED_ON.value,
        RelationshipType.OBSERVED_WITH.value,
    }
    _CERTIFICATE_TYPES = {
        RelationshipType.USES.value,
        RelationshipType.CERTIFICATE_FOR.value,
        RelationshipType.SIGNED_BY.value,
        RelationshipType.SHARES_CERTIFICATE_WITH.value,
    }
    _ORG_TYPES = {
        RelationshipType.BELONGS_TO.value,
        RelationshipType.PART_OF.value,
        RelationshipType.ANNOUNCED_BY.value,
    }

    def asset_inventory_graph(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the full asset inventory graph."""
        return self._view("asset_inventory", relationships, mission_id=mission_id)

    def network_graph(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the network-level view (IP/CIDR/ASN/port/service edges)."""
        return self._view(
            "network",
            relationships,
            mission_id=mission_id,
            rel_types=self._NETWORK_TYPES,
        )

    def dns_graph(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the DNS topology view."""
        return self._view("dns", relationships, mission_id=mission_id, rel_types=self._DNS_TYPES)

    def service_graph(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the service topology view (host → port → service)."""
        return self._view("service", relationships, mission_id=mission_id, rel_types=self._SERVICE_TYPES)

    def certificate_graph(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the certificate topology view."""
        return self._view("certificate", relationships, mission_id=mission_id, rel_types=self._CERTIFICATE_TYPES)

    def organization_graph(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the organization infrastructure view."""
        return self._view("organization", relationships, mission_id=mission_id, rel_types=self._ORG_TYPES)

    def external_attack_surface(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the external attack surface (all in-scope edges)."""
        return self._view(
            "external_attack_surface",
            [edge for edge in relationships if edge.in_scope],
            mission_id=mission_id,
        )

    def shared_infrastructure(
        self,
        clusters: Sequence[TopologyCluster],
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """Return the shared-infrastructure view (clusters + SHARES_* edges)."""
        nodes: dict[str, dict[str, Any]] = {}
        for cluster in clusters:
            for key in cluster.entity_keys:
                nodes.setdefault(key, self._node_from_key(key))
        shared_edges = [edge.as_dict() for edge in relationships]
        return {
            "view": "shared_infrastructure",
            "mission_id": mission_id,
            "clusters": [cluster.as_dict() for cluster in clusters],
            "nodes": list(nodes.values()),
            "relationships": shared_edges,
        }

    def asset_clusters(self, clusters: Sequence[TopologyCluster]) -> dict[str, Any]:
        """Return the asset cluster view (cluster records only)."""
        return {
            "view": "asset_clusters",
            "clusters": [cluster.as_dict() for cluster in clusters],
            "count": len(clusters),
        }

    def historical_view(self, changes: Sequence[TopologyChange]) -> dict[str, Any]:
        """Return the historical topology change view."""
        return {
            "view": "historical",
            "changes": [change.as_dict() for change in changes],
            "count": len(changes),
        }

    def related_assets(self, key: str, related: Sequence[str]) -> dict[str, Any]:
        """Return the related-assets view for ``key``."""
        return {
            "view": "related_assets",
            "asset": key,
            "related": sorted(related),
            "count": len(related),
        }

    def analysis_summary(self, analysis: TopologyAnalysis) -> dict[str, Any]:
        """Return the analysis summary view."""
        return analysis.as_dict()

    # -- helpers ------------------------------------------------------------

    def _view(
        self,
        name: str,
        relationships: Sequence[GraphRelationship],
        *,
        mission_id: str,
        rel_types: set[str] | None = None,
    ) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        for edge in relationships:
            if rel_types is not None and edge.rel_type.value not in rel_types:
                continue
            nodes.setdefault(edge.source.key, edge.source.as_dict())
            nodes.setdefault(edge.target.key, edge.target.as_dict())
            edges.append(edge.as_dict())
        return {
            "view": name,
            "mission_id": mission_id,
            "nodes": list(nodes.values()),
            "relationships": edges,
            "node_count": len(nodes),
            "relationship_count": len(edges),
        }

    @staticmethod
    def _node_from_key(key: str) -> dict[str, Any]:
        kind, _, name = key.partition(":")
        return {"kind": kind, "name": name, "key": key, "label": name}
