# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology analyzer.

Deterministic analysis over the correlated graph: asset clusters, shared
infrastructure, network/service concentration, density, orphan/dangling/
unresolved/stale assets and connected components. Analysis output feeds
reporting and the SHARES_* relationships in the graph.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence

from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.enums import ClusterType, EntityKind, RelationshipType
from hunterx.domain.topology.graph import TopologyGraph
from hunterx.domain.topology.models import GraphRelationship, TopologyAnalysis, TopologyCluster

#: Maximum members for which pairwise SHARES_* edges are emitted.
_MAX_PAIR_MEMBERS = 8


class TopologyAnalyzer:
    """Compute deterministic topology analytics."""

    def __init__(self, confidence: TopologyConfidenceEngine | None = None) -> None:
        self._confidence = confidence or TopologyConfidenceEngine()

    def analyze(
        self,
        relationships: Sequence[GraphRelationship],
        *,
        now: str = "",
        stale_days: float = 90.0,
        node_keys: Iterable[str] | None = None,
        mission_id: str = "",
        correlation_id: str = "",
    ) -> TopologyAnalysis:
        """Analyze a set of correlated edges."""
        graph = TopologyGraph(relationships)
        nodes = graph.nodes()
        known = set(node_keys) if node_keys is not None else None
        if now == "":
            from hunterx.shared.time import utcnow_iso

            now = utcnow_iso()

        clusters = self._clusters(graph, mission_id=mission_id, correlation_id=correlation_id)
        shared_edges = self._shared_edges(clusters, mission_id=mission_id, correlation_id=correlation_id)
        for edge in shared_edges:
            graph.add(edge)

        analysis = TopologyAnalysis(
            node_count=len(nodes),
            relationship_count=len(graph),
            clusters=clusters,
            shared_relationships=shared_edges,
            cluster_count=len(clusters),
            density=self._density(nodes, len(graph)),
        )

        components = graph.components()
        analysis.components = len(components)
        if components:
            analysis.largest_component_size = max(len(c) for c in components)

        self._flag_assets(graph, known, now, stale_days, analysis, mission_id, correlation_id)
        return analysis

    # -- clusters -----------------------------------------------------------

    def _clusters(
        self,
        graph: TopologyGraph,
        *,
        mission_id: str,
        correlation_id: str,
    ) -> list[TopologyCluster]:
        clusters: list[TopologyCluster] = []

        clusters.extend(
            self._group_cluster(
                graph,
                attr=lambda e: e.rel_type.value,
                member_rel_types={RelationshipType.RESOLVES_TO.value, RelationshipType.USES.value},
                cluster_type=ClusterType.SAME_IP,
                label="same_ip",
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
        )

        clusters.extend(
            self._group_cluster(
                graph,
                attr=lambda e: e.target.key,
                member_rel_types={RelationshipType.USES.value},
                cluster_type=ClusterType.SAME_CERT,
                label="same_cert",
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
        )

        clusters.extend(
            self._group_cluster(
                graph,
                attr=lambda e: e.target.key,
                member_rel_types={RelationshipType.DELEGATED_TO.value},
                cluster_type=ClusterType.SAME_NAMESERVER,
                label="same_nameserver",
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
        )

        clusters.extend(
            self._group_cluster(
                graph,
                attr=lambda e: e.target.key,
                member_rel_types={RelationshipType.ANNOUNCED_BY.value},
                cluster_type=ClusterType.SAME_ASN,
                label="same_asn",
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
        )

        clusters.extend(
            self._group_cluster(
                graph,
                attr=lambda e: e.target.key,
                member_rel_types={RelationshipType.PART_OF.value},
                cluster_type=ClusterType.SAME_CIDR,
                label="same_cidr",
                member_kinds={EntityKind.IP.value, EntityKind.HOSTNAME.value},
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
        )

        clusters.extend(
            self._group_cluster(
                graph,
                attr=lambda e: e.target.name,
                member_rel_types={RelationshipType.SERVES.value, RelationshipType.OBSERVED_WITH.value},
                cluster_type=ClusterType.SERVICE,
                label="service",
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
        )
        return clusters

    @staticmethod
    def _group_cluster(
        graph: TopologyGraph,
        *,
        attr: callable,
        member_rel_types: set[str],
        cluster_type: ClusterType,
        label: str,
        mission_id: str,
        correlation_id: str,
        member_kinds: set[str] | None = None,
    ) -> list[TopologyCluster]:
        groups: dict[object, set[str]] = defaultdict(set)
        for edge in graph.edges():
            if edge.rel_type.value not in member_rel_types:
                continue
            if member_kinds is not None and edge.source.kind.value not in member_kinds:
                continue
            groups[attr(edge)].add(edge.source.key)

        clusters: list[TopologyCluster] = []
        for shared_value in sorted(groups, key=str):
            members = groups[shared_value]
            if len(members) < 2:
                continue
            clusters.append(
                TopologyCluster(
                    name=f"{label}:{shared_value}",
                    cluster_type=cluster_type,
                    entity_keys=sorted(members),
                    metric={"shared": str(shared_value), "member_count": len(members)},
                    detected_by="topology.analysis",
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
            )
        return clusters

    def _shared_edges(
        self,
        clusters: Sequence[TopologyCluster],
        *,
        mission_id: str,
        correlation_id: str,
    ) -> list[GraphRelationship]:
        """Emit pairwise SHARES_* edges for small clusters (bounded)."""
        type_map = {
            ClusterType.SAME_IP: RelationshipType.SHARES_IP_WITH,
            ClusterType.SAME_CERT: RelationshipType.SHARES_CERTIFICATE_WITH,
            ClusterType.SAME_NAMESERVER: RelationshipType.SHARES_NAMESERVER_WITH,
            ClusterType.SAME_ASN: RelationshipType.SHARES_INFRASTRUCTURE_WITH,
            ClusterType.SAME_CIDR: RelationshipType.SHARES_INFRASTRUCTURE_WITH,
            ClusterType.SERVICE: RelationshipType.SHARES_INFRASTRUCTURE_WITH,
        }
        edges: list[GraphRelationship] = []
        for cluster in clusters:
            members = cluster.entity_keys
            if len(members) < 2 or len(members) > _MAX_PAIR_MEMBERS:
                continue
            rel_type = type_map[cluster.cluster_type]
            from hunterx.domain.topology.models import TopologyEntity

            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    left, right = members[i], members[j]
                    source_kind, _, source_name = left.partition(":")
                    target_kind, _, target_name = right.partition(":")
                    edges.append(
                        GraphRelationship(
                            rel_type=rel_type,
                            source=TopologyEntity(kind=source_kind, name=source_name),
                            target=TopologyEntity(kind=target_kind, name=target_name),
                            sources=["topology.analysis"],
                            evidence={"cluster": cluster.name, "cluster_type": cluster.cluster_type.value},
                            confidence=0.9,
                            mission_id=mission_id,
                            correlation_id=correlation_id,
                            in_scope=True,
                        )
                    )
        return edges

    # -- flags --------------------------------------------------------------

    def _flag_assets(
        self,
        graph: TopologyGraph,
        known: set[str] | None,
        now: str,
        stale_days: float,
        analysis: TopologyAnalysis,
        mission_id: str,
        correlation_id: str,
    ) -> None:
        incident: set[str] = set()
        by_rel: dict[str, set[str]] = defaultdict(set)
        last_seen: dict[str, str] = {}
        resolved: set[str] = set()

        for edge in graph.edges():
            incident.add(edge.source.key)
            incident.add(edge.target.key)
            by_rel[edge.rel_type.value].add(edge.source.key)
            last_seen[edge.source.key] = max(last_seen.get(edge.source.key, ""), edge.last_seen or "")
            if edge.rel_type.value == RelationshipType.RESOLVES_TO.value:
                resolved.add(edge.source.key)

        if known is not None:
            analysis.orphan_keys = sorted(k for k in known if k not in incident)
            analysis.orphan_count = len(analysis.orphan_keys)

            unresolved_hostnames = [
                k
                for k in known
                if k.startswith(f"{EntityKind.HOSTNAME.value}:")
                and k not in resolved
                and k in incident
            ]
            analysis.unresolved_count = len(unresolved_hostnames)
            analysis.dangling_keys = sorted(
                k
                for k in known
                if k not in incident
                and not k.startswith(f"{EntityKind.ROUTE.value}:")
                and not k.startswith(f"{EntityKind.TOOL.value}:")
                and not k.startswith(f"{EntityKind.ASN.value}:")
                and not k.startswith(f"{EntityKind.NAMESERVER.value}:")
                and not k.startswith(f"{EntityKind.MX.value}:")
            )
            analysis.dangling_count = len(analysis.dangling_keys)

        stale = [
            k
            for k, seen in last_seen.items()
            if seen and self._confidence.is_stale(last_seen=seen, now=now, max_age_days=stale_days)
        ]
        analysis.stale_keys = sorted(stale)
        analysis.stale_count = len(stale)

    @staticmethod
    def _density(nodes: set[str], edge_count: int) -> float:
        n = len(nodes)
        if n < 2:
            return 0.0
        return edge_count / (n * (n - 1) / 2.0)
