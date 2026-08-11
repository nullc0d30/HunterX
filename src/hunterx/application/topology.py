# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Network mapping & attack-surface topology use-case services.

``TopologyService`` is the orchestrator: it collects existing target
intelligence from the TIDB, optionally runs route-level tools through the
Tool Integration SDK, derives and correlates relationships, detects and
preserves conflicts, diffs history, analyzes the graph, persists the derived
topology into the TIDB (the single system of record) and publishes
``topology.*`` events.

``TopologyQueryService`` reads persisted topology relationships back from the
TIDB and answers the canonical graph queries (neighbors, ancestors,
descendants, shortest paths, shared infrastructure, clusters, ...). Both
services depend on ports only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.entities.tidb.network import (
    ASN,
    CIDR,
    Certificate,
    DNSRecord,
    Domain,
    Hostname,
    IPAddress,
    MXRecord,
    Nameserver,
    Port,
    Service,
    Subdomain,
)
from hunterx.domain.entities.tidb.technology import TechnologyObservation
from hunterx.domain.entities.tidb.topology import (
    TopologyBuild,
)
from hunterx.domain.entities.tidb.topology import (
    TopologyChange as TidbChange,
)
from hunterx.domain.entities.tidb.topology import (
    TopologyCluster as TidbCluster,
)
from hunterx.domain.entities.tidb.topology import (
    TopologyConflict as TidbConflict,
)
from hunterx.domain.entities.tidb.topology import (
    TopologyRelationship as TidbRelationship,
)
from hunterx.domain.events.types import (
    TopologyAnalysisCompletedEvent,
    TopologyAnalysisStartedEvent,
    TopologyBuildCompletedEvent,
    TopologyBuildFailedEvent,
    TopologyBuildStartedEvent,
    TopologyClusterCreatedEvent,
    TopologyConflictDetectedEvent,
    TopologyEntityCorrelatedEvent,
    TopologyRelationshipDiscoveredEvent,
    TopologyRelationshipRemovedEvent,
    TopologyRelationshipUpdatedEvent,
)
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.topology.analysis import TopologyAnalyzer
from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.conflicts import TopologyConflictResolver
from hunterx.domain.topology.correlator import TopologyCorrelator
from hunterx.domain.topology.deriver import RelationshipDeriver
from hunterx.domain.topology.enums import TopologyStatus
from hunterx.domain.topology.history import TopologyHistory
from hunterx.domain.topology.models import (
    GraphRelationship,
    RelationshipObservation,
    TopologyBatch,
    TopologyCluster,
    TopologyExecutionSummary,
    TopologySourceData,
    TopologyTarget,
)
from hunterx.domain.topology.normalizer import TopologyNormalizer
from hunterx.domain.topology.scope import TopologyScopeEnforcer, TopologyScopePolicy
from hunterx.domain.topology.strategy import TopologyStrategy, TopologyStrategyBuilder
from hunterx.domain.topology.validator import TopologyValidator
from hunterx.domain.topology.views import TopologyViewBuilder
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

#: Topology TIDB entity classes whose repositories the service reads.
_SOURCE_ENTITY_CLASSES = {
    "organizations": None,
    "targets": None,
    "domains": Domain,
    "subdomains": Subdomain,
    "hostnames": Hostname,
    "ip_addresses": IPAddress,
    "cidrs": CIDR,
    "asns": ASN,
    "ports": Port,
    "services": Service,
    "certificates": Certificate,
    "nameservers": Nameserver,
    "mx_records": MXRecord,
    "dns_records": DNSRecord,
    "technology_observations": TechnologyObservation,
}


class TopologyService:
    """Run topology build missions against the TIDB + Tool SDK."""

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        scope: TopologyScopePolicy | None = None,
        strategy_builder: TopologyStrategyBuilder | None = None,
        deriver: RelationshipDeriver | None = None,
        correlator: TopologyCorrelator | None = None,
        confidence: TopologyConfidenceEngine | None = None,
        history: TopologyHistory | None = None,
        analyzer: TopologyAnalyzer | None = None,
        validator: TopologyValidator | None = None,
        conflicts: TopologyConflictResolver | None = None,
        normalizer: TopologyNormalizer | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._scope = scope or TopologyScopePolicy()
        self._confidence = confidence or TopologyConfidenceEngine()
        self._normalizer = normalizer or TopologyNormalizer()
        self._strategy_builder = strategy_builder or TopologyStrategyBuilder()
        self._deriver = deriver or RelationshipDeriver(normalizer=self._normalizer, confidence=self._confidence)
        self._correlator = correlator or TopologyCorrelator(confidence=self._confidence)
        self._history = history or TopologyHistory()
        self._analyzer = analyzer or TopologyAnalyzer(confidence=self._confidence)
        self._validator = validator or TopologyValidator()
        self._conflicts = conflicts or TopologyConflictResolver(confidence=self._confidence)
        self._scope_enforcer = TopologyScopeEnforcer(self._scope)

    # -- public API ---------------------------------------------------------

    def run(
        self,
        *,
        mission_id: str = "",
        target_key: str,
        target_id: str = "",
        mode: str = "full",
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        with_routes: bool = True,
        with_history: bool = True,
        historical: Sequence[GraphRelationship] | None = None,
        targets: Sequence[Any] | None = None,
    ) -> TopologyBatch:
        """Run a topology build and return the correlated batch.

        Args:
            mission_id: owning mission id.
            target_key: canonical target key (usually ``domain:example.com``).
            target_id: owning target id when known (enables scoped reads).
            mode: build mode (full or incremental).
            tools: topology tool ids to execute (e.g. ``traceroute``).
            parameters: tool parameters merged into execution contexts.
            with_routes: derive ROUTES_TO edges from route tools.
            with_history: diff against ``historical`` (or persisted state).
            historical: previous canonical edges to compare against.
            targets: owning :class:`Target` entities (for ``belongs_to`` edges).

        """
        started = utcnow_iso()
        strategy = self._strategy_builder.build(
            target_key=target_key,
            mode=mode,
            scope=self._scope,
            tools=list(tools or []),
            tool_parameters=dict(parameters or {}),
        )
        correlation_id = generate_id()
        target = TopologyTarget(
            target_id=target_id or "",
            label=target_key,
            mode=strategy.mode,
            correlation_id=correlation_id,
        )
        batch = TopologyBatch(target=target, started_at=started)
        self._publish(
            TopologyBuildStartedEvent(
                mission_id,
                correlation_id,
                target_key,
                mode=strategy.mode,
                tools=strategy.tools,
            )
        )

        try:
            data = self._collect(target_id=target_id, mission_id=mission_id)
            if targets:
                data.targets = list(targets)
            batch.entities_processed = data.entity_count()

            observations: list[RelationshipObservation] = []
            per_source: dict[str, TopologyExecutionSummary] = {}

            if strategy.tools and with_routes:
                for tool_id in strategy.tools:
                    tool_observations, summary = self._run_tool(
                        tool_id,
                        target,
                        mission_id,
                        correlation_id,
                        strategy,
                    )
                    observations.extend(tool_observations)
                    per_source[tool_id] = summary

            derived = self._deriver.derive(
                data,
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
            for obs in derived:
                obs.in_scope = self._scope_enforcer.check(obs.source.kind, obs.source.name).in_scope or self._scope_enforcer.check(
                    obs.target.kind, obs.target.name
                ).in_scope
            observations.extend(derived)
            batch.relationships_processed = len(observations)
            per_source["tidb"] = TopologyExecutionSummary(
                source_name="tidb", observations=len(derived), relationships=len(derived)
            )

            # Scope boundary: when third-party endpoints are disallowed, fully
            # out-of-scope observations are excluded rather than promoted. This
            # guarantees the graph never silently expands mission scope.
            if not self._scope.allow_third_party:
                observations = [obs for obs in observations if obs.in_scope]

            valid, _invalid = self._validator.validate_all(observations)
            valid = [obs for obs in valid if strategy.allows(obs.rel_type)]

            edges = self._correlator.correlate(
                valid,
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
            batch.relationships = edges

            conflicts = self._conflicts.detect(
                valid,
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
            batch.conflicts = conflicts

            self._publish(
                TopologyEntityCorrelatedEvent(
                    mission_id,
                    correlation_id,
                    entities=batch.entities_processed,
                    relationships=len(edges),
                )
            )
            for conflict in conflicts:
                self._publish(
                    TopologyConflictDetectedEvent(
                        correlation_id,
                        conflict.key,
                        conflict.conflict_type.value,
                        [o.get("rel_type", "") for o in conflict.observations],
                        selected=conflict.selected_value,
                        mission_id=mission_id,
                    )
                )

            if with_history:
                previous_map = self._load_previous(target_key, mission_id, historical)
                current_map = {edge.key: edge for edge in edges}
                merged, changes = self._history.diff(
                    previous_map,
                    current_map,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                )
                batch.relationships = merged
                batch.changes = changes

            self._publish(
                TopologyAnalysisStartedEvent(mission_id, correlation_id, target_key)
            )
            analysis = self._analyzer.analyze(
                batch.relationships,
                now=utcnow_iso(),
                stale_days=strategy.stale_days,
                node_keys=self._collect_node_keys(data),
                mission_id=mission_id,
                correlation_id=correlation_id,
            )
            batch.analysis = analysis
            batch.clusters = analysis.clusters

            for edge in analysis.shared_relationships:
                batch.relationships.append(edge)
            self._publish(
                TopologyAnalysisCompletedEvent(
                    mission_id,
                    correlation_id,
                    node_count=analysis.node_count,
                    relationship_count=analysis.relationship_count,
                    cluster_count=analysis.cluster_count,
                )
            )
            for cluster in analysis.clusters:
                self._publish(
                    TopologyClusterCreatedEvent(
                        correlation_id,
                        cluster.cluster_type.value,
                        cluster.name,
                        cluster.entity_keys,
                        mission_id=mission_id,
                    )
                )

            if self._stores is not None:
                self._persist(
                    batch,
                    mission_id=mission_id,
                    target_id=target_id,
                    started_at=started,
                )

            self._emit_relationship_events(batch, mission_id, correlation_id)
            batch.per_source = [
                per_source[name] for name in sorted(per_source, key=str)
            ]
            batch.status = TopologyStatus.COMPLETED
            batch.completed_at = utcnow_iso()
            self._publish(
                TopologyBuildCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=target_key,
                    entities_processed=batch.entities_processed,
                    relationships_processed=batch.relationships_processed,
                    new_relationships=batch.new_relationships,
                    updated_relationships=batch.updated_relationships,
                    removed_relationships=batch.removed_relationships,
                    conflicts=len(batch.conflicts),
                )
            )
            return batch

        except Exception as exc:  # noqa: BLE001 - failures are reported, not fatal
            batch.status = TopologyStatus.FAILED
            batch.completed_at = utcnow_iso()
            self._publish(
                TopologyBuildFailedEvent(
                    mission_id,
                    correlation_id,
                    target_key,
                    str(exc),
                )
            )
            raise

    # -- helpers ------------------------------------------------------------

    def _run_tool(
        self,
        tool_id: str,
        target: TopologyTarget,
        mission_id: str,
        correlation_id: str,
        strategy: TopologyStrategy,
    ) -> tuple[list[RelationshipObservation], TopologyExecutionSummary]:
        """Run one topology tool and convert its route records to observations."""
        merged = dict(strategy.tool_parameters.get(tool_id, {}))
        if target.target_id:
            merged["target_id"] = target.target_id
        context = (
            ExecutionContextBuilder(tool_id=tool_id, target=target.label)
            .with_mission(mission_id)
            .with_target_type("domain")
            .with_profile("topology")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )
        outcome = self._engine.execute(context)
        result = outcome.result
        records: list[RelationshipObservation] = []
        if result.status.is_success and isinstance(result.output.json, dict):
            from hunterx.tools.topology.models import routes_from_payload, routes_to_observations

            route_records = routes_from_payload(result.output.json)
            for obs in routes_to_observations(
                route_records,
                mission_id=mission_id,
                correlation_id=correlation_id,
                execution_id=result.execution_id,
            ):
                obs.in_scope = self._scope_enforcer.check(obs.source.kind, obs.source.name).in_scope or self._scope_enforcer.check(
                    obs.target.kind, obs.target.name
                ).in_scope
                records.append(obs)
        summary = TopologyExecutionSummary(
            source_name=tool_id,
            observations=len(records),
            relationships=len(records),
        )
        return records, summary

    def _collect(self, *, target_id: str, mission_id: str) -> TopologySourceData:
        """Collect TIDB entities into a :class:`TopologySourceData`.

        The topology is derived from the canonical TIDB as a whole; scope
        authorization is applied per-observation by the scope enforcer rather
        than by dropping entities here (dropping hierarchy entities such as
        subdomains/ports/services would corrupt the derivation). Mission/target
        scoping is enforced at query and persistence time.
        """
        data = TopologySourceData()
        if self._stores is None:
            return data
        for field_name, entity_cls in _SOURCE_ENTITY_CLASSES.items():
            if entity_cls is None:
                continue
            repo = self._stores.repository_for(entity_cls)
            setattr(data, field_name, list(repo.stream()))
        return data

    def _load_previous(
        self,
        target_key: str,
        mission_id: str,
        historical: Sequence[GraphRelationship] | None,
    ) -> dict[str, GraphRelationship]:
        """Return the previous topology for history comparison."""
        if historical is not None:
            return {edge.key: edge for edge in historical}
        if self._stores is None:
            return {}
        repo = self._stores.repository_for(TidbRelationship)
        edges: dict[str, GraphRelationship] = {}
        for entity in repo.stream():
            if entity.deleted_at is not None:
                continue
            edges[entity.relationship_key] = GraphRelationship.from_tidb(entity)
        return edges

    def _collect_node_keys(self, data: TopologySourceData) -> set[str]:
        """Collect every canonical node key from the source entities."""
        keys: set[str] = set()
        for name in ("domains", "subdomains", "hostnames", "ip_addresses", "cidrs", "asns", "nameservers", "mx_records"):
            for entity in getattr(data, name):
                value = getattr(entity, "name", None) or getattr(entity, "address", None) or getattr(entity, "network", None)
                if value:
                    kind = _NODE_KIND_BY_FIELD.get(name)
                    if kind:
                        keys.add(self._normalizer.normalize_entity(kind, value).key)
        return keys

    def _persist(
        self,
        batch: TopologyBatch,
        *,
        mission_id: str,
        target_id: str,
        started_at: str,
    ) -> int:
        """Persist topology entities into the TIDB; returns rows written."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist topology without TIDB stores")

        rel_repo = stores.repository_for(TidbRelationship)
        written = rel_repo.save_many([edge.to_tidb() for edge in batch.relationships])

        conflict_repo = stores.repository_for(TidbConflict)
        conflict_repo.save_many([conflict.to_tidb() for conflict in batch.conflicts])

        change_repo = stores.repository_for(TidbChange)
        change_repo.save_many([change.to_tidb() for change in batch.changes])

        cluster_repo = stores.repository_for(TidbCluster)
        cluster_repo.save_many([cluster.to_tidb() for cluster in batch.clusters])

        build = TopologyBuild(
            mission_id=mission_id,
            target_key=batch.target.label,
            status=batch.status,
            entities_processed=batch.entities_processed,
            relationships_processed=batch.relationships_processed,
            new_relationships=batch.new_relationships,
            updated_relationships=batch.updated_relationships,
            removed_relationships=batch.removed_relationships,
            conflicts=len(batch.conflicts),
            started_at=started_at,
            completed_at=batch.completed_at or utcnow_iso(),
            summary={
                "node_count": batch.analysis.node_count,
                "cluster_count": batch.analysis.cluster_count,
                "density": batch.analysis.density,
            },
            correlation_id=batch.target.correlation_id,
        )
        build_repo = stores.repository_for(TopologyBuild)
        build_repo.save(build)
        return written

    def _emit_relationship_events(self, batch: TopologyBatch, mission_id: str, correlation_id: str) -> None:
        """Publish discovered/updated/removed events for relationship changes."""
        changes_by_type: dict[str, list[Any]] = {"new": [], "changed": [], "removed": []}
        for change in batch.changes:
            if change.change_type in changes_by_type:
                changes_by_type[change.change_type].append(change)

        for change in changes_by_type["new"]:
            edge = next((e for e in batch.relationships if e.key == change.key), None)
            if edge is None:
                continue
            self._publish(
                TopologyRelationshipDiscoveredEvent(
                    correlation_id,
                    edge.key,
                    edge.rel_type.value,
                    edge.source.key,
                    edge.target.key,
                    mission_id=mission_id,
                )
            )
        for change in changes_by_type["changed"]:
            edge = next((e for e in batch.relationships if e.key == change.key), None)
            if edge is None:
                continue
            self._publish(
                TopologyRelationshipUpdatedEvent(
                    correlation_id,
                    edge.key,
                    edge.rel_type.value,
                    edge.source.key,
                    edge.target.key,
                    mission_id=mission_id,
                )
            )
        for change in changes_by_type["removed"]:
            self._publish(
                TopologyRelationshipRemovedEvent(
                    correlation_id,
                    change.key,
                    "",
                    "",
                    "",
                    mission_id=mission_id,
                )
            )

    def _publish(self, event: Any) -> None:
        """Publish an event when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


#: Maps TopologySourceData field names to entity kinds for node-key collection.
_NODE_KIND_BY_FIELD: dict[str, str] = {
    "domains": "domain",
    "subdomains": "subdomain",
    "hostnames": "hostname",
    "ip_addresses": "ip",
    "cidrs": "cidr",
    "asns": "asn",
    "nameservers": "nameserver",
    "mx_records": "mx",
}


class TopologyQueryService:
    """Answer canonical topology queries from persisted TIDB relationships."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        cache: CachePort | None = None,
        analyzer: TopologyAnalyzer | None = None,
        views: TopologyViewBuilder | None = None,
        confidence: TopologyConfidenceEngine | None = None,
    ) -> None:
        self._stores = stores
        self._cache = cache
        self._analyzer = analyzer or TopologyAnalyzer(confidence=confidence or TopologyConfidenceEngine())
        self._views = views or TopologyViewBuilder()

    def graph(self, *, mission_id: str = "") -> Any:
        """Return a :class:`TopologyGraph` built from persisted relationships."""
        from hunterx.domain.topology.graph import TopologyGraph

        relationships = self._relationships(mission_id=mission_id)
        return TopologyGraph(relationships)

    def neighbors(self, key: str, *, mission_id: str = "") -> list[dict]:
        """Return adjacent nodes of ``key``."""
        return self.graph(mission_id=mission_id).neighbors(key)

    def ancestors(self, key: str, *, mission_id: str = "", max_depth: int = 0) -> set[str]:
        """Return ancestors of ``key``."""
        return self.graph(mission_id=mission_id).ancestors(key, max_depth=max_depth)

    def descendants(self, key: str, *, mission_id: str = "", max_depth: int = 0) -> set[str]:
        """Return descendants of ``key``."""
        return self.graph(mission_id=mission_id).descendants(key, max_depth=max_depth)

    def shortest_path(
        self,
        source_key: str,
        target_key: str,
        *,
        mission_id: str = "",
        rel_types: Sequence[str] | None = None,
        max_depth: int = 0,
    ) -> list[str]:
        """Return the shortest relationship path between two nodes."""
        return self.graph(mission_id=mission_id).shortest_path(
            source_key, target_key, rel_types=rel_types, max_depth=max_depth
        )

    def related_assets(self, key: str, *, mission_id: str = "", max_depth: int = 3) -> list[str]:
        """Return assets connected to ``key`` within ``max_depth`` hops."""
        graph = self.graph(mission_id=mission_id)
        return sorted(
            graph.descendants(key, max_depth=max_depth) | graph.ancestors(key, max_depth=max_depth)
        )

    def shared_infrastructure(self, keys: Sequence[str], *, mission_id: str = "") -> list[dict]:
        """Return SHARES_* relationships connecting the given asset keys."""
        from hunterx.domain.topology.paths import TopologyPathFinder

        finder = TopologyPathFinder(self.graph(mission_id=mission_id))
        return [edge.as_dict() for edge in finder.shared_infrastructure(keys)]

    def asset_cluster(self, key: str, *, mission_id: str = "") -> list[dict]:
        """Return clusters containing ``key``."""
        clusters = self._clusters(mission_id=mission_id)
        return [cluster.as_dict() for cluster in clusters if key in cluster.entity_keys]

    def service_cluster(self, ip_key: str, *, mission_id: str = "") -> list[dict]:
        """Return service clusters hosted on ``ip_key``."""
        clusters = self._clusters(mission_id=mission_id)
        return [
            cluster.as_dict()
            for cluster in clusters
            if cluster.cluster_type.value == "service" and ip_key in cluster.entity_keys
        ]

    def certificate_relationships(self, cert_key: str, *, mission_id: str = "") -> list[dict]:
        """Return edges incident to a certificate node."""
        return [edge.as_dict() for edge in self.graph(mission_id=mission_id).incoming(cert_key)]

    def network_relationships(self, cidr_key: str, *, mission_id: str = "") -> list[dict]:
        """Return network-layer edges incident to a CIDR node."""
        return [edge.as_dict() for edge in self.graph(mission_id=mission_id).outgoing(cidr_key)]

    def historical_relationships(self, key: str = "", *, mission_id: str = "") -> list[dict]:
        """Return persisted topology changes, optionally filtered by key."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbChange)
        changes = list(repo.stream())
        if key:
            changes = [change for change in changes if change.key == key]
        return [_change_dict(change) for change in changes]

    def attack_surface(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return the external attack-surface view."""
        return self._views.external_attack_surface(self._relationships(mission_id=mission_id))

    def network_graph(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return the network topology view."""
        return self._views.network_graph(self._relationships(mission_id=mission_id))

    def dns_graph(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return the DNS topology view."""
        return self._views.dns_graph(self._relationships(mission_id=mission_id))

    def service_graph(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return the service topology view."""
        return self._views.service_graph(self._relationships(mission_id=mission_id))

    def certificate_graph(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return the certificate topology view."""
        return self._views.certificate_graph(self._relationships(mission_id=mission_id))

    def organization_graph(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return the organization infrastructure view."""
        return self._views.organization_graph(self._relationships(mission_id=mission_id))

    def analysis(self, *, mission_id: str = "") -> dict[str, Any]:
        """Return the analysis summary for the current topology."""
        relationships = self._relationships(mission_id=mission_id)
        result = self._analyzer.analyze(relationships, now=utcnow_iso(), mission_id=mission_id)
        return result.as_dict()

    # -- helpers ------------------------------------------------------------

    def _relationships(self, *, mission_id: str = "") -> list[GraphRelationship]:
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbRelationship)
        relationships: list[GraphRelationship] = []
        for entity in repo.stream():
            if entity.deleted_at is not None:
                continue
            if mission_id and entity.mission_id != mission_id:
                continue
            relationships.append(GraphRelationship.from_tidb(entity))
        return relationships

    def _clusters(self, *, mission_id: str = "") -> list[TopologyCluster]:
        if self._stores is None:
            return []
        repo = self._stores.repository_for(TidbCluster)
        clusters: list[TopologyCluster] = []
        for entity in repo.stream():
            if entity.deleted_at is not None:
                continue
            if mission_id and entity.mission_id != mission_id:
                continue
            clusters.append(
                TopologyCluster(
                    name=entity.name,
                    cluster_type=entity.cluster_type,
                    entity_keys=list(entity.entity_keys),
                    metric=entity.metric,
                    detected_by=entity.detected_by,
                    mission_id=entity.mission_id,
                    correlation_id=entity.correlation_id,
                )
            )
        return clusters


def _change_dict(change: Any) -> dict[str, Any]:
    return {
        "kind": change.kind,
        "key": change.key,
        "change_type": change.change_type,
        "old_value": change.old_value,
        "new_value": change.new_value,
        "tool_id": change.tool_id,
        "confidence": change.confidence,
        "mission_id": change.mission_id,
        "correlation_id": change.correlation_id,
        "created_at": change.created_at,
    }
