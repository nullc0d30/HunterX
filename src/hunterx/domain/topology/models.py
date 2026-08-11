# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology domain models.

Pure data structures for the network-mapping capability: canonical nodes,
raw relationship observations, correlated graph edges, conflicts, changes,
clusters, analysis results and build batches. These are free of I/O; the
application layer bridges them to/from TIDB system-of-record entities.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.topology.enums import (
    ClusterType,
    ConflictType,
    EntityKind,
    RelationshipType,
)
from hunterx.domain.topology.keys import relationship_key

#: JSON-ish payload keys used by build records and views.
PAYLOAD_TYPE = dict[str, Any]


@dataclass(frozen=True, slots=True)
class TopologyEntity:
    """A canonical topology node.

    Attributes:
        kind: entity kind.
        name: canonical name/value of the entity.
        key: stable canonical key (``kind:name``); derived when omitted.
        entity_id: TIDB entity id when the node maps to a stored entity.
        label: optional human label.
        meta: optional node attributes.

    """

    kind: EntityKind | str
    name: str
    key: str = ""
    entity_id: str | None = None
    label: str = ""
    meta: dict[str, Any] = field(default_factory=dict, kw_only=True)

    def __post_init__(self) -> None:
        kind = str(self.kind) if isinstance(self.kind, EntityKind) else self.kind
        object.__setattr__(self, "kind", EntityKind(kind))
        if not self.key:
            from hunterx.domain.topology.keys import entity_key

            object.__setattr__(self, "key", entity_key(self.kind.value, self.name))
        if not self.label:
            object.__setattr__(self, "label", self.name)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the node to a JSON-safe mapping."""
        return {
            "kind": self.kind.value,
            "name": self.name,
            "key": self.key,
            "entity_id": self.entity_id,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class TopologyTarget:
    """The subject of a topology build run.

    Attributes:
        target_id: owning target identifier.
        label: human label (usually a domain).
        mode: build mode.
        correlation_id: correlation id for the whole run.

    """

    target_id: str
    label: str
    mode: str = "full"
    correlation_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Serialize the target to a JSON-safe mapping."""
        return {
            "target_id": self.target_id,
            "label": self.label,
            "mode": self.mode,
            "correlation_id": self.correlation_id,
        }


@dataclass(slots=True)
class TopologySourceData:
    """TIDB entities collected for a build, grouped by table.

    The deriver consumes these lists (already scoped and normalized) to produce
    relationship observations. Lists are optional; empty lists yield nothing.
    """

    organizations: list[Any] = field(default_factory=list)
    targets: list[Any] = field(default_factory=list)
    domains: list[Any] = field(default_factory=list)
    subdomains: list[Any] = field(default_factory=list)
    hostnames: list[Any] = field(default_factory=list)
    ip_addresses: list[Any] = field(default_factory=list)
    cidrs: list[Any] = field(default_factory=list)
    asns: list[Any] = field(default_factory=list)
    ports: list[Any] = field(default_factory=list)
    services: list[Any] = field(default_factory=list)
    certificates: list[Any] = field(default_factory=list)
    nameservers: list[Any] = field(default_factory=list)
    mx_records: list[Any] = field(default_factory=list)
    dns_records: list[Any] = field(default_factory=list)
    host_observations: list[Any] = field(default_factory=list)
    port_observations: list[Any] = field(default_factory=list)
    service_observations: list[Any] = field(default_factory=list)
    technology_observations: list[Any] = field(default_factory=list)

    def entity_count(self) -> int:
        """Return the total number of collected entities."""
        return sum(len(getattr(self, name)) for name in self.__dataclass_fields__)

    def __iter__(self) -> Any:  # pragma: no cover - debugging aid
        for name in self.__dataclass_fields__:
            yield name, getattr(self, name)


@dataclass(slots=True)
class RelationshipObservation:
    """A raw, single-source observation of a directed relationship.

    Attributes:
        rel_type: relationship type.
        source: source node.
        target: target node.
        source_name: provenance label (e.g. ``subfinder``, ``nmap``,
            ``tidb:domain``).
        evidence: evidence details for the observation.
        confidence: source confidence in ``[0, 1]``.
        observed_at: observation timestamp (UTC ISO).
        mission_id: owning mission.
        execution_id: tool execution when tool-derived.
        correlation_id: producing run correlation id.
        in_scope: whether both endpoints are authorized.
        attributes: free-form observation attributes.

    """

    rel_type: RelationshipType | str
    source: TopologyEntity
    target: TopologyEntity
    source_name: str = "tidb"
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    observed_at: str = ""
    mission_id: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    in_scope: bool = True
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.rel_type, str):
            self.rel_type = RelationshipType(self.rel_type)
        if not self.observed_at:
            from hunterx.shared.time import utcnow_iso

            self.observed_at = utcnow_iso()

    @property
    def key(self) -> str:
        """Return the stable dedup key of this observation."""
        return relationship_key(self.rel_type.value, self.source.key, self.target.key)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the observation to a JSON-safe mapping."""
        return {
            "rel_type": self.rel_type.value,
            "source": self.source.as_dict(),
            "target": self.target.as_dict(),
            "source_name": self.source_name,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
            "in_scope": self.in_scope,
            "attributes": self.attributes,
        }


@dataclass(slots=True)
class GraphRelationship:
    """A correlated, canonical directed relationship.

    Attributes:
        rel_type: relationship type.
        source: source node.
        target: target node.
        sources: provenance sources that reported the edge.
        evidence: merged evidence.
        confidence: merged confidence in ``[0, 1]``.
        first_seen: earliest observation stamp.
        last_seen: latest observation stamp.
        mission_id: owning mission.
        execution_id: latest tool execution.
        correlation_id: latest producing run.
        in_scope: whether both endpoints are authorized.
        source_id: TIDB id of the source node.
        target_id: TIDB id of the target node.
        attributes: free-form edge attributes.

    """

    rel_type: RelationshipType | str
    source: TopologyEntity
    target: TopologyEntity
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    first_seen: str = ""
    last_seen: str = ""
    mission_id: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    in_scope: bool = True
    source_id: str | None = None
    target_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.rel_type, str):
            self.rel_type = RelationshipType(self.rel_type)
        if not self.first_seen:
            from hunterx.shared.time import utcnow_iso

            self.first_seen = self.last_seen = utcnow_iso()

    @property
    def key(self) -> str:
        """Return the stable dedup key of the edge."""
        return relationship_key(self.rel_type.value, self.source.key, self.target.key)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the edge to a JSON-safe mapping."""
        return {
            "rel_type": self.rel_type.value,
            "source": self.source.as_dict(),
            "target": self.target.as_dict(),
            "sources": list(self.sources),
            "evidence": self.evidence,
            "confidence": round(self.confidence, 4),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
            "in_scope": self.in_scope,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "attributes": self.attributes,
            "key": self.key,
        }

    # -- TIDB bridge --------------------------------------------------------

    def to_tidb(self) -> Any:
        """Convert to a :class:`TopologyRelationship` TIDB entity."""
        from hunterx.domain.entities.tidb.topology import TopologyRelationship

        return TopologyRelationship(
            rel_type=self.rel_type.value,
            source_entity=self.source.kind.value,
            source_key=self.source.key,
            source_id=self.source_id or self.source.entity_id,
            target_entity=self.target.kind.value,
            target_key=self.target.key,
            target_id=self.target_id or self.target.entity_id,
            sources=list(self.sources),
            evidence=self.evidence,
            confidence=self.confidence,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            mission_id=self.mission_id,
            execution_id=self.execution_id,
            correlation_id=self.correlation_id,
            in_scope=self.in_scope,
            relationship_key=self.key,
        )

    @classmethod
    def from_tidb(cls, entity: Any) -> GraphRelationship:
        """Build a graph edge from a :class:`TopologyRelationship` entity."""
        source = TopologyEntity(
            kind=entity.source_entity,
            name=entity.source_key.split(":", 1)[1] if ":" in entity.source_key else entity.source_key,
            key=entity.source_key,
            entity_id=entity.source_id,
        )
        target = TopologyEntity(
            kind=entity.target_entity,
            name=entity.target_key.split(":", 1)[1] if ":" in entity.target_key else entity.target_key,
            key=entity.target_key,
            entity_id=entity.target_id,
        )
        edge = cls(
            rel_type=entity.rel_type,
            source=source,
            target=target,
            sources=list(entity.sources),
            evidence=entity.evidence,
            confidence=entity.confidence,
            first_seen=entity.first_seen or "",
            last_seen=entity.last_seen or "",
            mission_id=entity.mission_id,
            execution_id=entity.execution_id,
            correlation_id=entity.correlation_id,
            in_scope=entity.in_scope,
            source_id=entity.source_id,
            target_id=entity.target_id,
        )
        edge.attributes["id"] = entity.id
        edge.attributes["created_at"] = entity.created_at
        return edge


@dataclass(slots=True)
class TopologyConflict:
    """A preserved contradiction from relationship correlation."""

    key: str
    conflict_type: ConflictType | str = ConflictType.VALUE
    observations: list[dict[str, Any]] = field(default_factory=list)
    selected_value: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    kind: str = "relationship"
    mission_id: str = ""
    correlation_id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.conflict_type, str):
            self.conflict_type = ConflictType(self.conflict_type)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the conflict to a JSON-safe mapping."""
        return {
            "kind": self.kind,
            "key": self.key,
            "conflict_type": self.conflict_type.value,
            "observations": self.observations,
            "selected_value": self.selected_value,
            "selected_source": self.selected_source,
            "reason": self.reason,
            "confidence": round(self.confidence, 4),
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
        }

    def to_tidb(self) -> Any:
        """Convert to a :class:`TopologyConflict` TIDB entity."""
        from hunterx.domain.entities.tidb.topology import TopologyConflict as TidbConflict

        return TidbConflict(
            kind=self.kind,
            key=self.key,
            observations=self.observations,
            conflict_type=self.conflict_type.value,
            selected_value=self.selected_value,
            selected_source=self.selected_source,
            reason=self.reason,
            confidence=self.confidence,
            mission_id=self.mission_id,
            correlation_id=self.correlation_id,
        )


@dataclass(slots=True)
class TopologyChange:
    """A temporal change in a topology subject."""

    key: str
    change_type: str = "new"
    old_value: str = ""
    new_value: str = ""
    kind: str = "relationship"
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Serialize the change to a JSON-safe mapping."""
        return {
            "kind": self.kind,
            "key": self.key,
            "change_type": self.change_type,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "tool_id": self.tool_id,
            "confidence": round(self.confidence, 4),
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
        }

    def to_tidb(self) -> Any:
        """Convert to a :class:`TopologyChange` TIDB entity."""
        from hunterx.domain.entities.tidb.topology import TopologyChange as TidbChange

        return TidbChange(
            kind=self.kind,
            key=self.key,
            change_type=self.change_type,
            old_value=self.old_value,
            new_value=self.new_value,
            tool_id=self.tool_id,
            confidence=self.confidence,
            mission_id=self.mission_id,
            correlation_id=self.correlation_id,
        )


@dataclass(slots=True)
class TopologyCluster:
    """A group of assets sharing a common attribute."""

    name: str
    cluster_type: ClusterType | str
    entity_keys: list[str] = field(default_factory=list)
    metric: dict[str, Any] = field(default_factory=dict)
    detected_by: str = "topology.analysis"
    mission_id: str = ""
    correlation_id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.cluster_type, str):
            self.cluster_type = ClusterType(self.cluster_type)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the cluster to a JSON-safe mapping."""
        return {
            "name": self.name,
            "cluster_type": self.cluster_type.value,
            "entity_keys": list(self.entity_keys),
            "metric": self.metric,
            "detected_by": self.detected_by,
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
        }

    def to_tidb(self) -> Any:
        """Convert to a :class:`TopologyCluster` TIDB entity."""
        from hunterx.domain.entities.tidb.topology import TopologyCluster as TidbCluster

        return TidbCluster(
            name=self.name,
            cluster_type=self.cluster_type.value,
            entity_keys=list(self.entity_keys),
            metric=self.metric,
            detected_by=self.detected_by,
            mission_id=self.mission_id,
            correlation_id=self.correlation_id,
        )


@dataclass(slots=True)
class TopologyAnalysis:
    """Result of analyzing a correlated graph."""

    node_count: int = 0
    relationship_count: int = 0
    orphan_count: int = 0
    dangling_count: int = 0
    unresolved_count: int = 0
    stale_count: int = 0
    cluster_count: int = 0
    density: float = 0.0
    components: int = 0
    largest_component_size: int = 0
    clusters: list[TopologyCluster] = field(default_factory=list)
    shared_relationships: list[GraphRelationship] = field(default_factory=list)
    orphan_keys: list[str] = field(default_factory=list)
    dangling_keys: list[str] = field(default_factory=list)
    stale_keys: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the analysis to a JSON-safe mapping."""
        return {
            "node_count": self.node_count,
            "relationship_count": self.relationship_count,
            "orphan_count": self.orphan_count,
            "dangling_count": self.dangling_count,
            "unresolved_count": self.unresolved_count,
            "stale_count": self.stale_count,
            "cluster_count": self.cluster_count,
            "density": round(self.density, 6),
            "components": self.components,
            "largest_component_size": self.largest_component_size,
            "clusters": [c.as_dict() for c in self.clusters],
            "shared_relationships": [r.as_dict() for r in self.shared_relationships],
            "orphan_keys": list(self.orphan_keys),
            "dangling_keys": list(self.dangling_keys),
            "stale_keys": list(self.stale_keys),
        }


@dataclass(slots=True)
class TopologyExecutionSummary:
    """Per-source/tool statistics for a build."""

    source_name: str
    observations: int = 0
    relationships: int = 0

    def as_dict(self) -> dict[str, Any]:
        """Serialize the summary to a JSON-safe mapping."""
        return {
            "source": self.source_name,
            "observations": self.observations,
            "relationships": self.relationships,
        }


@dataclass(slots=True)
class TopologyBatch:
    """The aggregate result of a topology build run.

    Attributes:
        target: the build target.
        relationships: correlated canonical edges.
        conflicts: preserved conflicts.
        changes: detected temporal changes.
        clusters: detected shared-infrastructure clusters.
        analysis: graph analysis result.
        per_source: per-source execution summaries.
        entities_processed: TIDB entities consumed.
        relationships_processed: raw observations correlated.
        started_at: build start stamp.
        completed_at: build completion stamp.
        status: build status.

    """

    target: TopologyTarget
    relationships: list[GraphRelationship] = field(default_factory=list)
    conflicts: list[TopologyConflict] = field(default_factory=list)
    changes: list[TopologyChange] = field(default_factory=list)
    clusters: list[TopologyCluster] = field(default_factory=list)
    analysis: TopologyAnalysis = field(default_factory=TopologyAnalysis)
    per_source: list[TopologyExecutionSummary] = field(default_factory=list)
    entities_processed: int = 0
    relationships_processed: int = 0
    started_at: str = ""
    completed_at: str = ""
    status: str = "completed"

    @property
    def new_relationships(self) -> int:
        """Number of edges created in this build."""
        return sum(1 for c in self.changes if c.change_type == "new")

    @property
    def updated_relationships(self) -> int:
        """Number of edges updated in this build."""
        return sum(1 for c in self.changes if c.change_type == "changed")

    @property
    def removed_relationships(self) -> int:
        """Number of edges removed in this build."""
        return sum(1 for c in self.changes if c.change_type == "removed")

    def as_dict(self) -> dict[str, Any]:
        """Serialize the batch to a JSON-safe mapping."""
        return {
            "target": self.target.as_dict(),
            "status": self.status,
            "entities_processed": self.entities_processed,
            "relationships_processed": self.relationships_processed,
            "relationships": [r.as_dict() for r in self.relationships],
            "conflicts": [c.as_dict() for c in self.conflicts],
            "changes": [c.as_dict() for c in self.changes],
            "clusters": [c.as_dict() for c in self.clusters],
            "analysis": self.analysis.as_dict(),
            "per_source": [s.as_dict() for s in self.per_source],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


def relationships_from_tidb(entities: Sequence[Any]) -> list[GraphRelationship]:
    """Convert persisted :class:`TopologyRelationship` entities to graph edges."""
    return [GraphRelationship.from_tidb(entity) for entity in entities]


def observations_from_records(records: Mapping[str, Any], *, kind_hint: str = "") -> list[RelationshipObservation]:
    """Convert JSON payload records (e.g. tool ``routes``) to observations.

    Records are expected as a mapping with ``source``, ``target`` and optional
    ``rel_type``/``confidence``/``evidence``/``source_name`` keys.
    """
    observations: list[RelationshipObservation] = []
    rel = records.get("rel_type") or kind_hint
    source_raw = records.get("source")
    target_raw = records.get("target")
    if not rel or not isinstance(source_raw, dict) or not isinstance(target_raw, dict):
        return observations
    observations.append(
        RelationshipObservation(
            rel_type=rel,
            source=TopologyEntity(kind=source_raw.get("kind", "hostname"), name=source_raw.get("name", "")),
            target=TopologyEntity(kind=target_raw.get("kind", "ip"), name=target_raw.get("name", "")),
            source_name=str(records.get("source_name", "tool")),
            evidence=records.get("evidence", {}),
            confidence=float(records.get("confidence", 1.0)),
        )
    )
    return observations
