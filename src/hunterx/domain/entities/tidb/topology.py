# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Network mapping & attack-surface topology TIDB entities.

System-of-record entities for the Sprint 010 topology capability. The topology
is a *derived* state over the canonical TIDB: relationships, conflicts,
changes, clusters and build records are persisted here so queries, reporting
and history are reproducible without ever introducing a second database.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class TopologyRelationship(TidbEntity):
    """A persisted canonical relationship between two TIDB entities.

    Attributes:
        rel_type: relationship type (one of :class:`RelationshipType` values).
        source_entity: entity kind of the source node.
        source_key: canonical key of the source node (``kind:name``).
        source_id: TIDB id of the source node when known.
        target_entity: entity kind of the target node.
        target_key: canonical key of the target node.
        target_id: TIDB id of the target node when known.
        sources: provenance sources that reported the relationship.
        evidence: merged evidence map (per-source details).
        confidence: merged confidence in ``[0, 1]``.
        mission_id: owning mission.
        execution_id: owning tool execution when tool-derived.
        correlation_id: correlation id of the producing run.
        in_scope: whether both endpoints fall inside the authorized scope.
        relationship_key: stable dedup key (``rel:src|dst``).

    """

    rel_type: str
    source_entity: str
    source_key: str
    target_entity: str
    target_key: str
    sources: list[str] = field(default_factory=list)
    evidence: dict[str, object] = field(default_factory=dict)
    confidence: float = 1.0
    source_id: str | None = None
    target_id: str | None = None
    mission_id: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    in_scope: bool = True
    relationship_key: str = ""


@dataclass(slots=True)
class TopologyConflict(TidbEntity):
    """A preserved contradiction found while correlating relationships.

    Attributes:
        kind: subject kind (usually ``relationship``).
        key: relationship/subject key the conflict concerns.
        observations: the disagreeing observations.
        conflict_type: conflict category (value/source/target/type).
        selected_value: value chosen for the canonical edge.
        selected_source: provenance of the selected value.
        reason: human-readable resolution rationale.
        confidence: confidence of the selected value.
        mission_id: owning mission.
        correlation_id: correlation id of the detecting run.

    """

    kind: str = "relationship"
    key: str = ""
    observations: list[dict[str, object]] = field(default_factory=list)
    conflict_type: str = "value"
    selected_value: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class TopologyChange(TidbEntity):
    """A temporal change in the derived topology.

    Attributes:
        kind: subject kind (usually ``relationship``).
        key: relationship/subject key that changed.
        change_type: ``new``, ``removed`` or ``changed``.
        old_value: previous canonical value (JSON-ish text).
        new_value: new canonical value (JSON-ish text).
        tool_id: tool that produced the change when applicable.
        confidence: confidence of the new value.
        mission_id: owning mission.
        correlation_id: correlation id of the detecting run.

    """

    kind: str = "relationship"
    key: str = ""
    change_type: str = "new"
    old_value: str = ""
    new_value: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class TopologyCluster(TidbEntity):
    """A group of assets sharing a common attribute (shared infra).

    Attributes:
        name: cluster label.
        cluster_type: cluster category (same_ip/same_cert/...).
        entity_keys: canonical keys of the clustered entities.
        metric: per-cluster measurements (members, shared value).
        detected_by: analysis that detected the cluster.
        mission_id: owning mission.
        correlation_id: correlation id of the detecting run.

    """

    name: str = ""
    cluster_type: str = "same_ip"
    entity_keys: list[str] = field(default_factory=list)
    metric: dict[str, object] = field(default_factory=dict)
    detected_by: str = "topology.analysis"
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class TopologyBuild(TidbEntity):
    """Observability record for a topology build run.

    Attributes:
        mission_id: owning mission.
        target_key: canonical key of the target the build covered.
        status: run status (running/completed/failed/partial).
        entities_processed: number of TIDB entities consumed.
        relationships_processed: number of raw observations correlated.
        new_relationships: canonical edges created.
        updated_relationships: canonical edges updated.
        removed_relationships: canonical edges removed.
        conflicts: conflicts detected and preserved.
        started_at: build start stamp.
        completed_at: build completion stamp (``None`` while running).
        duration_ms: wall-clock duration in milliseconds.
        summary: free-form summary of the run.
        correlation_id: correlation id of the run.

    """

    mission_id: str = ""
    target_key: str = ""
    status: str = "running"
    entities_processed: int = 0
    relationships_processed: int = 0
    new_relationships: int = 0
    updated_relationships: int = 0
    removed_relationships: int = 0
    conflicts: int = 0
    started_at: str = ""
    completed_at: str | None = None
    duration_ms: int = 0
    summary: dict[str, object] = field(default_factory=dict)
    correlation_id: str = ""
