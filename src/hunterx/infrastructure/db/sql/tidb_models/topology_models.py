# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB topology entities (relationships, conflicts, clusters)."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class TopologyRelationshipModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.topology.TopologyRelationship`."""

    __tablename__ = "tidb_topology_relationships"

    rel_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_entity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    target_entity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    sources: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    source_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    execution_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    relationship_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)

    __table_args__ = (
        Index("ix_tidb_topology_rel_key_type", "relationship_key", "rel_type"),
        Index("ix_tidb_topology_rel_source", "source_entity", "source_key"),
        Index("ix_tidb_topology_rel_target", "target_entity", "target_key"),
    )


class TopologyConflictModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.topology.TopologyConflict`."""

    __tablename__ = "tidb_topology_conflicts"

    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="relationship", index=True)
    key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    observations: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    conflict_type: Mapped[str] = mapped_column(String(32), nullable=False, default="value")
    selected_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    selected_source: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class TopologyChangeModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.topology.TopologyChange`."""

    __tablename__ = "tidb_topology_changes"

    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="relationship", index=True)
    key: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False, default="new", index=True)
    old_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    new_value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tool_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class TopologyClusterModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.topology.TopologyCluster`."""

    __tablename__ = "tidb_topology_clusters"

    name: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    cluster_type: Mapped[str] = mapped_column(String(32), nullable=False, default="same_ip", index=True)
    entity_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metric: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    detected_by: Mapped[str] = mapped_column(String(255), nullable=False, default="topology.analysis")
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)


class TopologyBuildModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.topology.TopologyBuild`."""

    __tablename__ = "tidb_topology_builds"

    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_key: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", index=True)
    entities_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    relationships_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_relationships: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_relationships: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    removed_relationships: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    completed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
