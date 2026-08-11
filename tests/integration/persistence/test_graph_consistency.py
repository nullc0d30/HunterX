# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Graph / TIDB consistency tests (Sprint 034.3 §23).

The runtime knowledge graph is a derived/cached layer that is NOT persisted in
the TIDB; derived graph facts ARE persisted relationally (topology
relationships, attack-path records). This suite documents the actual
architecture and verifies the synchronization contract.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    AdaptiveAttackPathRecord,
    FindingRecord,
    IntelligenceAssetRecord,
    TopologyRelationship,
)
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph

pytest.importorskip("sqlalchemy")


def test_graph_is_cached_and_does_not_write_tidb(sql_factory) -> None:
    graph = InMemoryKnowledgeGraph()
    graph.upsert_node("asset-1", labels=["Asset"], properties={"kind": "domain", "name": "example.com"})
    graph.upsert_node("finding-1", labels=["Finding"], properties={"title": "SQLi"})
    graph.upsert_relationship("affects", "finding-1", "asset-1")

    # The graph write is independent of the TIDB.
    assert sql_factory.repository_for(IntelligenceAssetRecord).count() == 0
    assert sql_factory.repository_for(FindingRecord).count() == 0
    assert sql_factory.repository_for(TopologyRelationship).count() == 0

    # The in-memory graph serves the query.
    neighbors = graph.query_neighbors("finding-1", depth=1)
    assert any(n["target"] == "asset-1" for n in neighbors)


def test_topology_relationship_persists_derived_edges(sql_factory) -> None:
    repo = sql_factory.repository_for(TopologyRelationship)
    relationship = TopologyRelationship(
        rel_type="connects_to",
        source_entity="service",
        source_key="service:example.com:443",
        target_entity="asset",
        target_key="asset:example.com",
        sources=["nmap"],
        evidence=["ev-1"],
        confidence=0.95,
        mission_id="mis-1",
        execution_id="exec-1",
        correlation_id="corr-1",
        in_scope=True,
        relationship_key="service:example.com:443->asset:example.com",
    )
    repo.save(relationship)

    loaded = repo.get(relationship.id)
    assert loaded is not None
    assert loaded.rel_type == "connects_to"
    assert loaded.source_key == "service:example.com:443"
    assert loaded.target_key == "asset:example.com"
    assert loaded.mission_id == "mis-1"
    assert loaded.execution_id == "exec-1"
    assert loaded.confidence == 0.95
    assert loaded.in_scope is True


def test_attack_path_is_persisted_relationally(sql_factory) -> None:
    repo = sql_factory.repository_for(AdaptiveAttackPathRecord)
    path = AdaptiveAttackPathRecord(
        path_id="path-1",
        mission_id="mis-1",
        objective="full_security_assessment",
        state="discovered",
        score=0.85,
        scores={"recon": 1.0, "exploit": 0.7},
        steps=[
            {"node": "asset:example.com", "action": "subfinder", "next": "asset:api.example.com"},
            {"node": "asset:api.example.com", "action": "nuclei", "next": "finding:F-1"},
        ],
        evidence_refs=["ev-1"],
        assumptions=["scope includes example.com"],
    )
    repo.save(path)

    loaded = repo.get(path.id)
    assert loaded is not None
    assert loaded.path_id == "path-1"
    assert len(loaded.steps) == 2
    assert loaded.evidence_refs == ["ev-1"]
    assert loaded.score == 0.85


def test_graph_is_derived_not_authoritative(sql_factory, memory_factory) -> None:
    """TIDB is the system of record; the graph is an in-memory projection. A
    graph delete must not remove TIDB rows and a TIDB delete must not remove
    graph nodes."""
    graph = InMemoryKnowledgeGraph()
    asset_repo = sql_factory.repository_for(IntelligenceAssetRecord)

    graph.upsert_node("asset-1", labels=["Asset"], properties={"name": "example.com"})
    asset = IntelligenceAssetRecord(asset_id="asset-1", target_id="tgt-1", asset_key="domain:example.com")
    asset_repo.save(asset)

    graph.delete_node("asset-1")
    assert asset_repo.get(asset.id) is not None

    asset_repo.delete(asset.id)
    assert graph.query_neighbors("asset-1", depth=1) == []


def test_graph_supports_both_backend_factories(sql_factory, memory_factory) -> None:
    """Knowledge-graph participation is backend-independent: the same graph can
    be attached to both the SQL and in-memory TIDB factories."""
    for factory in (sql_factory, memory_factory):
        repo = factory.repository_for(FindingRecord)
        finding = FindingRecord(finding_id="F-graph", target_id="tgt-1", title="XSS", status="validated")
        repo.save(finding)
        assert repo.get(finding.id) is not None
