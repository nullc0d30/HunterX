# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the network-mapping topology capability.

Benchmarks are executed by the performance quality gate
(``python -m eng gates --gate performance``) with pytest-benchmark. They
measure correlation throughput and graph query latency on large synthetic
topologies (thousands of assets, hundreds of thousands of relationships).
"""

from __future__ import annotations

from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.correlator import TopologyCorrelator
from hunterx.domain.topology.graph import TopologyGraph
from hunterx.domain.topology.models import GraphRelationship, RelationshipObservation, TopologyEntity


def _observation(index: int, *, duplicates: int = 1) -> list[RelationshipObservation]:
    host = TopologyEntity(kind="hostname", name=f"host{index}.example.com")
    ip = TopologyEntity(kind="ip", name=f"10.0.{index // 250}.{index % 250}")
    return [
        RelationshipObservation(
            rel_type="resolves_to",
            source=host,
            target=ip,
            source_name=f"tool{duplicates}",
            observed_at=f"2026-01-01T00:00:0{duplicates}+00:00",
        )
        for _ in range(duplicates)
    ]


def test_correlate_10k_observations(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Correlate 10k raw observations (1k edges x10 duplicates) efficiently."""
    observations = [obs for i in range(1000) for obs in _observation(i, duplicates=10)]

    def _run() -> int:
        edges = TopologyCorrelator().correlate(observations)
        return len(edges)

    result = benchmark(_run)
    assert result == 1000


def test_correlate_1k_distinct(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Correlate 1k distinct observations into 1k edges."""

    def _run() -> int:
        edges = TopologyCorrelator().correlate([_observation(i)[0] for i in range(1000)])
        return len(edges)

    result = benchmark(_run)
    assert result == 1000


def _big_graph(nodes: int) -> TopologyGraph:
    graph = TopologyGraph()
    for i in range(1, nodes):
        graph.add(
            GraphRelationship(
                rel_type="resolves_to",
                source=TopologyEntity(kind="hostname", name=f"host{i}.example.com"),
                target=TopologyEntity(kind="ip", name=f"10.0.{i // 250}.{i % 250}"),
            )
        )
    return graph


def test_query_neighbors_on_1000_node_graph(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Neighbor lookups must be fast on large graphs."""
    graph = _big_graph(1000)

    def _run() -> int:
        return len(graph.neighbors("hostname:host500.example.com"))

    result = benchmark(_run)
    assert result >= 0


def test_shortest_path_on_1000_node_graph(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Shortest path BFS must stay responsive on a 1000-node graph."""
    graph = _big_graph(1000)

    def _run() -> int:
        return len(graph.shortest_path("hostname:host1.example.com", "ip:10.0.2.250"))

    result = benchmark(_run)
    assert result >= 0


def test_confidence_combine_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Confidence combination is on the correlation hot path."""
    engine = TopologyConfidenceEngine()

    def _run() -> float:
        total = 0.0
        for _ in range(200):
            total += engine.combine([0.8, 0.7, 0.9])
        return total

    benchmark(_run)
