# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Circular dependency detection.

A directed graph is built from internal import records and Tarjan's
strongly-connected-components algorithm identifies every component with more
than one node — i.e. a dependency cycle. ``TYPE_CHECKING`` imports are excluded
because they never execute, so they cannot form a real runtime cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.architecture.imports import ImportRecord


@dataclass(frozen=True, slots=True)
class Cycle:
    """A circular dependency between modules.

    Attributes:
        modules: sorted member modules of the strongly-connected component.
        edges: the import edges that participate in the component.

    """

    modules: tuple[str, ...]
    edges: tuple[tuple[str, str], ...]


class _Graph:
    """Tiny directed graph with adjacency lists (stdlib only)."""

    def __init__(self, nodes: set[str], edges: list[tuple[str, str]]) -> None:
        self.nodes = nodes
        self.adj: dict[str, set[str]] = {node: set() for node in nodes}
        for source, target in edges:
            if source in self.adj and target in self.adj:
                self.adj[source].add(target)


def _strongly_connected_components(graph: _Graph) -> list[list[str]]:
    """Return the SCCs of ``graph`` (Tarjan's algorithm, iterative)."""
    index: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = [0]

    def strongconnect(node: str) -> None:
        index[node] = lowlink[node] = counter[0]
        counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        for neighbor in graph.adj[node]:
            if neighbor not in index:
                strongconnect(neighbor)
                lowlink[node] = min(lowlink[node], lowlink[neighbor])
            elif neighbor in on_stack:
                lowlink[node] = min(lowlink[node], index[neighbor])
        if lowlink[node] == index[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            components.append(component)

    for node in graph.nodes:
        if node not in index:
            strongconnect(node)
    return components


def find_cycles(
    import_records: dict[str, list[ImportRecord]],
    package: str = "hunterx",
) -> list[Cycle]:
    """Find circular dependencies across the internal module graph.

    ``TYPE_CHECKING`` imports are ignored. Self-imports (a module importing
    itself) are also ignored.

    Args:
        import_records: module name to import records mapping.
        package: package prefix that bounds the graph.

    Returns:
        A list of :class:`Cycle` objects, one per non-trivial SCC.

    """
    nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    for source, records in import_records.items():
        if not (source == package or source.startswith(f"{package}.")):
            continue
        nodes.add(source)
        for record in records:
            if record.is_type_checking:
                continue
            target = record.target
            if not (target == package or target.startswith(f"{package}.")):
                continue
            if target == source:
                continue
            if target not in import_records:
                # Target exists in the graph only if it is a scanned module.
                continue
            nodes.add(target)
            edges.append((source, target))

    graph = _Graph(nodes, edges)
    cycles: list[Cycle] = []
    for component in _strongly_connected_components(graph):
        if len(component) > 1:
            members = set(component)
            cycle_edges = tuple(sorted((s, t) for s, t in edges if s in members and t in members))
            cycles.append(Cycle(modules=tuple(sorted(component)), edges=cycle_edges))
    cycles.sort(key=lambda cycle: cycle.modules)
    return cycles


def build_layer_graph(import_records: dict[str, list[ImportRecord]], package: str = "hunterx") -> Any:
    """Build a layer-level adjacency graph for reporting.

    Returns a plain dict mapping each layer name to the set of layers it
    imports from (for report rendering only; validation uses the dependency
    matrix in :mod:`hunterx.architecture.lint`).
    """
    from hunterx.architecture.layers import resolve_layer

    layer_adj: dict[str, set[str]] = {}
    for source, records in import_records.items():
        if not (source == package or source.startswith(f"{package}.")):
            continue
        source_layer = resolve_layer(source).name
        layer_adj.setdefault(source_layer, set())
        for record in records:
            target = record.target
            if not (target == package or target.startswith(f"{package}.")):
                continue
            target_layer = resolve_layer(target).name
            if target_layer != source_layer:
                layer_adj[source_layer].add(target_layer)
    return {layer: sorted(targets) for layer, targets in layer_adj.items()}
