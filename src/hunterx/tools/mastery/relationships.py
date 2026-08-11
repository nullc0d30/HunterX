# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool relationship graph.

Models how tools relate to one another: which tool enables another, which
validates another, which replaces another, which conflicts, which must
precede/follow another. The graph powers chaining, alternatives, conflict
detection and "what should I run next" reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.tool_mastery import (
    ToolRelationship,
    ToolRelationshipKind,
)

#: All relationship kinds the graph understands.
RELATIONSHIP_KINDS = tuple(ToolRelationshipKind)

#: Bidirectional complements are the default representation of COMPLEMENTS.
_COMPLEMENT_REVERSE = {ToolRelationshipKind.COMPLEMENTS}


@dataclass(slots=True)
class ToolRelationshipGraph:
    """A directed graph of tool relationships.

    Each edge is a :class:`ToolRelationship`. Query helpers let callers walk
    predecessors/successors for any relation kind, find alternatives
    (REPLACES), detect conflicts, and compute a suggested next tool.
    """

    edges: list[ToolRelationship] = field(default_factory=list)

    def add(self, relationship: ToolRelationship) -> None:
        """Add a relationship edge.

        COMPLEMENTS edges are mirrored automatically (A complements B implies
        B complements A) so the graph stays symmetric for that relation.
        """
        self.edges.append(relationship)
        if relationship.kind in _COMPLEMENT_REVERSE:
            self.edges.append(
                ToolRelationship(
                    source=relationship.target,
                    target=relationship.source,
                    kind=relationship.kind,
                    capability=relationship.capability,
                    rationale=f"mirrored complement of {relationship.source}",
                    strength=relationship.strength,
                )
            )

    def add_many(self, relationships: list[ToolRelationship]) -> None:
        """Add several relationships at once."""
        for relationship in relationships:
            self.add(relationship)

    # -- basic accessors ----------------------------------------------------

    def edges_for(self, tool_id: str) -> list[ToolRelationship]:
        """Return every edge where ``tool_id`` is source or target."""
        return [e for e in self.edges if e.source == tool_id or e.target == tool_id]

    def successors(self, tool_id: str, kind: ToolRelationshipKind | None = None) -> list[str]:
        """Return tool ids reachable from ``tool_id`` via outgoing edges."""
        result: list[str] = []
        for edge in self.edges:
            if edge.source == tool_id and (kind is None or edge.kind is kind):
                result.append(edge.target)
        return result

    def predecessors(self, tool_id: str, kind: ToolRelationshipKind | None = None) -> list[str]:
        """Return tool ids that point at ``tool_id`` via incoming edges."""
        result: list[str] = []
        for edge in self.edges:
            if edge.target == tool_id and (kind is None or edge.kind is kind):
                result.append(edge.source)
        return result

    def neighbors(self, tool_id: str) -> list[str]:
        """Return every direct neighbor of ``tool_id`` (any relation kind)."""
        result: list[str] = []
        for edge in self.edges:
            if edge.source == tool_id:
                result.append(edge.target)
            elif edge.target == tool_id:
                result.append(edge.source)
        return result

    # -- semantic helpers ----------------------------------------------------

    def requires(self, tool_id: str) -> list[str]:
        """Return tool ids that ``tool_id`` REQUIRES."""
        return self.successors(tool_id, ToolRelationshipKind.REQUIRES)

    def enables(self, tool_id: str) -> list[str]:
        """Return tool ids that ``tool_id`` ENABLES."""
        return self.successors(tool_id, ToolRelationshipKind.ENABLES)

    def validates(self, tool_id: str) -> list[str]:
        """Return tool ids that ``tool_id`` VALIDATES (or corroborates)."""
        result = self.successors(tool_id, ToolRelationshipKind.VALIDATES)
        result += self.successors(tool_id, ToolRelationshipKind.CORROBORATES)
        return result

    def alternatives(self, tool_id: str) -> list[str]:
        """Return tool ids that REPLACE ``tool_id`` (its alternatives)."""
        result = self.successors(tool_id, ToolRelationshipKind.REPLACES)
        result += self.predecessors(tool_id, ToolRelationshipKind.REPLACES)
        return result

    def conflicts_with(self, tool_id: str) -> list[str]:
        """Return tool ids that CONFLICT_WITH ``tool_id``."""
        return self.successors(tool_id, ToolRelationshipKind.CONFLICTS_WITH)

    def next_tools(self, tool_id: str) -> list[str]:
        """Return the natural next tool ids (FOLLOWS, ENABLES, VALIDATES)."""
        result: list[str] = []
        for kind in (
            ToolRelationshipKind.FOLLOWS,
            ToolRelationshipKind.ENABLES,
            ToolRelationshipKind.VALIDATES,
        ):
            result += self.successors(tool_id, kind)
        return result

    def previous_tools(self, tool_id: str) -> list[str]:
        """Return the natural predecessor tool ids (PRECEDES, REQUIRES)."""
        result: list[str] = []
        for kind in (ToolRelationshipKind.PRECEDES, ToolRelationshipKind.REQUIRES):
            result += self.predecessors(tool_id, kind)
        return result

    # -- integrity -----------------------------------------------------------

    def unknown_refs(self, known: list[str]) -> list[str]:
        """Return every referenced tool id not present in ``known``."""
        referenced: set[str] = set()
        for edge in self.edges:
            referenced.add(edge.source)
            referenced.add(edge.target)
        return sorted(referenced - set(known))

    def cycles(self, kind: ToolRelationshipKind | None = None) -> list[list[str]]:
        """Return elementary cycles in the graph (optionally per kind).

        Uses a DFS over the (possibly kind-filtered) edge set.
        """
        adjacency: dict[str, list[str]] = {}
        for edge in self.edges:
            if kind is not None and edge.kind is not kind:
                continue
            adjacency.setdefault(edge.source, []).append(edge.target)

        cycles: list[list[str]] = []
        for node in list(adjacency):
            path: list[str] = []
            visited: set[str] = set()

            def dfs(current: str, path: list[str], visited: set[str]) -> None:
                if current in path:
                    idx = path.index(current)
                    cycle = path[idx:] + [current]
                    if cycle not in cycles:
                        cycles.append(cycle)
                    return
                if current in visited:
                    return
                visited.add(current)
                path.append(current)
                for neighbor in adjacency.get(current, []):
                    dfs(neighbor, path, visited)
                path.pop()

            dfs(node, path, visited)

        return cycles
