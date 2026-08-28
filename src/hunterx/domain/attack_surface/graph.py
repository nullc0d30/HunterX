# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack-surface graph.

Phase 1 generic layered graph:

    Target → Asset → Service → Application → Surface → Input/Object/State
    → Workflow → Applicable Security Capability

The graph is extensible by construction: node kinds are strings registered in
the :class:`SurfaceKindRegistry`, layers come from :class:`SurfaceLayer`, and
core traversal code never branches on a specific kind. Adding a new target
technology therefore never requires changing this module or any orchestration
logic — only registering kinds and observing surfaces.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from hunterx.domain.attack_surface.enums import SurfaceKind, SurfaceLayer
from hunterx.domain.attack_surface.models import (
    CapabilityAssignment,
    DynamicObject,
    SurfaceContext,
    SurfaceEdge,
    SurfaceNode,
    surface_key,
)
from hunterx.domain.attack_surface.registry import SurfaceKindRegistry

#: Relationship labels used by the layered graph.
CONTAINS = "contains"
EXPOSES = "exposes"
TRANSITIONS_TO = "transitions_to"
PART_OF = "part_of"


class SurfaceGraph:
    """A layered, extensible attack-surface graph.

    Attributes:
        registry: the surface-kind registry used for classification.
        target_key: the root target key of the graph.

    """

    def __init__(self, *, registry: SurfaceKindRegistry | None = None, target_key: str = "") -> None:
        self.registry = registry if registry is not None else SurfaceKindRegistry()
        self.target_key: str = target_key or ""
        self._nodes: dict[str, SurfaceNode] = {}
        self._edges: dict[str, SurfaceEdge] = {}
        self._children: dict[str, list[str]] = {}
        self._parent: dict[str, str] = {}
        self._objects: dict[str, DynamicObject] = {}
        self._assignments: dict[str, CapabilityAssignment] = {}
        self._assignments_by_surface: dict[str, list[str]] = {}

    # -- mutation -----------------------------------------------------------

    def set_target(self, *, mission_id: str, target_key: str) -> SurfaceNode:
        """Ensure the root target node exists and return it."""
        self.target_key = target_key
        node = self._nodes.get(target_key)
        if node is None:
            node = SurfaceNode(
                mission_id=mission_id,
                target_key=target_key,
                layer=SurfaceLayer.TARGET,
                kind=SurfaceKind.TARGET,
                name=target_key,
                key=target_key,
                source="mission",
            )
            self._nodes[target_key] = node
            self._children.setdefault(target_key, [])
        return node

    def upsert(
        self,
        parent_key: str,
        *,
        kind: SurfaceKind | str,
        name: str,
        mission_id: str = "",
        layer: SurfaceLayer | None = None,
        dynamic_type: str = "",
        attributes: dict[str, Any] | None = None,
        context: SurfaceContext | None = None,
        confidence: float = 1.0,
        source: str = "",
        rel_type: str = CONTAINS,
        rationale: str = "",
    ) -> tuple[SurfaceNode, bool]:
        """Add or refresh a surface node under ``parent_key``.

        Returns the node and whether it was newly created. Creating a node
        links it to its parent with ``rel_type``; refreshing a node only updates
        its attributes, context and observer, so repeated observations never
        duplicate nodes.
        """
        key = surface_key(kind, name)
        existing = self._nodes.get(key)
        if existing is not None:
            existing.attributes.update(attributes or {})
            if context is not None:
                existing.context = context
            existing.confidence = max(existing.confidence, confidence)
            existing.source = source or existing.source
            existing.touch()
            return existing, False
        node = SurfaceNode(
            mission_id=mission_id,
            target_key=self.target_key,
            layer=layer if layer is not None else self.registry.layer(kind.value if isinstance(kind, SurfaceKind) else str(kind)),
            kind=kind,
            name=name,
            key=key,
            parent_key=parent_key,
            dynamic_type=dynamic_type,
            attributes=dict(attributes or {}),
            context=context if context is not None else SurfaceContext(),
            confidence=confidence,
            source=source,
        )
        self._nodes[key] = node
        self._children.setdefault(parent_key, []).append(key)
        self._children.setdefault(key, [])
        self._parent[key] = parent_key
        self.add_edge(parent_key, key, rel_type=rel_type, rationale=rationale)
        return node, True

    def add_edge(self, source_key: str, target_key: str, *, rel_type: str, rationale: str = "") -> SurfaceEdge:
        """Add or refresh a directed edge between two nodes."""
        if source_key not in self._nodes or target_key not in self._nodes:
            raise KeyError(f"cannot add edge between unknown nodes: {source_key} -> {target_key}")
        edge = SurfaceEdge(source_key=source_key, target_key=target_key, rel_type=rel_type, rationale=rationale)
        self._edges[edge.key()] = edge
        return edge

    def add_object(self, obj: DynamicObject) -> tuple[DynamicObject, bool]:
        """Add a dynamic object (returns it and whether it is new)."""
        existing = self._objects.get(obj.key)
        if existing is not None:
            return existing, False
        self._objects[obj.key] = obj
        self._children.setdefault(obj.parent_key, []).append(obj.key)
        self._parent[obj.key] = obj.parent_key
        self._nodes.setdefault(obj.key, SurfaceNode(
            mission_id=obj.mission_id,
            target_key=obj.target_key,
            layer=SurfaceLayer.OBJECT,
            kind=SurfaceKind.OBJECT,
            name=obj.name,
            key=obj.key,
            parent_key=obj.parent_key,
            dynamic_type=obj.object_type,
            attributes=dict(obj.attributes),
            source=obj.source,
        ))
        return obj, True

    def attach_assignment(self, assignment: CapabilityAssignment) -> tuple[CapabilityAssignment, bool]:
        """Store a capability assignment (deduplicated by identity).

        The ``Capability × Surface × Context`` relationship is captured by the
        surface→assignment index rather than a phantom graph edge, so the graph
        keeps only observed surfaces as nodes.
        """
        key = assignment.identity_key()
        existing = self._assignments.get(key)
        if existing is not None:
            return existing, False
        self._assignments[key] = assignment
        self._assignments_by_surface.setdefault(assignment.surface_key, []).append(key)
        return assignment, True

    # -- reads --------------------------------------------------------------

    def node(self, key: str) -> SurfaceNode | None:
        """Return a surface node by key (``None`` when absent)."""
        return self._nodes.get(key)

    def edge(self, key: str) -> SurfaceEdge | None:
        """Return an edge by its identity key."""
        return self._edges.get(key)

    def nodes(self, *, layer: SurfaceLayer | None = None, kind: str | None = None) -> list[SurfaceNode]:
        """Return all nodes, optionally filtered by layer or kind."""
        result = list(self._nodes.values())
        if layer is not None:
            result = [node for node in result if node.layer is layer]
        if kind is not None:
            result = [node for node in result if node.kind_value() == kind]
        return sorted(result, key=lambda node: node.key)

    def edges(self) -> list[SurfaceEdge]:
        """Return all edges."""
        return sorted(self._edges.values(), key=lambda edge: edge.key())

    def objects(self) -> list[DynamicObject]:
        """Return all dynamic objects."""
        return sorted(self._objects.values(), key=lambda obj: obj.key)

    def assignments(self) -> list[CapabilityAssignment]:
        """Return all capability assignments."""
        return list(self._assignments.values())

    def assignments_for(self, surface_key_value: str) -> list[CapabilityAssignment]:
        """Return the assignments attached to a surface."""
        keys = self._assignments_by_surface.get(surface_key_value, ())
        return [self._assignments[key] for key in keys if key in self._assignments]

    def children(self, key: str) -> list[SurfaceNode]:
        """Return the direct children of a node."""
        return [self._nodes[child] for child in self._children.get(key, ()) if child in self._nodes]

    def parent(self, key: str) -> SurfaceNode | None:
        """Return the direct parent of a node (``None`` for the root)."""
        parent_key = self._parent.get(key)
        return self._nodes.get(parent_key) if parent_key else None

    def descendants(self, key: str, *, layer: SurfaceLayer | None = None) -> list[SurfaceNode]:
        """Return all descendants of a node, optionally filtered by layer."""
        seen: set[str] = set()
        frontier = list(self._children.get(key, ()))
        while frontier:
            current = frontier.pop()
            if current in seen or current not in self._nodes:
                continue
            seen.add(current)
            frontier.extend(self._children.get(current, ()))
        nodes = [self._nodes[k] for k in seen]
        if layer is not None:
            nodes = [node for node in nodes if node.layer is layer]
        return sorted(nodes, key=lambda node: node.key)

    def ancestors(self, key: str) -> list[SurfaceNode]:
        """Return all ancestors of a node, nearest first."""
        result: list[SurfaceNode] = []
        current = self._parent.get(key)
        while current:
            node = self._nodes.get(current)
            if node is None:
                break
            result.append(node)
            current = self._parent.get(current)
        return result

    def inputs_of(self, surface_key_value: str) -> list[SurfaceNode]:
        """Return the input-layer children of a surface."""
        return self.descendants(surface_key_value, layer=SurfaceLayer.INPUT)

    def objects_of(self, surface_key_value: str) -> list[SurfaceNode]:
        """Return the object-layer children of a surface."""
        return self.descendants(surface_key_value, layer=SurfaceLayer.OBJECT)

    def states_of(self, surface_key_value: str) -> list[SurfaceNode]:
        """Return the state-layer children of a surface."""
        return self.descendants(surface_key_value, layer=SurfaceLayer.STATE)

    def workflows_of(self, surface_key_value: str) -> list[SurfaceNode]:
        """Return the workflow-layer children of a surface."""
        return self.descendants(surface_key_value, layer=SurfaceLayer.WORKFLOW)

    def surfaces_for(self, layer: SurfaceLayer | None = None) -> list[SurfaceNode]:
        """Return the schedulable surface nodes (optionally by layer)."""
        return self.nodes(layer=layer)

    def node_count(self) -> int:
        """Return the number of surface nodes."""
        return len(self._nodes)

    def object_count(self) -> int:
        """Return the number of dynamic objects."""
        return len(self._objects)

    def assignment_count(self) -> int:
        """Return the number of capability assignments."""
        return len(self._assignments)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the whole graph to a JSON-safe mapping."""
        return {
            "target_key": self.target_key,
            "nodes": [node.to_dict() for node in self.nodes()],
            "edges": [edge.to_dict() for edge in self.edges()],
            "objects": [obj.to_dict() for obj in self.objects()],
            "assignments": [assignment.to_dict() for assignment in self.assignments()],
        }


def link_chain(graph: SurfaceGraph, *layers: tuple[str, str, SurfaceLayer, str]) -> list[SurfaceNode]:
    """Build a parent→child chain of surface nodes.

    Each entry is ``(kind, name, layer, parent_kind)``; the first entry's
    parent must already exist in the graph. Returns the created nodes.
    """
    created: list[SurfaceNode] = []
    for kind, name, _layer, parent_kind in layers:
        parent_key = surface_key(parent_kind, name)
        node, _is_new = graph.upsert(parent_key, kind=kind, name=name)
        created.append(node)
    return created


def kind_names(nodes: Iterable[SurfaceNode]) -> list[str]:
    """Return the distinct kind strings of a node collection."""
    return sorted({node.kind_value() for node in nodes})


__all__ = ["CONTAINS", "EXPOSES", "PART_OF", "TRANSITIONS_TO", "SurfaceGraph", "kind_names", "link_chain"]
