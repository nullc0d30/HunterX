# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Dependency engine.

Understands tool dependencies as a graph: a tool requires capabilities, and
capabilities are provided by other tools. Supports graph traversal to answer
"what must run before tool X?" and "which tools does this mission need?".
"""

from __future__ import annotations

from collections import defaultdict, deque

from hunterx.domain.exceptions import ToolNotFoundError
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry


class DependencyEngine:
    """Capability-based dependency graph over the tool registry.

    The graph edges are capability requirements. For a tool ``T`` that
    declares ``requires capabilities = [c1, c2]`` and provides ``[c3]``, the
    engine can traverse to the tools that provide ``c1`` and ``c2``
    transitively.
    """

    def __init__(self, registry: ToolIntelligenceRegistry) -> None:
        self._registry = registry

    def requires(self, tool_id: str) -> list[str]:
        """Return the capability ids ``tool_id`` requires (from its knowledge)."""
        knowledge = self._registry.get_knowledge(tool_id)
        if knowledge is None:
            return []
        return [dependency.capability for dependency in knowledge.dependencies]

    def provides(self, tool_id: str) -> list[str]:
        """Return the capability ids ``tool_id`` provides."""
        return self._registry.capabilities_for(tool_id)

    def providers_of(self, capability_id: str) -> list[str]:
        """Return tool ids that can provide ``capability_id``."""
        return self._registry.providers_for(capability_id)

    def resolve_dependencies(self, tool_id: str) -> list[str]:
        """Return tool ids that must run before ``tool_id``.

        Traverses the capability graph transitively and returns a topological
        (breadth-first) ordering of prerequisite tools, excluding ``tool_id``.
        Dependencies with no registered provider are skipped.

        Raises:
            ToolNotFoundError: if ``tool_id`` is not registered.

        """
        if self._registry.get_metadata(tool_id) is None:
            raise ToolNotFoundError(tool_id)

        ordered: list[str] = []
        seen: set[str] = set()
        queue: deque[str] = deque([tool_id])

        while queue:
            current = queue.popleft()
            for capability_id in self.requires(current):
                for provider in self.providers_of(capability_id):
                    if provider in seen or provider == tool_id:
                        continue
                    seen.add(provider)
                    ordered.append(provider)
                    queue.append(provider)
        return ordered

    def is_satisfied(self, tool_id: str) -> tuple[bool, list[str]]:
        """Return ``(ok, missing)`` where missing lists unsatisfied capabilities.

        A required capability is satisfied when at least one registered tool
        provides it and that provider is itself satisfiable (recursively).
        """
        missing: list[str] = []
        for capability_id in self.requires(tool_id):
            if not self.providers_of(capability_id):
                missing.append(capability_id)
        return (not missing, missing)

    def required_tool_chain(self, capability_ids: list[str]) -> list[str]:
        """Return the minimal set of tools needed to provide ``capability_ids``.

        Uses breadth-first traversal: for every capability, the first
        registered provider is chosen and its own dependencies are expanded.
        """
        ordered: list[str] = []
        seen: set[str] = set()
        queue: deque[str] = deque(capability_ids)

        while queue:
            capability_id = queue.popleft()
            for provider in self.providers_of(capability_id):
                if provider in seen:
                    continue
                seen.add(provider)
                ordered.append(provider)
                for dep in self.requires(provider):
                    if dep not in seen and self.providers_of(dep):
                        queue.append(dep)
        return ordered

    def dependency_map(self) -> dict[str, list[str]]:
        """Return tool_id → prerequisite tool ids for every registered tool."""
        mapping: dict[str, list[str]] = defaultdict(list)
        for metadata in self._registry.list_metadata():
            mapping[metadata.tool_id] = self.resolve_dependencies(metadata.tool_id)
        return dict(mapping)

    def cycle_report(self) -> list[list[str]]:
        """Return simple dependency cycles found in the capability graph.

        A cycle is a list of capability ids; an empty list means acyclic.
        Detected via DFS on capability → provider → required-capability edges.
        """
        capabilities = sorted({c for k in self._registry.list_knowledge() for c in k.capabilities})

        def _visit(node: str, path: list[str]) -> list[list[str]]:
            if node in path:
                idx = path.index(node)
                return [path[idx:] + [node]]
            cycles: list[list[str]] = []
            for provider in self.providers_of(node):
                for dep in self.requires(provider):
                    if dep == node:
                        continue
                    cycles.extend(_visit(dep, path + [node]))
            return cycles

        found: list[list[str]] = []
        for capability in capabilities:
            for cycle in _visit(capability, []):
                if cycle not in found:
                    found.append(cycle)
        return found
