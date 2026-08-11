# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission dependency graph.

Represents the execution dependencies between the steps of an execution plan
and supports sequential, parallel, conditional, fan-out and fan-in execution.
The graph is derived from the plan's phase/step structure and can be traversed
topologically to determine which steps are ready to run.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.orchestration.models import ExecutionPlan, MissionStep


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A dependency edge between two steps.

    Attributes:
        source_step_id: the step that must finish first.
        target_step_id: the step that depends on the source.
        kind: edge kind (``finish-to-start``).

    """

    source_step_id: str
    target_step_id: str
    kind: str = "finish-to-start"


@dataclass(frozen=True, slots=True)
class GraphNode:
    """A node in the mission dependency graph.

    Attributes:
        step: the underlying planned step.
        depends_on: step ids that must finish first.
        dependants: step ids that depend on this step.

    """

    step: MissionStep
    depends_on: tuple[str, ...] = ()
    dependants: tuple[str, ...] = ()


class MissionDependencyGraph:
    """A dependency graph over the steps of an execution plan.

    The graph supports readiness queries (which steps can run now), parallel
    waves, fan-out/fan-in tracking and cycle detection. It is built once from
    a plan and is immutable thereafter.
    """

    def __init__(self, plan: ExecutionPlan) -> None:
        self._plan = plan
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._build(plan)

    @property
    def plan(self) -> ExecutionPlan:
        """Return the plan this graph was built from."""
        return self._plan

    @property
    def nodes(self) -> dict[str, GraphNode]:
        """Return every graph node keyed by step id."""
        return dict(self._nodes)

    @property
    def edges(self) -> list[GraphEdge]:
        """Return every dependency edge."""
        return list(self._edges)

    def node(self, step_id: str) -> GraphNode | None:
        """Return the node for ``step_id`` or ``None``."""
        return self._nodes.get(step_id)

    def step(self, step_id: str) -> MissionStep | None:
        """Return the planned step for ``step_id`` or ``None``."""
        node = self._nodes.get(step_id)
        return node.step if node is not None else None

    def ready(self, completed: set[str], *, skipped: set[str] | None = None) -> list[str]:
        """Return step ids whose dependencies are satisfied.

        Args:
            completed: step ids already completed.
            skipped: step ids that were skipped (treated as satisfied).

        """
        skipped = skipped or set()
        satisfied = completed | skipped
        ready: list[str] = []
        for step_id, node in self._nodes.items():
            if step_id in satisfied:
                continue
            if all(dep in satisfied for dep in node.depends_on):
                ready.append(step_id)
        return ready

    def root_ids(self) -> list[str]:
        """Return step ids with no dependencies."""
        return [step_id for step_id, node in self._nodes.items() if not node.depends_on]

    def parallel_waves(self) -> list[list[str]]:
        """Return waves of concurrently runnable step ids (Kahn's algorithm)."""
        remaining = {step_id: set(node.depends_on) for step_id, node in self._nodes.items()}
        waves: list[list[str]] = []
        while remaining:
            wave = [step_id for step_id, deps in remaining.items() if not deps]
            if not wave:
                raise ValueError("mission dependency graph contains a cycle")
            waves.append(wave)
            for step_id in wave:
                remaining.pop(step_id)
            completed_wave = set(wave)
            for deps in remaining.values():
                deps.difference_update(completed_wave)
        return waves

    def topological_order(self) -> list[str]:
        """Return step ids in a valid topological order."""
        order: list[str] = []
        remaining = {step_id: set(node.depends_on) for step_id, node in self._nodes.items()}
        while remaining:
            ready = [step_id for step_id, deps in remaining.items() if not deps]
            if not ready:
                raise ValueError("mission dependency graph contains a cycle")
            for step_id in sorted(ready):
                order.append(step_id)
                remaining.pop(step_id)
            ready_set = set(ready)
            for deps in remaining.values():
                deps.difference_update(ready_set)
        return order

    def successors(self, step_id: str) -> list[str]:
        """Return the dependants of ``step_id`` (fan-out)."""
        node = self._nodes.get(step_id)
        return list(node.dependants) if node is not None else []

    def predecessors(self, step_id: str) -> list[str]:
        """Return the dependencies of ``step_id`` (fan-in)."""
        node = self._nodes.get(step_id)
        return list(node.depends_on) if node is not None else []

    def has_cycle(self) -> bool:
        """Return ``True`` when the graph contains a cycle."""
        try:
            self.topological_order()
            return False
        except ValueError:
            return True

    def validate(self) -> list[str]:
        """Return a list of graph validation errors."""
        errors: list[str] = []
        for step_id, node in self._nodes.items():
            for dep in node.depends_on:
                if dep not in self._nodes:
                    errors.append(f"step '{step_id}' depends on unknown step '{dep}'")
        if self.has_cycle():
            errors.append("mission dependency graph contains a cycle")
        return errors

    # -- construction -------------------------------------------------------

    def _build(self, plan: ExecutionPlan) -> None:
        step_ids = {step.step_id for step in plan.steps()}
        depends_map: dict[str, tuple[str, ...]] = {}
        for step in plan.steps():
            deps = tuple(dep for dep in step.depends_on if dep in step_ids)
            depends_map[step.step_id] = deps
        dependants: dict[str, list[str]] = {step_id: [] for step_id in step_ids}
        for step_id, deps in depends_map.items():
            for dep in deps:
                dependants.setdefault(dep, []).append(step_id)
                self._edges.append(GraphEdge(source_step_id=dep, target_step_id=step_id))
        for step in plan.steps():
            self._nodes[step.step_id] = GraphNode(
                step=step,
                depends_on=depends_map.get(step.step_id, ()),
                dependants=tuple(dependants.get(step.step_id, ())),
            )
