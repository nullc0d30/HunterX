# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution graph builder.

Turns a :class:`~hunterx.domain.mission_planning.MissionPlan` into a directed
acyclic graph (:class:`~hunterx.domain.mission_planning.ExecutionGraph`) of
execution nodes. Nodes model steps; edges encode intra-phase sequencing and
cross-phase dependencies. The builder also applies graph configuration:
conditional nodes, fallback edges (rollback/recovery) and retryable flags.

Supported graph configuration (under ``plan.config["graph"]``):

- ``conditions``: ``{phase_id: expression}`` marks a phase's nodes conditional.
- ``fallbacks``: ``{phase_id: fallback_phase_id}`` routes the last node of a
  phase to the first node of a fallback phase on failure.
- ``retryable``: ``[phase_id | action, ...]`` marks matching nodes retryable.
"""

from __future__ import annotations

from hunterx.domain.exceptions import InvalidMissionPlanError
from hunterx.domain.mission_planning import ExecutionGraph, ExecutionNode, MissionPlan


class ExecutionGraphBuilder:
    """Build an :class:`ExecutionGraph` from a mission plan."""

    def build(self, plan: MissionPlan) -> ExecutionGraph:
        """Return the execution graph for ``plan``.

        Raises :class:`InvalidMissionPlanError` when the plan produces no
        executable steps.
        """
        graph_cfg = plan.config.get("graph")
        if not isinstance(graph_cfg, dict):
            graph_cfg = {}
        conditions = graph_cfg.get("conditions", {}) or {}
        fallbacks = graph_cfg.get("fallbacks", {}) or {}
        retryable = set(graph_cfg.get("retryable", []) or [])

        nodes = self._build_nodes(plan, conditions, retryable)
        if not nodes:
            raise InvalidMissionPlanError(
                "mission plan produced no executable steps."
            )
        phase_first, phase_last = self._phase_edges(nodes)
        nodes = self._apply_fallbacks(nodes, fallbacks, phase_first, phase_last)
        root_ids = tuple(node.node_id for node in nodes if not node.depends_on)
        return ExecutionGraph(nodes=tuple(nodes), root_ids=root_ids)

    def _build_nodes(
        self,
        plan: MissionPlan,
        conditions: dict[str, object],
        retryable: set[str],
    ) -> list[ExecutionNode]:
        """Create one node per step, chaining phases and steps."""
        nodes: list[ExecutionNode] = []
        phase_last: dict[str, str] = {}
        for phase in plan.phases:
            first: str | None = None
            for step in phase.steps:
                depends = list(step.depends_on)
                if first is None:
                    for dependency in phase.depends_on:
                        if dependency in phase_last:
                            depends.append(phase_last[dependency])
                condition = str(conditions.get(phase.phase_id, ""))
                nodes.append(
                    ExecutionNode(
                        node_id=step.step_id,
                        action=step.action,
                        target=step.target,
                        parameters=dict(step.parameters),
                        phase_id=phase.phase_id,
                        phase_kind=phase.kind,
                        depends_on=tuple(dict.fromkeys(depends)),
                        parallel=phase.parallel,
                        conditional=bool(condition),
                        condition=condition,
                        retryable=phase.phase_id in retryable or step.action in retryable,
                        approval_required=step.approval_required,
                        estimated_duration_seconds=step.estimated_duration_seconds,
                    )
                )
                if first is None:
                    first = step.step_id
                phase_last[phase.phase_id] = step.step_id
        return nodes

    @staticmethod
    def _phase_edges(nodes: list[ExecutionNode]) -> tuple[dict[str, str], dict[str, str]]:
        """Return (first-node, last-node) ids per phase."""
        first: dict[str, str] = {}
        last: dict[str, str] = {}
        for node in nodes:
            first.setdefault(node.phase_id, node.node_id)
            last[node.phase_id] = node.node_id
        return first, last

    @staticmethod
    def _apply_fallbacks(
        nodes: list[ExecutionNode],
        fallbacks: dict[str, object],
        phase_first: dict[str, str],
        phase_last: dict[str, str],
    ) -> list[ExecutionNode]:
        """Attach fallback edges from the last node of a phase to its fallback."""
        by_id = {node.node_id: node for node in nodes}
        for source_phase, target_phase in fallbacks.items():
            last_id = phase_last.get(str(source_phase))
            first_id = phase_first.get(str(target_phase))
            if last_id is None or first_id is None:
                continue
            node = by_id[last_id]
            by_id[last_id] = ExecutionNode(
                node_id=node.node_id,
                action=node.action,
                target=node.target,
                parameters=node.parameters,
                phase_id=node.phase_id,
                phase_kind=node.phase_kind,
                depends_on=node.depends_on,
                parallel=node.parallel,
                conditional=node.conditional,
                condition=node.condition,
                fallback_node_id=first_id,
                retryable=node.retryable,
                approval_required=node.approval_required,
                estimated_duration_seconds=node.estimated_duration_seconds,
            )
        return [by_id[node.node_id] for node in nodes]
