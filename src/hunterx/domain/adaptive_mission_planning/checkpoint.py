# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Checkpoint and resume for adaptive missions.

A mission must be resumable: the checkpoint captures the mission state, plan
version, completed/pending actions, observations, evidence, hypotheses, proof
states and tool state. After restart the mission is reconstructed without
losing intelligence.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import ActionStatus, MissionState
from hunterx.domain.adaptive_mission_planning.graph import AdaptiveExecutionGraph
from hunterx.domain.adaptive_mission_planning.models import PlanCheckpoint


class CheckpointEngine:
    """Build and restore :class:`PlanCheckpoint` snapshots."""

    def create(
        self,
        *,
        mission_id: str,
        graph: AdaptiveExecutionGraph,
        plan_version: int,
        mission_state: MissionState,
        observations: tuple[str, ...] = (),
        evidence: tuple[str, ...] = (),
        hypotheses: tuple[str, ...] = (),
        proof_states: dict[str, object] | None = None,
        tool_state: dict[str, object] | None = None,
    ) -> PlanCheckpoint:
        """Snapshot the mission for later resume."""
        return PlanCheckpoint(
            mission_id=mission_id,
            plan_version=plan_version,
            mission_state=mission_state,
            completed_actions=tuple(
                action.action_id for action in graph.actions.values() if action.status.is_terminal
            ),
            pending_actions=tuple(
                action.action_id for action in graph.actions.values() if not action.status.is_terminal
            ),
            observations=observations,
            evidence=evidence,
            hypotheses=hypotheses,
            proof_states=dict(proof_states or {}),
            tool_state=dict(tool_state or {}),
        )

    def resume(self, checkpoint: PlanCheckpoint, graph: AdaptiveExecutionGraph) -> AdaptiveExecutionGraph:
        """Reconstruct action statuses from ``checkpoint`` on ``graph``.

        Actions recorded as completed keep their terminal state; actions that
        were pending are reset to ``APPROVED`` so the executor may continue
        from where the mission stopped.
        """
        for action in graph.actions.values():
            if action.action_id in checkpoint.completed_actions:
                action.mark(ActionStatus.COMPLETED)
            elif action.action_id in checkpoint.pending_actions:
                action.mark(ActionStatus.APPROVED)
        return graph
