# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission branch manager.

Sprint 032. When an observation opens multiple paths, the orchestrator forks
branches. Each branch keeps its own hypothesis, state, evidence, actions, cost
and outcome. The branch manager ranks open branches so the orchestrator pursues
the best one first without abandoning the others.
"""

from __future__ import annotations

from dataclasses import replace

from hunterx.domain.mission_orchestration.models import MissionBranch
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class BranchManager:
    """Create, rank and resolve mission branches."""

    def create(
        self,
        *,
        mission_id: str,
        hypothesis_id: str,
        rationale: str,
        parent_branch_id: str = "",
        priority: float = 0.5,
        actions: tuple[str, ...] = (),
    ) -> MissionBranch:
        """Open a new mission branch."""
        return MissionBranch(
            branch_id=generate_id(),
            mission_id=mission_id,
            parent_branch_id=parent_branch_id,
            hypothesis_id=hypothesis_id,
            rationale=rationale,
            state="open",
            actions=list(actions),
            priority=priority,
            created_at=utcnow_iso(),
            updated_at=utcnow_iso(),
        )

    def record_action(self, branch: MissionBranch, action_id: str, cost: float = 0.0) -> MissionBranch:
        """Record an action executed on a branch."""
        return replace(
            branch,
            actions=list(dict.fromkeys(branch.actions + [action_id])),
            cost=round(branch.cost + cost, 4),
            updated_at=utcnow_iso(),
        )

    def record_evidence(self, branch: MissionBranch, evidence_ref: str) -> MissionBranch:
        """Record evidence attached to a branch."""
        return replace(
            branch,
            evidence_refs=list(dict.fromkeys(branch.evidence_refs + [evidence_ref])),
            updated_at=utcnow_iso(),
        )

    def resolve(self, branch: MissionBranch, *, outcome: str) -> MissionBranch:
        """Close a branch with an outcome (``validated``/``refuted``/``abandoned``)."""
        return replace(
            branch,
            state="resolved",
            outcome=outcome,
            updated_at=utcnow_iso(),
        )

    def rank(self, branches: list[MissionBranch], *, limit: int = 10) -> list[MissionBranch]:
        """Return open branches ranked by priority."""
        open_branches = [branch for branch in branches if branch.state == "open"]
        return sorted(open_branches, key=lambda branch: (-branch.priority, branch.created_at))[:limit]

    def states(self, branches: list[MissionBranch]) -> dict[str, int]:
        """Return branch counts per state."""
        counts: dict[str, int] = {}
        for branch in branches:
            counts[branch.state] = counts.get(branch.state, 0) + 1
        return counts


__all__ = ["BranchManager"]
