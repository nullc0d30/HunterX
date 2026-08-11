# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge-gap engine.

Sprint 032. After each phase the engine answers:

    WHAT DO WE KNOW?
    WHAT DO WE NOT KNOW?
    WHAT COULD CHANGE OUR CONCLUSION?
    WHAT ACTION WOULD REDUCE THAT UNCERTAINTY?

The output drives adaptive planning: a ranked list of knowledge gaps, each
paired with the action that would reduce the uncertainty it represents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.mission_orchestration.mission import OrchestratedMission
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class KnowledgeGap:
    """A concrete, actionably-answerable knowledge gap.

    Attributes:
        gap_id: stable gap identifier.
        mission_id: owning mission.
        category: what we do not know.
        question: the precise question that, answered, advances the mission.
        what_could_change_conclusion: what observation could flip the current view.
        reducing_action: the action that would reduce this uncertainty.
        capability: capability the reducing action exercises.
        priority: ranking weight.
        blocking: ``True`` when the mission cannot advance without this.

    """

    gap_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    category: str = ""
    question: str = ""
    what_could_change_conclusion: str = ""
    reducing_action: str = ""
    capability: str = ""
    priority: float = 0.5
    blocking: bool = False
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "gap_id": self.gap_id,
            "mission_id": self.mission_id,
            "category": self.category,
            "question": self.question,
            "what_could_change_conclusion": self.what_could_change_conclusion,
            "reducing_action": self.reducing_action,
            "capability": self.capability,
            "priority": self.priority,
            "blocking": self.blocking,
            "created_at": self.created_at,
        }


class KnowledgeGapEngine:
    """Derive knowledge gaps from the current mission state."""

    def analyze(self, mission: OrchestratedMission) -> list[KnowledgeGap]:
        """Return ranked knowledge gaps for a mission.

        Gaps are derived from (1) open hypotheses, (2) uncovered coverage
        cells, (3) open branches and (4) negative evidence that warrants a
        higher-quality alternative.
        """
        gaps: list[KnowledgeGap] = []
        known, not_known = self._knowledge_view(mission)

        # 1. Open hypotheses need evidence to resolve.
        for hypothesis in mission.open_hypotheses(limit=20):
            missing = []
            if hypothesis.state.value in ("proposed", "inconclusive", "novel_behavior"):
                missing.append("supporting or contradicting evidence")
            if not hypothesis.proof_strategy and hypothesis.state.value not in ("refuted", "disproved"):
                missing.append("a proof strategy")
            if missing:
                gaps.append(
                    KnowledgeGap(
                        mission_id=mission.mission_id,
                        category="hypothesis_evidence",
                        question=f"What evidence would resolve hypothesis '{hypothesis.statement[:80]}'?",
                        what_could_change_conclusion=(
                            "an independent validator reproducing (or failing to reproduce) the behavior"
                        ),
                        reducing_action=f"validate hypothesis {hypothesis.hypothesis_id}",
                        capability=hypothesis.category.value,
                        priority=0.8 + hypothesis.priority * 0.2,
                        blocking=hypothesis.priority >= 0.8,
                    )
                )

        # 2. Uncovered coverage cells.
        unknown_assets = self._uncovered(mission)
        for capability, count in unknown_assets.items():
            gaps.append(
                KnowledgeGap(
                    mission_id=mission.mission_id,
                    category="coverage",
                    question=f"Capability '{capability}' is not exercised on {count} asset(s).",
                    what_could_change_conclusion=(
                        "running the capability and recording the observed behavior"
                    ),
                    reducing_action=f"exercise capability '{capability}'",
                    capability=capability,
                    priority=0.6,
                )
            )

        # 3. Open branches.
        for branch in mission.open_branches():
            gaps.append(
                KnowledgeGap(
                    mission_id=mission.mission_id,
                    category="branch",
                    question=f"Branch '{branch.branch_id}' is open: {branch.rationale[:100]}.",
                    what_could_change_conclusion="resolving the branch's hypothesis with evidence",
                    reducing_action=f"advance branch {branch.branch_id}",
                    capability=branch.hypothesis_id or "",
                    priority=branch.priority,
                )
            )

        gaps.sort(key=lambda gap: (-gap.priority, gap.blocking))
        return gaps

    def _knowledge_view(self, mission: OrchestratedMission) -> tuple[list[str], list[str]]:
        """Return the "what we know" and "what we do not know" summaries."""
        known = [
            f"{len(mission.observations)} observations",
            f"{len(mission.context.assets)} assets in context",
            f"{len(mission.context.attack_paths)} attack paths in context",
        ]
        known = [item for item in known if not item.startswith("0 ")] or ["target modeled"]
        open_hypotheses = mission.open_hypotheses(limit=3)
        if open_hypotheses:
            not_known = [hypothesis.statement for hypothesis in open_hypotheses]
        else:
            uncovered = self._uncovered(mission)
            not_known = [f"capability '{capability}' uncovered" for capability in uncovered] or [
                "nothing explicitly unknown"
            ]
        return known, not_known[:5]

    def _uncovered(self, mission: OrchestratedMission) -> dict[str, int]:
        """Return uncovered capability counts across assets."""
        counts: dict[str, int] = {}
        for cells in mission.coverage.values():
            for cell in cells.values():
                if cell.state.uncovered():
                    counts[cell.capability] = counts.get(cell.capability, 0) + 1
        return counts


__all__ = ["KnowledgeGap", "KnowledgeGapEngine"]
