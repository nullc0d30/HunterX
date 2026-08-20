# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack-surface completion gate.

The completion gate answers the Phase 1 mandatory question: has the assessment
genuinely *exhausted* the applicable attack surface? Completion is never defined
as "N cycles / N probes / N findings / N parameters". It requires, all at once:

    discovery exhausted
    AND dynamic discovery exhausted
    AND every applicable capability×surface×context combination evaluated
    AND the assessment queue exhausted
    AND the verification queue exhausted
    AND no new attack paths remain

Failure is never converted into completion: a target that is unavailable or an
assessment that is blocked terminates with an explicit non-complete verdict.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.attack_surface.enums import (
    CompletionVerdict,
    ExhaustionCriterion,
    VerificationState,
)
from hunterx.domain.attack_surface.graph import SurfaceGraph
from hunterx.domain.attack_surface.models import ExhaustionReport
from hunterx.domain.attack_surface.queue import AssessmentQueue


class CompletionGate:
    """Evaluates attack-surface exhaustion from the graph and assessment queue.

    Args:
        stale_window: consecutive observations with no genuinely new surface
            required to declare discovery exhausted.
        min_surfaces: minimum surfaced nodes before exhaustion is even possible
            (guards against declaring a zero-discovery target "exhausted").
        min_rounds: minimum discovery rounds before exhaustion is evaluated.

    """

    def __init__(self, *, stale_window: int = 3, min_surfaces: int = 1, min_rounds: int = 1) -> None:
        self.stale_window = max(1, stale_window)
        self.min_surfaces = max(0, min_surfaces)
        self.min_rounds = max(0, min_rounds)
        self._rounds = 0
        self._stale_observations = 0
        self._total_surfaces = 0
        self._unavailable_reason = ""
        self._blocked_reason = ""
        self._last_new_attack_paths = 0
        self._seen_attack_paths = 0

    # -- discovery bookkeeping ----------------------------------------------

    def record_observation(self, *, surfaces_before: int, surfaces_after: int) -> None:
        """Record an observation round and its surface delta.

        A round that added no surface keeps the stale counter climbing; a round
        with new surfaces resets it. ``surfaces_after`` also refreshes the
        running total used by the availability guard.
        """
        self._rounds += 1
        self._total_surfaces = max(self._total_surfaces, surfaces_after)
        if surfaces_after > surfaces_before:
            self._stale_observations = 0
        else:
            self._stale_observations += 1

    def record_attack_paths(self, count: int) -> None:
        """Record the attack-path count observed so far."""
        new = max(0, count - self._seen_attack_paths)
        self._last_new_attack_paths = new
        self._seen_attack_paths = max(self._seen_attack_paths, count)

    def mark_unavailable(self, reason: str) -> None:
        """Mark the target as unavailable (never converted into completion)."""
        self._unavailable_reason = reason

    def mark_blocked(self, reason: str) -> None:
        """Mark the assessment as blocked (never converted into completion)."""
        self._blocked_reason = reason

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, graph: SurfaceGraph, queue: AssessmentQueue) -> ExhaustionReport:
        """Return the exhaustion verdict for the current surface state."""
        surfaced = graph.node_count()
        if self._unavailable_reason:
            return ExhaustionReport(
                verdict=CompletionVerdict.TARGET_UNAVAILABLE,
                surfaced=surfaced,
                reason=f"target unavailable: {self._unavailable_reason}",
                unavailable_reason=self._unavailable_reason,
            )
        if self._blocked_reason:
            return ExhaustionReport(
                verdict=CompletionVerdict.BLOCKED,
                surfaced=surfaced,
                reason=f"assessment blocked: {self._blocked_reason}",
                blocked_reason=self._blocked_reason,
            )
        assignments = graph.assignments()
        applicable = [assignment for assignment in assignments if assignment.applicable]
        evaluated = [
            assignment
            for assignment in applicable
            if assignment.status.is_terminal or assignment.verification_state.is_settled
        ]
        pending_verification = any(
            task.status.is_actionable
            and task.verification_state in (VerificationState.UNVERIFIED, VerificationState.VERIFYING)
            for task in queue.tasks()
        )

        discovery_exhausted = (
            self._rounds >= self.min_rounds
            and surfaced >= self.min_surfaces
            and self._stale_observations >= self.stale_window
        )
        dynamic_discovery_exhausted = discovery_exhausted and self._stale_observations >= self.stale_window
        combinations_evaluated = (not applicable) or (len(evaluated) == len(applicable))
        assessment_queue_exhausted = queue.exhausted()
        verification_queue_exhausted = not pending_verification
        no_attack_paths_remain = self._last_new_attack_paths == 0

        criteria = {
            ExhaustionCriterion.DISCOVERY_EXHAUSTED.value: discovery_exhausted,
            ExhaustionCriterion.DYNAMIC_DISCOVERY_EXHAUSTED.value: dynamic_discovery_exhausted,
            ExhaustionCriterion.COMBINATIONS_EVALUATED.value: combinations_evaluated,
            ExhaustionCriterion.ASSESSMENT_QUEUE_EXHAUSTED.value: assessment_queue_exhausted,
            ExhaustionCriterion.VERIFICATION_QUEUE_EXHAUSTED.value: verification_queue_exhausted,
            ExhaustionCriterion.NO_ATTACK_PATHS_REMAIN.value: no_attack_paths_remain,
        }
        satisfied = all(criteria.values())
        unmet = [key for key, value in criteria.items() if not value]
        if satisfied:
            return ExhaustionReport(
                verdict=CompletionVerdict.EXHAUSTED,
                criteria=criteria,
                reason="discovery, dynamic discovery, applicable combinations, assessment queue, "
                "verification queue and attack paths are all exhausted",
                surfaced=surfaced,
                applicable_combinations=len(applicable),
                evaluated_combinations=len(evaluated),
                pending_tasks=queue.remaining(),
                stale_observations=self._stale_observations,
            )
        return ExhaustionReport(
            verdict=CompletionVerdict.NOT_EXHAUSTED,
            criteria=criteria,
            reason=f"assessment not exhausted: unmet criteria = {unmet}",
            surfaced=surfaced,
            applicable_combinations=len(applicable),
            evaluated_combinations=len(evaluated),
            pending_tasks=queue.remaining(),
            stale_observations=self._stale_observations,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the gate configuration to a JSON-safe mapping."""
        return {
            "stale_window": self.stale_window,
            "min_surfaces": self.min_surfaces,
            "min_rounds": self.min_rounds,
            "rounds": self._rounds,
            "stale_observations": self._stale_observations,
            "total_surfaces": self._total_surfaces,
            "unavailable_reason": self._unavailable_reason,
            "blocked_reason": self._blocked_reason,
        }


__all__ = ["CompletionGate"]
