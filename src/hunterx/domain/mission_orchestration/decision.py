# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission decision engine.

Sprint 032. The decision engine ranks candidate actions by **expected
information gain** — never randomly. Ranking combines: information gain,
attack-surface expansion, finding-validation potential, evidence improvement,
hypothesis discrimination, coverage improvement, cost, previous failures and
tool reliability.

Output contract per decision:
``NEXT_ACTION / REASON / EXPECTED_RESULT / PRIORITY / DEPENDENCIES /
ALTERNATIVES`` — all explainable, all persisted.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from hunterx.domain.mission_orchestration.enums import StrategyKind
from hunterx.domain.mission_orchestration.models import (
    MissionDecision,
    MissionHypothesis,
    NegativeEvidenceRecord,
)
from hunterx.shared.time import monotonic_ms, utcnow_iso


@dataclass(frozen=True, slots=True)
class CandidateAction:
    """A candidate action the decision engine can rank.

    Attributes:
        action_id: stable action identifier.
        capability: capability the action exercises.
        description: one-line action description.
        tool_ids: ordered compatible tool ids.
        expected_information_gain: estimated uncertainty removed in ``[0, 1]``.
        attack_surface_expansion: attack-surface expansion potential.
        finding_validation_potential: how much the action can validate findings.
        evidence_improvement: evidence-quality improvement potential.
        hypothesis_discrimination: hypothesis-discrimination value.
        coverage_improvement: coverage improvement potential.
        cost: resource cost estimate.
        dependencies: action ids that must complete first.
        reliability: historical tool reliability factor.

    """

    action_id: str
    capability: str
    description: str = ""
    tool_ids: tuple[str, ...] = ()
    expected_information_gain: float = 0.0
    attack_surface_expansion: float = 0.0
    finding_validation_potential: float = 0.0
    evidence_improvement: float = 0.0
    hypothesis_discrimination: float = 0.0
    coverage_improvement: float = 0.0
    cost: float = 0.1
    dependencies: tuple[str, ...] = ()
    reliability: float = 0.9
    #: Hypothesis this action is designed to test (evidence-driven probes only).
    hypothesis_id: str = ""


@dataclass(frozen=True, slots=True)
class DecisionInput:
    """Inputs the decision engine consumes.

    Attributes:
        mission_id: owning mission.
        candidates: candidate actions.
        hypotheses: open hypotheses.
        negative_evidence: recorded negative evidence (previous failures).
        coverage_ratio: current coverage ratio.
        strategy: orchestration strategy.
        ai_suggestion: advisory AI next-action (action id), if any.
        ai_reason: advisory AI rationale (never executed directly).

    """

    mission_id: str
    candidates: tuple[CandidateAction, ...] = ()
    hypotheses: tuple[MissionHypothesis, ...] = ()
    negative_evidence: tuple[NegativeEvidenceRecord, ...] = ()
    coverage_ratio: float = 0.0
    strategy: StrategyKind = StrategyKind.ADAPTIVE
    ai_suggestion: str = ""
    ai_reason: str = ""


class MissionDecisionEngine:
    """Rank candidate actions by expected information gain.

    The engine is deterministic: identical inputs yield identical rankings and
    decision records. AI suggestions are advisory — the ranking factors are
    always recomputed deterministically.
    """

    #: Factor weights per strategy (additive modifiers on top of the base
    #: information-gain weight). Strategies never override scope or safety.
    _STRATEGY_WEIGHTS: dict[StrategyKind, dict[str, float]] = {
        StrategyKind.ADAPTIVE: {
            "information_gain": 0.30,
            "hypothesis_discrimination": 0.20,
            "coverage_improvement": 0.15,
            "evidence_improvement": 0.10,
            "finding_validation_potential": 0.10,
            "attack_surface_expansion": 0.10,
            "cost": 0.05,
        },
        StrategyKind.BREADTH_FIRST: {
            "information_gain": 0.15,
            "attack_surface_expansion": 0.35,
            "coverage_improvement": 0.30,
            "cost": 0.20,
        },
        StrategyKind.DEPTH_FIRST: {
            "information_gain": 0.25,
            "hypothesis_discrimination": 0.40,
            "evidence_improvement": 0.35,
        },
        StrategyKind.RISK_FIRST: {
            "finding_validation_potential": 0.45,
            "evidence_improvement": 0.25,
            "information_gain": 0.30,
        },
        StrategyKind.ASSET_FIRST: {
            "attack_surface_expansion": 0.40,
            "coverage_improvement": 0.30,
            "information_gain": 0.30,
        },
        StrategyKind.TECHNOLOGY_FIRST: {
            "evidence_improvement": 0.40,
            "information_gain": 0.35,
            "coverage_improvement": 0.25,
        },
        StrategyKind.VULNERABILITY_FIRST: {
            "finding_validation_potential": 0.50,
            "hypothesis_discrimination": 0.30,
            "information_gain": 0.20,
        },
        StrategyKind.EVIDENCE_FIRST: {
            "evidence_improvement": 0.50,
            "finding_validation_potential": 0.30,
            "information_gain": 0.20,
        },
        StrategyKind.COVERAGE_FIRST: {
            "coverage_improvement": 0.50,
            "attack_surface_expansion": 0.30,
            "information_gain": 0.20,
        },
        StrategyKind.HYPOTHESIS_FIRST: {
            "hypothesis_discrimination": 0.50,
            "information_gain": 0.30,
            "evidence_improvement": 0.20,
        },
    }

    def decide(self, inp: DecisionInput) -> MissionDecision | None:
        """Return the highest-ranked decision or ``None`` when nothing is actionable."""
        started = monotonic_ms()
        if not inp.candidates:
            return None
        ranked = self.rank(inp)
        best = ranked[0]
        candidate, score = best
        reasons = _reasons_for(score, inp.strategy)
        alternatives: list[tuple[str, str]] = []
        for other, other_score in ranked[1:4]:
            why_not = (
                f"lower information gain ({other_score['information_gain']:.2f} "
                f"vs {score['information_gain']:.2f})"
            )
            alternatives.append((other.tool_ids[0] if other.tool_ids else other.capability, why_not))
        return MissionDecision(
            mission_id=inp.mission_id,
            next_action=candidate.action_id,
            capability=candidate.capability,
            tool_id=candidate.tool_ids[0] if candidate.tool_ids else "",
            reason=reasons["reason"],
            expected_result=reasons["expected_result"],
            priority=score["total"],
            dependencies=candidate.dependencies,
            alternatives=tuple(alternatives),
            information_gain=round(score["information_gain"], 4),
            factors={key: round(value, 4) for key, value in score.items() if key != "total"},
            ai_assisted=bool(inp.ai_suggestion and inp.ai_suggestion == candidate.action_id),
            decided_at=utcnow_iso(),
            latency_ms=monotonic_ms() - started,
        )

    def rank(self, inp: DecisionInput) -> list[tuple[CandidateAction, dict[str, float]]]:
        """Return candidates ranked by the strategy-weighted score.

        ``previous failures`` reduce a candidate's effective reliability;
        ``tool reliability`` is a multiplicative factor on information gain.
        """
        weights = self._weights(inp.strategy)
        open_by_id = {hypothesis.hypothesis_id: hypothesis for hypothesis in inp.hypotheses}
        results: list[tuple[CandidateAction, dict[str, float]]] = []
        for candidate in inp.candidates:
            failure_factor = self._failure_factor(candidate, inp.negative_evidence)
            reliability = candidate.reliability * failure_factor
            information_gain = candidate.expected_information_gain * reliability
            hypothesis_discrimination = self._hypothesis_factor(candidate, open_by_id)
            factors = {
                "information_gain": information_gain,
                "attack_surface_expansion": candidate.attack_surface_expansion,
                "finding_validation_potential": candidate.finding_validation_potential,
                "evidence_improvement": candidate.evidence_improvement,
                "hypothesis_discrimination": hypothesis_discrimination,
                "coverage_improvement": candidate.coverage_improvement,
                "cost": _cost_penalty(candidate.cost),
            }
            total = sum(factors[key] * weight for key, weight in weights.items() if key in factors)
            if inp.ai_suggestion and candidate.action_id == inp.ai_suggestion:
                total += 0.05
            factors["total"] = total
            results.append((candidate, factors))
        return sorted(results, key=lambda item: (-item[1]["total"], -item[0].expected_information_gain))

    @staticmethod
    def _hypothesis_factor(
        candidate: CandidateAction,
        open_by_id: dict[str, MissionHypothesis],
    ) -> float:
        """Return how well ``candidate`` pursues the open hypotheses.

        A candidate explicitly bound to an open hypothesis is boosted by that
        hypothesis's priority/confidence, so evidence genuinely drives the next
        action instead of a fixed capability order. The factor is bounded in
        ``[0, 1]``.
        """
        if candidate.hypothesis_id:
            hypothesis = open_by_id.get(candidate.hypothesis_id)
            if hypothesis is not None:
                return max(candidate.hypothesis_discrimination, round(hypothesis.priority * hypothesis.confidence, 3))
        return candidate.hypothesis_discrimination

    def _weights(self, strategy: StrategyKind) -> dict[str, float]:
        """Return the normalized factor weights for ``strategy``."""
        raw = self._STRATEGY_WEIGHTS.get(strategy, self._STRATEGY_WEIGHTS[StrategyKind.ADAPTIVE])
        total = sum(raw.values())
        return {key: value / total for key, value in raw.items()}

    @staticmethod
    def _failure_factor(candidate: CandidateAction, negatives: Iterable[NegativeEvidenceRecord]) -> float:
        """Return a ``[0.5, 1.0]`` reliability factor from previous failures."""
        failures = sum(
            1
            for record in negatives
            if record.capability == candidate.capability
            and record.kind.value in ("not_reproducible", "blocked", "inconclusive")
        )
        if failures == 0:
            return 1.0
        return max(0.5, 1.0 - 0.15 * failures)


def _cost_penalty(cost: float) -> float:
    """Convert a cost estimate to a ``[0, 1]`` penalty (lower is better)."""
    return max(0.0, 1.0 - cost)


def _reasons_for(score: Mapping[str, float], strategy: StrategyKind) -> dict[str, str]:
    """Build the explainable reason and expected-result strings."""
    reason = (
        f"Ranked highest across {len(score) - 1} decision factors for strategy "
        f"'{strategy.value}' with information gain {score['information_gain']:.2f}; "
        "selects the action that removes the most uncertainty at the lowest cost."
    )
    expected = (
        "Expected result: new observations that either validate, support or "
        "disprove an open hypothesis, and expand/confirm the attack surface."
    )
    return {"reason": reason, "expected_result": expected}


__all__ = [
    "CandidateAction",
    "DecisionInput",
    "MissionDecision",
    "MissionDecisionEngine",
]
