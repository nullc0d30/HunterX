# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Next-Action Engine.

Sprint 026. The central decision engine. It receives the current target state,
coverage, unknowns, hypotheses, mission objective, scope, safety policy,
available tools, tool health/capabilities/cost/risk, previous executions and
historical results, then produces ranked, explainable actions.

Ranking uses configurable, explainable weights — never blindly hard-coded
numerical scores in the ranking logic:

    Priority = information_gain + hypothesis_relevance + coverage_gap
            + evidence_value + proof_value
            - execution_cost - risk - redundancy

Each action carries the objective, asset, required capability, selected tool,
reason, expected information gain, evidence, cost, risk, scope status,
preconditions, stop conditions, fallback and priority. Tool *selection* is
delegated to a pluggable adapter (the Sprint 025 selector) so the engine stays
pure and testable.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from hunterx.domain.target_intelligence.enums import (
    ActionStatus,
    ActionType,
    CoverageCapability,
    CoverageState,
    HypothesisStatus,
    IntelligencePhase,
    StopCondition,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceAction,
    IntelligenceDecision,
    IntelligenceTarget,
    TargetIntelligenceState,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Default ranking weights. Configurable via policy and recorded on decisions.
DEFAULT_RANKING_WEIGHTS: dict[str, float] = {
    "information_gain": 0.30,
    "hypothesis_relevance": 0.20,
    "coverage_gap": 0.15,
    "evidence_value": 0.10,
    "proof_value": 0.10,
    "execution_cost": 0.15,
    "risk": 0.15,
    "redundancy": 0.10,
}


@dataclass(frozen=True, slots=True)
class RankingWeights:
    """Explainable, configurable weights for action ranking.

    Attributes:
        information_gain: weight for expected information gain.
        hypothesis_relevance: weight for relevance to open hypotheses.
        coverage_gap: weight for closing coverage gaps.
        evidence_value: weight for evidence the action produces.
        proof_value: weight for moving toward proof.
        execution_cost: penalty weight for execution cost.
        risk: penalty weight for action risk.
        redundancy: penalty weight for redundant/repeated work.

    """

    information_gain: float = 0.30
    hypothesis_relevance: float = 0.20
    coverage_gap: float = 0.15
    evidence_value: float = 0.10
    proof_value: float = 0.10
    execution_cost: float = 0.15
    risk: float = 0.15
    redundancy: float = 0.10

    @classmethod
    def from_mapping(cls, values: dict[str, float]) -> RankingWeights:
        """Build weights from a mapping, filling unset fields with defaults."""
        defaults = cls()
        merged = {name: getattr(defaults, name) for name in cls.__dataclass_fields__}
        for key, value in values.items():
            if key in merged:
                merged[key] = value
        return cls(**merged)

    def to_dict(self) -> dict[str, float]:
        """Return the weights as a mapping."""
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class ToolSelectorAdapter(Protocol):
    """Pluggable tool selection for a required capability.

    The application layer wires this to the Sprint 025 selector. Returns a
    ``(tool_id, alternatives, reason)`` tuple, or ``("", (), reason)`` when no
    tool is available.
    """

    def select(
        self,
        *,
        target: IntelligenceTarget,
        capability: CoverageCapability,
        asset_key: str = "",
        mission_id: str = "",
    ) -> tuple[str, tuple[str, ...], str]:
        """Select a tool for a required capability, returning tool/alternatives/reason."""


class NextActionEngine:
    """Rank the next best actions for a target state.

    Attributes:
        weights: configurable :class:`RankingWeights`.
        tool_selector: optional :class:`ToolSelectorAdapter`.
        action_budget: maximum number of actions returned (``0`` = unlimited).

    """

    def __init__(
        self,
        *,
        weights: RankingWeights | dict[str, float] | None = None,
        tool_selector: ToolSelectorAdapter | None = None,
        action_budget: int = 0,
    ) -> None:
        if isinstance(weights, dict):
            self.weights = RankingWeights.from_mapping(weights)
        else:
            self.weights = weights or RankingWeights()
        self.tool_selector = tool_selector
        self.action_budget = action_budget

    # -- main entry ---------------------------------------------------------

    def rank(
        self,
        state: TargetIntelligenceState,
        *,
        mission_objective: str = "",
        available_tools: Sequence[str] | None = None,
        safety_ceiling: str = "high_impact",
        authorization_granted: bool = False,
        previous_actions: Sequence[IntelligenceAction] = (),
    ) -> tuple[list[IntelligenceAction], IntelligenceDecision]:
        """Return ``(ranked_actions, decision)`` for the current state.

        The decision carries the rationale, alternatives and policy applied so
        every adaptive decision is explainable and reproducible.
        """
        candidates: list[IntelligenceAction] = []
        candidates.extend(self._discovery_actions(state))
        candidates.extend(self._hypothesis_actions(state))
        candidates.extend(self._gap_actions(state, available_tools=available_tools))
        candidates.extend(self._phase_actions(state, mission_objective))

        ranked = self._rank(candidates, state, previous_actions=previous_actions)
        ranked = self._enforce_budget(ranked)
        ranked = self._apply_safety(ranked, safety_ceiling=safety_ceiling, authorization_granted=authorization_granted)

        rationale = [
            f"ranked {len(ranked)} actions for target {state.target.target_id}",
            f"policy: {self._policy_id()}",
            *(f"{action.objective} (priority {round(action.priority, 3)})" for action in ranked[:5]),
        ]
        decision = IntelligenceDecision(
            decision_id=generate_id(),
            target_id=state.target.target_id,
            mission_id=state.target.mission_id,
            kind="next-action",
            payload={
                "count": len(ranked),
                "phase": state.target.phase.value,
                "budget": self.action_budget,
                "weights": self.weights.to_dict(),
            },
            rationale=tuple(rationale),
            policy_applied=(self._policy_id(),),
            alternatives=tuple(action.tool for action in ranked if action.tool),
            created_at=utcnow_iso(),
        )
        for action in ranked:
            object.__setattr__(action, "decision_id", decision.decision_id)
        return ranked, decision

    # -- candidate builders -------------------------------------------------

    def _discovery_actions(self, state: TargetIntelligenceState) -> list[IntelligenceAction]:
        """Actions that discover/enumerate new assets from coverage gaps."""
        actions: list[IntelligenceAction] = []
        matrix = state.coverage
        for capability, objective, stop_conds in (
            (CoverageCapability.SUBDOMAIN_ENUMERATION, "Enumerate subdomains", (StopCondition.SCOPE_EXHAUSTED, StopCondition.RATE_LIMIT)),
            (CoverageCapability.PORT_DISCOVERY, "Discover open ports", (StopCondition.SCOPE_EXHAUSTED, StopCondition.RATE_LIMIT)),
            (CoverageCapability.DNS_ENUMERATION, "Enumerate DNS records", (StopCondition.SCOPE_EXHAUSTED, StopCondition.RATE_LIMIT)),
            (CoverageCapability.CERTIFICATE_ENUMERATION, "Enumerate certificates", (StopCondition.SCOPE_EXHAUSTED,)),
            (CoverageCapability.CLOUD_OWNERSHIP_MAPPING, "Map cloud ownership", (StopCondition.SCOPE_EXHAUSTED,)),
        ):
            if matrix.state("", capability).uncovered():
                actions.append(
                    self._build(
                        state=state,
                        asset_key="",
                        action_type=ActionType.ENUMERATE,
                        objective=objective,
                        capability=capability,
                        gain=0.8,
                        stop_conditions=stop_conds,
                    )
                )
        return actions

    def _gap_actions(
        self,
        state: TargetIntelligenceState,
        *,
        available_tools: Sequence[str] | None = None,
    ) -> list[IntelligenceAction]:
        """Actions that close the most important open information gaps."""
        actions: list[IntelligenceAction] = []
        for gap in sorted(state.gaps, key=lambda g: -g.importance):
            action_type = _gap_action_type(gap.required_capability)
            gain = 0.5 + 0.4 * gap.importance
            action = self._build(
                state=state,
                asset_key=gap.asset_key,
                action_type=action_type,
                objective=gap.question,
                capability=gap.required_capability,
                gain=min(gain, 0.95),
                candidates=gap.candidate_tools,
                stop_conditions=(StopCondition.SUFFICIENT_EVIDENCE, StopCondition.RATE_LIMIT),
                preconditions=("scope_authorized",),
                fallback=f"skip {gap.category.value}",
            )
            if available_tools and action.tool and action.tool not in available_tools:
                available = [tool for tool in gap.candidate_tools if tool in available_tools]
                action = self._with_tool(action, available[0] if available else "")
            actions.append(action)
        return actions

    def _hypothesis_actions(self, state: TargetIntelligenceState) -> list[IntelligenceAction]:
        """Actions that validate or prove open hypotheses."""
        actions: list[IntelligenceAction] = []
        for hypothesis in state.hypotheses:
            if hypothesis.status in (HypothesisStatus.DISMISSED, HypothesisStatus.PROVEN):
                continue
            capability = CoverageCapability.for_hypothesis(hypothesis.category.value)
            matrix_state = state.coverage.state(hypothesis.asset_key, capability)
            if matrix_state is CoverageState.VALIDATED:
                # Move to proof when evidence justifies it.
                actions.append(
                    self._build(
                        state=state,
                        asset_key=hypothesis.asset_key,
                        action_type=ActionType.PROVE,
                        objective=f"Prove: {hypothesis.statement}",
                        capability=capability,
                        gain=0.9,
                        stop_conditions=(StopCondition.PROOF_VALIDATED, StopCondition.RISK_THRESHOLD),
                        preconditions=("evidence_justifies_proof", "scope_authorized"),
                        fallback="record proof as inconclusive",
                    )
                )
            elif matrix_state.uncovered():
                actions.append(
                    self._build(
                        state=state,
                        asset_key=hypothesis.asset_key,
                        action_type=ActionType.VALIDATE,
                        objective=f"Validate: {hypothesis.statement}",
                        capability=capability,
                        gain=0.7,
                        stop_conditions=(StopCondition.SUFFICIENT_EVIDENCE, StopCondition.RISK_THRESHOLD),
                        preconditions=("scope_authorized",),
                        fallback="keep hypothesis open",
                    )
                )
        return actions

    def _phase_actions(self, state: TargetIntelligenceState, mission_objective: str) -> list[IntelligenceAction]:
        """Phase-aware actions (analysis, reassess, monitor, stop)."""
        actions: list[IntelligenceAction] = []
        phase = state.target.phase
        if phase.rank <= IntelligencePhase.ANALYSIS.rank:
            actions.append(
                self._build(
                    state=state,
                    asset_key="",
                    action_type=ActionType.ANALYZE,
                    objective="Analyze collected intelligence and generate hypotheses",
                    capability=CoverageCapability.VULNERABILITY_SCANNING,
                    gain=0.4,
                    stop_conditions=(StopCondition.SUFFICIENT_EVIDENCE,),
                )
            )
        if mission_objective:
            actions.append(
                self._build(
                    state=state,
                    asset_key="",
                    action_type=ActionType.REASSESS,
                    objective=f"Reassess against mission objective: {mission_objective}",
                    capability=CoverageCapability.ASSET_DISCOVERY,
                    gain=0.3,
                    stop_conditions=(StopCondition.SUFFICIENT_EVIDENCE,),
                )
            )
        if phase.rank >= IntelligencePhase.VALIDATION.rank and not state.hypotheses:
            actions.append(
                self._build(
                    state=state,
                    asset_key="",
                    action_type=ActionType.STOP,
                    objective="No open hypotheses remain; evaluate terminal coverage",
                    capability=CoverageCapability.PROOF_VALIDATION,
                    gain=0.0,
                    stop_conditions=(StopCondition.SUFFICIENT_EVIDENCE,),
                )
            )
        return actions

    # -- ranking ------------------------------------------------------------

    def _rank(
        self,
        actions: list[IntelligenceAction],
        state: TargetIntelligenceState,
        *,
        previous_actions: Sequence[IntelligenceAction],
    ) -> list[IntelligenceAction]:
        scored: list[tuple[float, IntelligenceAction]] = []
        done = {action.objective for action in previous_actions if action.status in (ActionStatus.COMPLETED, ActionStatus.RUNNING)}
        for action in actions:
            redundancy = 1.0 if action.objective in done else 0.0
            score = self._score(action, state, redundancy=redundancy)
            scored.append((score, action))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [self._with_priority(action, score) for score, action in scored]

    def _score(self, action: IntelligenceAction, state: TargetIntelligenceState, *, redundancy: float) -> float:
        """Compute the weighted, explainable priority of an action in ``[0, 1]``."""
        w = self.weights
        information_gain = action.expected_information_gain
        hypothesis_relevance = self._hypothesis_relevance(action, state)
        coverage_gap = 1.0 if state.coverage.state(action.asset_key, action.required_capability).uncovered() else 0.0
        evidence_value = min(0.5, 0.25 * len(action.expected_evidence))
        proof_value = 0.8 if action.action_type is ActionType.PROVE else 0.2
        risk = _risk_value(action.risk)
        cost = min(1.0, action.estimated_cost)

        score = (
            w.information_gain * information_gain
            + w.hypothesis_relevance * hypothesis_relevance
            + w.coverage_gap * coverage_gap
            + w.evidence_value * evidence_value
            + w.proof_value * proof_value
            - w.execution_cost * cost
            - w.risk * risk
            - w.redundancy * redundancy
        )
        return max(0.0, min(1.0, score))

    @staticmethod
    def _hypothesis_relevance(action: IntelligenceAction, state: TargetIntelligenceState) -> float:
        for hypothesis in state.hypotheses:
            if (hypothesis.asset_key == action.asset_key or action.asset_key == "") and CoverageCapability.for_hypothesis(
                hypothesis.category.value
            ) is action.required_capability:
                return 1.0
        return 0.2

    @staticmethod
    def _enforce_budget(actions: list[IntelligenceAction]) -> list[IntelligenceAction]:
        if not actions:
            return actions
        if actions[0].action_type is ActionType.STOP:
            return actions[:1]
        return actions[:10]

    def _apply_safety(
        self,
        actions: list[IntelligenceAction],
        *,
        safety_ceiling: str,
        authorization_granted: bool,
    ) -> list[IntelligenceAction]:
        ceiling = _RISK_RANK.get(safety_ceiling, 3)
        filtered: list[IntelligenceAction] = []
        for action in actions:
            risk = _RISK_RANK.get(action.risk, 0)
            if risk > ceiling:
                action = self._with_tool(action, "")
                action = self._block(action, reason=f"risk {action.risk} exceeds ceiling {safety_ceiling}")
            elif risk >= 2 and not authorization_granted:
                action = self._with_tool(action, "")
                action = self._block(action, reason="requires authorization")
            filtered.append(action)
        return filtered

    # -- construction helpers ----------------------------------------------

    def _build(
        self,
        *,
        state: TargetIntelligenceState,
        asset_key: str,
        action_type: ActionType,
        objective: str,
        capability: CoverageCapability,
        gain: float,
        stop_conditions: Sequence[StopCondition],
        candidates: Sequence[str] = (),
        preconditions: Sequence[str] = (),
        fallback: str = "",
    ) -> IntelligenceAction:
        tool, alternatives, reason = self._select_tool(state, capability, asset_key)
        return IntelligenceAction(
            action_id=generate_id(),
            target_id=state.target.target_id,
            mission_id=state.target.mission_id,
            asset_key=asset_key,
            objective=objective,
            action_type=action_type,
            required_capability=capability,
            tool=tool,
            reason=reason or f"required capability: {capability.value}",
            expected_information_gain=gain,
            expected_evidence=(capability.value,),
            risk=_RISK_BY_CAPABILITY.get(capability, "passive"),
            scope_status="in_scope",
            preconditions=tuple(preconditions),
            stop_conditions=tuple(stop_conditions),
            fallback=fallback,
            status=ActionStatus.PROPOSED,
            candidates=alternatives or tuple(candidates),
            created_at=utcnow_iso(),
        )

    def _select_tool(
        self,
        state: TargetIntelligenceState,
        capability: CoverageCapability,
        asset_key: str,
    ) -> tuple[str, tuple[str, ...], str]:
        if self.tool_selector is not None:
            try:
                tool, alternatives, reason = self.tool_selector.select(
                    target=state.target,
                    capability=capability,
                    asset_key=asset_key,
                    mission_id=state.target.mission_id,
                )
                return tool, alternatives, reason
            except Exception:  # noqa: BLE001 - selector failures degrade gracefully
                return "", (), "tool selection unavailable"
        return "", (), f"required capability: {capability.value}"

    @staticmethod
    def _with_tool(action: IntelligenceAction, tool: str) -> IntelligenceAction:
        import dataclasses

        return dataclasses.replace(action, tool=tool)

    @staticmethod
    def _with_priority(action: IntelligenceAction, priority: float) -> IntelligenceAction:
        import dataclasses

        return dataclasses.replace(action, priority=round(priority, 4))

    @staticmethod
    def _block(action: IntelligenceAction, *, reason: str) -> IntelligenceAction:
        import dataclasses

        return dataclasses.replace(action, status=ActionStatus.BLOCKED, reason=f"{action.reason}; blocked: {reason}")

    def _policy_id(self) -> str:
        return "target-intelligence/ranking/1.0.0"


#: Risk rank ordering for safety-ceiling enforcement.
_RISK_RANK: dict[str, int] = {
    "passive": 0,
    "read_only": 0,
    "low": 1,
    "low_impact_active": 1,
    "active": 2,
    "high": 3,
    "high_impact": 3,
    "restricted": 4,
}

#: Baseline risk label per capability.
_RISK_BY_CAPABILITY: dict[CoverageCapability, str] = {
    CoverageCapability.ASSET_DISCOVERY: "passive",
    CoverageCapability.SUBDOMAIN_ENUMERATION: "passive",
    CoverageCapability.PORT_DISCOVERY: "low",
    CoverageCapability.SERVICE_DETECTION: "passive",
    CoverageCapability.TECHNOLOGY_FINGERPRINT: "passive",
    CoverageCapability.CONTENT_DISCOVERY: "low",
    CoverageCapability.PARAMETER_DISCOVERY: "low",
    CoverageCapability.ENDPOINT_ENUMERATION: "low",
    CoverageCapability.API_MAPPING: "low",
    CoverageCapability.GRAPHQL_ENUMERATION: "low",
    CoverageCapability.DNS_ENUMERATION: "passive",
    CoverageCapability.CERTIFICATE_ENUMERATION: "passive",
    CoverageCapability.CLOUD_OWNERSHIP_MAPPING: "passive",
    CoverageCapability.AUTHENTICATION_ANALYSIS: "active",
    CoverageCapability.AUTHORIZATION_ANALYSIS: "active",
    CoverageCapability.VULNERABILITY_SCANNING: "low",
    CoverageCapability.SQL_INJECTION: "active",
    CoverageCapability.XSS: "active",
    CoverageCapability.SSRF: "active",
    CoverageCapability.SSTI: "active",
    CoverageCapability.XXE: "active",
    CoverageCapability.LFI: "active",
    CoverageCapability.RCE: "high",
    CoverageCapability.IDOR: "active",
    CoverageCapability.API_SECURITY: "low",
    CoverageCapability.GRAPHQL_SECURITY: "low",
    CoverageCapability.SECRET_DETECTION: "passive",
    CoverageCapability.DEPENDENCY_CHECK: "passive",
    CoverageCapability.PROOF_VALIDATION: "active",
    CoverageCapability.REPLAY: "low",
}


def _risk_value(label: str) -> float:
    return _RISK_RANK.get(label, 0) / 4.0


def _gap_action_type(capability: CoverageCapability) -> ActionType:
    if capability in (CoverageCapability.PROOF_VALIDATION, CoverageCapability.REPLAY):
        return ActionType.PROVE
    if capability in (
        CoverageCapability.SQL_INJECTION,
        CoverageCapability.XSS,
        CoverageCapability.SSRF,
        CoverageCapability.SSTI,
        CoverageCapability.XXE,
        CoverageCapability.LFI,
        CoverageCapability.RCE,
        CoverageCapability.IDOR,
        CoverageCapability.API_SECURITY,
        CoverageCapability.GRAPHQL_SECURITY,
    ):
        return ActionType.TEST
    if capability in (
        CoverageCapability.AUTHENTICATION_ANALYSIS,
        CoverageCapability.AUTHORIZATION_ANALYSIS,
        CoverageCapability.API_MAPPING,
        CoverageCapability.GRAPHQL_ENUMERATION,
        CoverageCapability.JAVASCRIPT_ANALYSIS,
    ):
        return ActionType.MAP
    return ActionType.ENUMERATE


__all__ = [
    "ActionStatus",
    "ActionType",
    "DEFAULT_RANKING_WEIGHTS",
    "IntelligenceAction",
    "IntelligenceDecision",
    "NextActionEngine",
    "RankingWeights",
    "StopCondition",
    "ToolSelectorAdapter",
]
