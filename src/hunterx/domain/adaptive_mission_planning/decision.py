# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Action decision engine.

The decision engine transforms target intelligence, coverage, unknowns,
hypotheses, mission objective, constraints, available tools and proof state
into ranked, policy-filtered candidate actions. Every candidate carries an
explainable rationale (why this action, why now, what information it provides,
what hypothesis it tests, what evidence is expected, what proof it enables,
which alternatives were rejected and why).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    ActionType,
    MissionMode,
    MissionObjective,
    ValidationLevel,
)
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    ActionProposal,
    MissionConstraints,
    PolicyDecision,
)
from hunterx.domain.adaptive_mission_planning.policy import PolicyEngine
from hunterx.domain.adaptive_mission_planning.scoring import ScoringModel, ScoringResult


class IntelligencePort(Protocol):
    """Read-only view of target intelligence needed by the decision engine."""

    def assets(self, mission_id: str = "") -> list[Any]:
        """Return assets relevant to the mission."""

    def coverage_gaps(self, mission_id: str = "") -> list[Any]:
        """Return coverage gaps for the mission."""

    def hypotheses(self, mission_id: str = "") -> list[Any]:
        """Return open hypotheses for the mission."""

    def unknowns(self, mission_id: str = "") -> list[Any]:
        """Return unknowns/gaps for the mission."""


@dataclass(frozen=True, slots=True)
class DecisionInput:
    """Everything the decision engine needs to rank candidate actions."""

    mission_id: str = ""
    objective: MissionObjective = MissionObjective.ATTACK_SURFACE_DISCOVERY
    mode: MissionMode = MissionMode.BALANCED
    intelligence: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    unknowns: tuple[Any, ...] = ()
    hypotheses: tuple[Any, ...] = ()
    available_tools: tuple[str, ...] = ()
    tool_health: dict[str, Any] = field(default_factory=dict)
    proof_state: dict[str, Any] = field(default_factory=dict)
    constraints: MissionConstraints = field(default_factory=MissionConstraints)
    authorization_context: str = "default"
    safety_ceiling: str = "low_impact_active"
    ai_proposals: tuple[ActionNode, ...] = ()
    ai_assisted: bool = False
    completion_threshold: float = 0.9


@dataclass(slots=True)
class DecisionResult:
    """Ranked, policy-filtered candidate actions plus decisions.

    Attributes:
        proposals: ranked :class:`ActionProposal` list (already policy-filtered).
        rejected: policy rejections (action id → :class:`PolicyDecision`).
        decision: the explainable decision record.
        scores: per-action :class:`ScoringResult` map.

    """

    proposals: list[ActionProposal] = field(default_factory=list)
    rejected: dict[str, PolicyDecision] = field(default_factory=dict)
    decision: Any = None
    scores: dict[str, ScoringResult] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the decision result to a JSON-safe mapping."""
        return {
            "proposals": [proposal.to_dict() for proposal in self.proposals],
            "rejected": {key: value.to_dict() for key, value in self.rejected.items()},
            "decision": self.decision.to_dict() if self.decision else None,
            "scores": {key: value.to_dict() for key, value in self.scores.items()},
        }


class ActionDecisionEngine:
    """Rank candidate actions and filter them through policy.

    Args:
        scoring: optional :class:`ScoringModel` (defaults to balanced mode).
        policy: optional :class:`PolicyEngine`.
        objective_defaults: default capability set for an objective when no
            intelligence is supplied (deterministic fallback planning).
        cap: maximum number of ranked proposals returned.

    """

    def __init__(
        self,
        *,
        scoring: ScoringModel | None = None,
        policy: PolicyEngine | None = None,
        cap: int = 10,
    ) -> None:
        self.scoring = scoring or ScoringModel()
        self.policy = policy or PolicyEngine()
        self.cap = cap

    def decide(self, inp: DecisionInput) -> DecisionResult:
        """Rank candidate actions for ``inp``.

        Deterministic candidate generation always runs; AI proposals are
        appended as advisory candidates and filtered through the same policy
        gates. The result is a ranked list whose ordering and rationale are
        fully explainable.
        """
        candidates = self._generate_candidates(inp)
        candidates.extend(inp.ai_proposals)

        result = DecisionResult()
        scored: list[tuple[float, ActionNode, ScoringResult]] = []
        for action in candidates:
            policy_decision = self.policy.check_proposal(
                action,
                inp.constraints,
                authorization_context=inp.authorization_context,
                safety_ceiling=inp.safety_ceiling,
                ai_proposed=action.provenance.get("ai_assisted", False),
            )
            if not policy_decision.allowed:
                result.rejected[action.action_id] = policy_decision
                continue
            context = self._score_context(action, inp)
            scoring_result = self.scoring.score(action, context=context)
            scored.append((scoring_result.score, action, scoring_result))

        scored.sort(key=lambda item: (-item[0], item[1].priority))
        for score, action, scoring_result in scored[: self.cap]:
            proposal = self._to_proposal(action, score, scoring_result, scored, inp)
            result.proposals.append(proposal)
            result.scores[action.action_id] = scoring_result

        result.decision = self._build_decision(result.proposals, inp)
        return result

    # -- candidate generation (deterministic fallback planning) -------------

    def _generate_candidates(self, inp: DecisionInput) -> list[ActionNode]:
        candidates: list[ActionNode] = []
        for gap in inp.unknowns:
            node = self._from_gap(gap, inp)
            if node is not None:
                candidates.append(node)
        for hypothesis in inp.hypotheses:
            node = self._from_hypothesis(hypothesis, inp)
            if node is not None:
                candidates.append(node)
        if not candidates:
            candidates = self._objective_defaults(inp)
        return candidates

    def _from_gap(self, gap: Any, inp: DecisionInput) -> ActionNode | None:
        capability = getattr(gap, "required_capability", None)
        if capability is None:
            return None
        capability_name = capability.value if hasattr(capability, "value") else str(capability)
        asset = getattr(gap, "asset_key", "") or ""
        importance = float(getattr(gap, "importance", 0.5) or 0.5)
        return ActionNode(
            mission_id=inp.mission_id,
            objective=inp.objective,
            action_type=_action_for_capability(capability_name),
            asset=asset,
            capability=capability_name,
            expected_information_gain=importance,
            expected_evidence=(f"evidence:{capability_name}",),
            status=ActionStatus.PROPOSED,
            priority=1.0,
            provenance={"source": "information_gap", "gap_id": getattr(gap, "gap_id", "")},
        )

    def _from_hypothesis(self, hypothesis: Any, inp: DecisionInput) -> ActionNode | None:
        hypothesis_id = getattr(hypothesis, "hypothesis_id", "") or getattr(hypothesis, "id", "")
        asset = getattr(hypothesis, "asset_key", "") or ""
        raw_confidence = getattr(hypothesis, "confidence", None)
        confidence = float(raw_confidence) if isinstance(raw_confidence, (int, float)) else 0.5
        statement = getattr(hypothesis, "statement", "")
        hypothesis_type = getattr(hypothesis, "category", None)
        type_value = getattr(hypothesis_type, "value", None) or str(hypothesis_type or "unknown")
        capability = _capability_for_hypothesis(type_value)
        validation = (
            ValidationLevel.PROOF if inp.objective in (MissionObjective.BUG_BOUNTY_ASSESSMENT, MissionObjective.PROOF_COLLECTION)
            else ValidationLevel.VALIDATION
        )
        return ActionNode(
            mission_id=inp.mission_id,
            objective=inp.objective,
            action_type=ActionType.VALIDATE_HYPOTHESIS,
            asset=asset,
            capability=capability,
            hypothesis_id=hypothesis_id,
            expected_information_gain=confidence,
            expected_evidence=(f"evidence:{capability}:{hypothesis_id}",),
            expected_proof_value=confidence if validation is ValidationLevel.PROOF else 0.0,
            validation_level=validation,
            status=ActionStatus.PROPOSED,
            priority=confidence,
            provenance={"source": "hypothesis", "hypothesis_id": hypothesis_id, "statement": statement},
        )

    def _objective_defaults(self, inp: DecisionInput) -> list[ActionNode]:
        """Deterministic fallback: seed discovery actions from the objective."""
        nodes: list[ActionNode] = []
        for capability in _objective_discovery_capabilities(inp.objective):
            nodes.append(
                ActionNode(
                    mission_id=inp.mission_id,
                    objective=inp.objective,
                    action_type=_action_for_capability(capability),
                    capability=capability,
                    expected_information_gain=0.7,
                    expected_evidence=(f"evidence:{capability}",),
                    status=ActionStatus.PROPOSED,
                    priority=0.5,
                    provenance={"source": "objective_default", "objective": inp.objective.value},
                )
            )
        return nodes

    # -- internals ----------------------------------------------------------

    def _score_context(self, action: ActionNode, inp: DecisionInput) -> dict[str, Any]:
        tool = action.selected_tool or (action.tool_candidate_set[0] if action.tool_candidate_set else "")
        health = inp.tool_health.get(tool) if tool else None
        effectiveness = 0.6
        if isinstance(health, dict):
            raw = health.get("reliability_score", health.get("effectiveness", 0.6))
            effectiveness = float(raw) if isinstance(raw, (int, float)) else 0.6
        return {
            "asset_criticality": 0.5,
            "mission_priority": 0.5,
            "tool_effectiveness": effectiveness,
            "redundancy": 0.0,
            "dependency_ready": True,
        }

    def _to_proposal(
        self,
        action: ActionNode,
        score: float,
        scoring_result: ScoringResult,
        scored: list[tuple[float, ActionNode, ScoringResult]],
        inp: DecisionInput,
    ) -> ActionProposal:
        alternatives = tuple(
            (other.action_id, f"score {other_score:.2f} vs {score:.2f}")
            for other_score, other, _ in scored
            if other.action_id != action.action_id
        )[:3]
        ai_assisted = bool(action.provenance.get("ai_assisted", False))
        return ActionProposal(
            action=action,
            score=round(score, 4),
            factors=scoring_result.factors,
            rationale=(
                f"Objective '{inp.objective.value}' requires capability "
                f"'{action.capability}' for {action.action_type.value}; {scoring_result.rationale}"
            ),
            alternatives=alternatives,
            ai_assisted=ai_assisted,
            ai_overridden=False,
            policy_applied="policy/1.0.0",
        )

    def _build_decision(self, proposals: list[ActionProposal], inp: DecisionInput) -> Any:
        best = proposals[0] if proposals else None
        from hunterx.domain.adaptive_mission_planning.models import DecisionRecord

        return DecisionRecord(
            mission_id=inp.mission_id,
            action_id=best.action.action_id if best else "",
            tool_id=best.action.selected_tool if best else "",
            why_this_action=f"Highest ranked action for objective '{inp.objective.value}'" if best else "No actionable proposal",
            why_now=(
                f"Mode '{inp.mode.value}'; {len(inp.hypotheses)} hypotheses, "
                f"{len(inp.unknowns)} information gaps"
            ),
            why_this_tool=best.action.selected_tool if best and best.action.selected_tool else "tool selected at execution",
            information_provided=", ".join(best.action.expected_observations) if best else "",
            hypothesis_tested=best.action.hypothesis_id if best else "",
            evidence_expected=", ".join(best.action.expected_evidence) if best else "",
            proof_enabled=f"proof value {best.action.expected_proof_value:.2f}" if best else "",
            alternatives=best.alternatives if best else (),
            decision_provenance={
                "objective": inp.objective.value,
                "mode": inp.mode.value,
                "authorization_context": inp.authorization_context,
                "safety_ceiling": inp.safety_ceiling,
            },
        )


def _action_for_capability(capability: str) -> ActionType:
    mapping: dict[str, ActionType] = {
        "asset_discovery": ActionType.DISCOVER_SUBDOMAINS,
        "subdomain_enumeration": ActionType.DISCOVER_SUBDOMAINS,
        "dns_enumeration": ActionType.ENUMERATE_DNS,
        "port_discovery": ActionType.IDENTIFY_SERVICES,
        "service_detection": ActionType.IDENTIFY_SERVICES,
        "technology_fingerprint": ActionType.IDENTIFY_TECHNOLOGY,
        "endpoint_enumeration": ActionType.DISCOVER_ENDPOINTS,
        "content_discovery": ActionType.DISCOVER_ENDPOINTS,
        "parameter_discovery": ActionType.DISCOVER_PARAMETERS,
        "api_mapping": ActionType.MAP_API,
        "graphql_enumeration": ActionType.MAP_GRAPHQL,
        "authentication_analysis": ActionType.ANALYZE_AUTHENTICATION,
        "authorization_analysis": ActionType.TEST_AUTHORIZATION,
        "vulnerability_scanning": ActionType.VALIDATE_HYPOTHESIS,
        "proof_validation": ActionType.COLLECT_PROOF,
        "replay": ActionType.REPLAY_PROOF,
    }
    return mapping.get(capability, ActionType.INVESTIGATE_BEHAVIOR)


def _capability_for_hypothesis(hypothesis_type: str) -> str:
    mapping: dict[str, str] = {
        "injection": "sql_injection",
        "xss": "xss",
        "ssrf": "ssrf",
        "ssti": "ssti",
        "xxe": "xxe",
        "lfi": "lfi",
        "rfi": "lfi",
        "rce": "rce",
        "idor": "idor",
        "authorization_issue": "authorization_analysis",
        "authentication_issue": "authentication_analysis",
        "api_security": "api_security",
        "graphql_security": "graphql_security",
        "cloud_exposure": "cloud_ownership_mapping",
        "secret_exposure": "secret_detection",
        "dependency_vulnerability": "dependency_check",
        "known_vulnerability": "vulnerability_scanning",
        "unknown_behavior": "vulnerability_scanning",
        "novel_variant": "vulnerability_scanning",
    }
    return mapping.get(hypothesis_type, "vulnerability_scanning")


def _objective_discovery_capabilities(objective: MissionObjective) -> tuple[str, ...]:
    defaults: dict[MissionObjective, tuple[str, ...]] = {
        MissionObjective.ATTACK_SURFACE_DISCOVERY: ("subdomain_enumeration", "port_discovery"),
        MissionObjective.WEB_SECURITY_ASSESSMENT: ("endpoint_enumeration", "parameter_discovery"),
        MissionObjective.API_SECURITY_ASSESSMENT: ("api_mapping", "endpoint_enumeration"),
        MissionObjective.CLOUD_SECURITY_ASSESSMENT: ("asset_discovery",),
        MissionObjective.NETWORK_SECURITY_ASSESSMENT: ("port_discovery", "service_detection"),
        MissionObjective.VULNERABILITY_DISCOVERY: ("technology_fingerprint",),
        MissionObjective.BUG_BOUNTY_ASSESSMENT: ("endpoint_enumeration", "parameter_discovery"),
        MissionObjective.PENTEST_ASSESSMENT: ("asset_discovery", "endpoint_enumeration"),
        MissionObjective.RED_TEAM_SIMULATION: ("asset_discovery",),
        MissionObjective.TARGET_MONITORING: ("asset_discovery",),
        MissionObjective.FINDING_VALIDATION: ("proof_validation",),
        MissionObjective.PROOF_COLLECTION: ("proof_validation",),
    }
    return defaults.get(objective, ("asset_discovery",))
