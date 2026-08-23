# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission policy & stop-condition engine.

Sprint 032. Policies define mission intent: objective, scope, allowed
techniques, resource limits, time limits, authentication contexts, validation
depth, proof depth, coverage target and stop conditions. Policies are mission
configuration — never hardcoded into individual tools. Stop conditions are
evaluated deterministically after every observation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.mission import OrchestratedMission


@dataclass(frozen=True, slots=True)
class PolicyVerdict:
    """Result of a policy gate evaluation.

    Attributes:
        allowed: ``True`` when the action passes the gate.
        reason: human-readable gate explanation.
        gates: per-gate pass/fail map.

    """

    allowed: bool
    reason: str
    gates: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {"allowed": self.allowed, "reason": self.reason, "gates": self.gates}


class MissionPolicyEngine:
    """Enforce mission policies on candidate actions.

    Every action receives the mission context, target context, scope context
    and execution policy. The gate chain is: scope → authorization → technique
    → resource budget → concurrency.

    Stop conditions are evaluated after every observation. Coverage-derived
    conditions (``COVERAGE_TARGET_ACHIEVED``) are NOT terminal on their own:
    they become terminal only when the mission's objective completion contract
    confirms every mandatory dimension was assessed (see
    :mod:`hunterx.domain.mission_orchestration.completion`). The contract is
    injected by the orchestrator via :attr:`completion_gate`.
    """

    #: Injected objective completion contract: ``(mission) -> (satisfied, unmet)``.
    completion_gate: Callable[[OrchestratedMission], tuple[bool, list[str]]] | None = None

    def __init__(
        self,
        *,
        completion_gate: Callable[[OrchestratedMission], tuple[bool, list[str]]] | None = None,
    ) -> None:
        self.completion_gate = completion_gate

    def check_action(
        self,
        mission: OrchestratedMission,
        *,
        capability: str,
        target: str,
        technique: str = "",
    ) -> PolicyVerdict:
        """Evaluate the policy gates for an action."""
        gates: dict[str, bool] = {}

        scope_gate = mission.context.scope.allows(target) if target else True
        gates["scope"] = scope_gate

        technique_gate = not mission.policy.allowed_techniques or (
            not technique or technique in mission.policy.allowed_techniques
        )
        gates["technique"] = technique_gate

        resource_gate = mission.budget.execution_remaining > 0
        gates["resource_budget"] = resource_gate

        concurrency_gate = mission.budget.active_concurrency < mission.budget.max_concurrency
        gates["concurrency"] = concurrency_gate

        allowed = all(gates.values())
        failed = [name for name, passed in gates.items() if not passed]
        reason = "all policy gates passed" if allowed else f"blocked by: {', '.join(failed)}"
        return PolicyVerdict(allowed=allowed, reason=reason, gates=gates)

    def evaluate_stop(self, mission: OrchestratedMission) -> StopCondition | None:
        """Evaluate stop conditions; return the first that fires or ``None``."""
        conditions = mission.policy.stop_conditions

        if StopCondition.OPERATOR_CANCELLED in conditions and mission.mission.state.value == "cancelled":
            return StopCondition.OPERATOR_CANCELLED

        if StopCondition.UNRECOVERABLE_FAILURE in conditions and mission.mission.state.value == "failed":
            return StopCondition.UNRECOVERABLE_FAILURE

        # Time exhaustion is checked before the combined resource check so a
        # wall-clock overrun is labelled ``TIME_BUDGET_EXHAUSTED`` — never
        # misreported as ``RESOURCE_BUDGET_EXHAUSTED``.
        if (
            StopCondition.TIME_BUDGET_EXHAUSTED in conditions
            and mission.budget.time_exhausted
        ):
            return StopCondition.TIME_BUDGET_EXHAUSTED

        if StopCondition.RESOURCE_BUDGET_EXHAUSTED in conditions and mission.budget.exhausted:
            return StopCondition.RESOURCE_BUDGET_EXHAUSTED

        if (
            StopCondition.FINDINGS_VALIDATED in conditions
            and self._all_findings_validated(mission)
            and not self._has_open_high_value_hypotheses(mission)
        ):
            return StopCondition.FINDINGS_VALIDATED

        if StopCondition.HIGH_VALUE_HYPOTHESES_RESOLVED in conditions and self._high_value_resolved(mission):
            return StopCondition.HIGH_VALUE_HYPOTHESES_RESOLVED

        # Coverage is a prerequisite, never a terminal condition by itself: the
        # objective completion contract must confirm every mandatory dimension
        # (active testing, browser, attack paths, hypotheses) was assessed. A
        # coverage percentage must never let a full assessment terminate while
        # actionable hypotheses remain open or major dimensions are untested.
        if (
            StopCondition.COVERAGE_TARGET_ACHIEVED in conditions
            and mission.coverage_ratio() >= mission.policy.coverage_target
            and self._completion_contract_satisfied(mission)
        ):
            return StopCondition.COVERAGE_TARGET_ACHIEVED
        if (
            StopCondition.OBJECTIVES_COMPLETE in conditions
            and not mission.context.remaining_objectives
            and self._completion_contract_satisfied(mission)
        ):
            return StopCondition.OBJECTIVES_COMPLETE

        return None

    def _completion_contract_satisfied(self, mission: OrchestratedMission) -> bool:
        """Return ``True`` when the objective completion contract is satisfied.

        Falls back to the historical high-value gate when no contract is wired
        (backward compatible for standalone policy-engine use).
        """
        if self.completion_gate is not None:
            satisfied, _unmet = self.completion_gate(mission)
            return bool(satisfied)
        return not self._has_open_high_value_hypotheses(mission)

    @staticmethod
    def _all_findings_validated(mission: OrchestratedMission) -> bool:
        """Return ``True`` when every recorded finding reached a terminal stage."""
        findings = mission.context.findings
        if not findings:
            return False
        return all(
            finding.get("stage") in ("verified", "proven", "report_ready", "refuted", "disproved")
            for finding in findings
        )

    @staticmethod
    def _is_high_value(hypothesis: Any) -> bool:
        """Return ``True`` when a hypothesis is high-value work.

        High-priority hypotheses (``priority >= 0.75``) always qualify. An
        OPEN class-specific vulnerability hypothesis (a concrete sql-injection
        / xss / lfi / command-injection / ... candidate with a probeable
        provenance class) is the engine's own discovered work too: the hunt
        never stops on a validated finding while a derived vulnerability
        candidate is still untested.
        """
        if hypothesis.priority >= 0.75:
            return True
        if hypothesis.state.value not in (
            "proposed",
            "supported",
            "weakly_supported",
            "inconclusive",
            "novel_behavior",
        ):
            return False
        provenance = hypothesis.provenance or {}
        vulnerability_class = str(provenance.get("vulnerability_class") or "").strip()
        if not vulnerability_class:
            return False
        from hunterx.domain.vulnerability_capability.registry import is_vulnerability_class

        return is_vulnerability_class(vulnerability_class)

    @staticmethod
    def _high_value_resolved(mission: OrchestratedMission) -> bool:
        """Return ``True`` when high-value hypotheses exist and all resolved.

        A mission with no high-value hypotheses is NOT considered complete by
        this condition (the condition only fires when there was real work).

        RESOLVED means terminal by evidence (VALIDATED/DISPROVED/REFUTED).
        DEFERRED/BLOCKED are explicitly classified and do NOT count as resolved.
        """
        high_value = [
            hypothesis for hypothesis in mission.hypotheses if MissionPolicyEngine._is_high_value(hypothesis)
        ]
        if not high_value:
            return False
        return all(hypothesis.state.is_terminal for hypothesis in high_value)

    @staticmethod
    def _has_open_high_value_hypotheses(mission: OrchestratedMission) -> bool:
        """Return ``True`` when a high-value hypothesis is still unresolved.

        Coverage measures what was tested — it does NOT prove the target is
        secure. A coverage percentage must never let the mission terminate
        while a high-value hypothesis (priority >= 0.75 or an open
        class-specific vulnerability candidate) remains open, so
        ``COVERAGE_TARGET_ACHIEVED`` is gated on this predicate.
        """
        return any(
            MissionPolicyEngine._is_high_value(hypothesis)
            and hypothesis.state.value
            in ("proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior")
            for hypothesis in mission.hypotheses
        )


__all__ = ["MissionPolicyEngine", "PolicyVerdict"]
