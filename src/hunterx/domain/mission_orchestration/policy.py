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
    """

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

        if StopCondition.RESOURCE_BUDGET_EXHAUSTED in conditions and mission.budget.exhausted:
            return StopCondition.RESOURCE_BUDGET_EXHAUSTED

        if (
            StopCondition.TIME_BUDGET_EXHAUSTED in conditions
            and mission.budget.time_budget_seconds > 0
            and mission.budget.time_used_seconds >= mission.budget.time_budget_seconds
        ):
            return StopCondition.TIME_BUDGET_EXHAUSTED

        if StopCondition.FINDINGS_VALIDATED in conditions and self._all_findings_validated(mission):
            return StopCondition.FINDINGS_VALIDATED

        if StopCondition.HIGH_VALUE_HYPOTHESES_RESOLVED in conditions and self._high_value_resolved(mission):
            return StopCondition.HIGH_VALUE_HYPOTHESES_RESOLVED

        if (
            StopCondition.COVERAGE_TARGET_ACHIEVED in conditions
            and mission.coverage_ratio() >= mission.policy.coverage_target
            and not self._has_open_high_value_hypotheses(mission)
        ):
            return StopCondition.COVERAGE_TARGET_ACHIEVED

        if StopCondition.OBJECTIVES_COMPLETE in conditions and not mission.context.remaining_objectives:
            return StopCondition.OBJECTIVES_COMPLETE

        return None

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
    def _high_value_resolved(mission: OrchestratedMission) -> bool:
        """Return ``True`` when high-priority hypotheses exist and all resolved.

        A mission with no high-value hypotheses is NOT considered complete by
        this condition (the condition only fires when there was real work).
        """
        high_value = [
            hypothesis for hypothesis in mission.hypotheses if hypothesis.priority >= 0.75
        ]
        if not high_value:
            return False
        return all(
            hypothesis.state.value not in (
                "proposed",
                "supported",
                "weakly_supported",
                "inconclusive",
                "novel_behavior",
            )
            for hypothesis in high_value
        )

    @staticmethod
    def _has_open_high_value_hypotheses(mission: OrchestratedMission) -> bool:
        """Return ``True`` when a high-priority hypothesis is still unresolved.

        Coverage measures what was tested — it does NOT prove the target is
        secure. A coverage percentage must never let the mission terminate
        while a high-value hypothesis (priority >= 0.75) remains open, so
        ``COVERAGE_TARGET_ACHIEVED`` is gated on this predicate.
        """
        return any(
            hypothesis.priority >= 0.75
            and hypothesis.state.value
            in ("proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior")
            for hypothesis in mission.hypotheses
        )


__all__ = ["MissionPolicyEngine", "PolicyVerdict"]
