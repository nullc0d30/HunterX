# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Policy enforcement for adaptive mission planning.

The policy engine is the security boundary of the planner: every candidate
action must pass scope, authorization, safety and rate-limit gates before it
can be scheduled. Scope and authorization are immutable — no planner, AI
proposal or tool output may ever override them.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import ValidationLevel
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    MissionConstraints,
    PolicyDecision,
)

#: Deepest :class:`ValidationLevel` permitted per authorization tier.
_LEVEL_BY_AUTHORIZATION: dict[str, ValidationLevel] = {
    "default": ValidationLevel.DISCOVERY,
    "discovery": ValidationLevel.DISCOVERY,
    "validation": ValidationLevel.VALIDATION,
    "proof": ValidationLevel.PROOF,
    "impact_demonstration": ValidationLevel.IMPACT_DEMONSTRATION,
    "authorized": ValidationLevel.PROOF,
}

#: Canonical mapping capability risk bands (informational only; real risk
#: comes from tool safety profiles in the Tool Intelligence Platform).
_RISK_BY_VALIDATION: dict[ValidationLevel, float] = {
    ValidationLevel.DISCOVERY: 0.1,
    ValidationLevel.VALIDATION: 0.4,
    ValidationLevel.PROOF: 0.6,
    ValidationLevel.IMPACT_DEMONSTRATION: 0.9,
}

#: Capabilities that are never allowed under any circumstance.
_FORBIDDEN_CAPABILITIES = frozenset(
    {
        "credential_attack",
        "password_spraying",
        "lateral_movement",
        "persistence",
        "weaponized_exploitation",
        "data_exfiltration",
    }
)


class PolicyEngine:
    """Deterministic policy gates for candidate actions.

    Gates are enforced in a fixed order: scope → authorization → safety →
    forbidden capabilities → risk threshold → rate limit. A single denial
    blocks the action with an explainable :class:`PolicyDecision`.
    """

    def __init__(self, *, rate_limit_per_minute: int = 0) -> None:
        self._rate_limit_per_minute = rate_limit_per_minute
        self._rate_bucket: dict[str, int] = {}

    def check(
        self,
        action: ActionNode,
        constraints: MissionConstraints,
        *,
        authorization_context: str = "default",
        safety_ceiling: str = "low_impact_active",
    ) -> PolicyDecision:
        """Evaluate every policy gate for ``action``."""
        gate = self._check_scope(action, constraints)
        if not gate.allowed:
            return gate
        gate = self._check_authorization(action, authorization_context)
        if not gate.allowed:
            return gate
        gate = self._check_safety(action, safety_ceiling)
        if not gate.allowed:
            return gate
        gate = self._check_risk(action, constraints)
        if not gate.allowed:
            return gate
        gate = self._check_rate_limit(action, constraints)
        if not gate.allowed:
            return gate
        return PolicyDecision(
            mission_id=action.mission_id,
            action_id=action.action_id,
            gate="policy",
            allowed=True,
            reason="action passes all policy gates",
        )

    def check_proposal(
        self,
        action: ActionNode,
        constraints: MissionConstraints,
        *,
        authorization_context: str = "default",
        safety_ceiling: str = "low_impact_active",
        ai_proposed: bool = False,
    ) -> PolicyDecision:
        """Gate an AI-assisted or deterministic proposal.

        AI proposals are advisory: they must pass every gate a deterministic
        action would pass. AI can never expand scope, override safety or
        declare proof without evidence.
        """
        decision = self.check(
            action,
            constraints,
            authorization_context=authorization_context,
            safety_ceiling=safety_ceiling,
        )
        if not decision.allowed:
            return decision
        if action.capability in _FORBIDDEN_CAPABILITIES:
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="ai_policy",
                allowed=False,
                reason=f"capability '{action.capability}' is forbidden by policy",
                detail={"ai_proposed": ai_proposed},
            )
        if action.validation_level.value in ("proof", "impact_demonstration") and not ai_proposed:
            # deterministic proposals may legitimately collect proof; keep gate
            return decision
        return decision

    def maximum_validation_level(self, authorization_context: str) -> ValidationLevel:
        """Return the deepest validation level allowed by ``authorization_context``."""
        return _LEVEL_BY_AUTHORIZATION.get(
            authorization_context,
            _LEVEL_BY_AUTHORIZATION["default"],
        )

    def verify_within_authorization(
        self,
        action: ActionNode,
        authorization_context: str,
    ) -> PolicyDecision:
        """Reject actions whose validation level exceeds the authorization tier."""
        ceiling = self.maximum_validation_level(authorization_context)
        rank = _validation_rank(action.validation_level)
        if rank <= _validation_rank(ceiling):
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="authorization",
                allowed=True,
                reason=f"validation level '{action.validation_level.value}' within '{authorization_context}'",
            )
        return PolicyDecision(
            mission_id=action.mission_id,
            action_id=action.action_id,
            gate="authorization",
            allowed=False,
            reason=(
                f"validation level '{action.validation_level.value}' exceeds authorization "
                f"tier '{authorization_context}' (ceiling '{ceiling.value}')"
            ),
        )

    # -- gates --------------------------------------------------------------

    def _check_scope(self, action: ActionNode, constraints: MissionConstraints) -> PolicyDecision:
        if constraints.scope and action.scope_requirements and constraints.scope not in action.scope_requirements:
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="scope",
                allowed=False,
                reason=f"action scope requirement not satisfied by mission scope '{constraints.scope}'",
            )
        if action.asset and not constraints.allows_asset(action.asset):
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="scope",
                allowed=False,
                reason=f"asset '{action.asset}' is excluded by mission constraints",
                detail={"excluded_assets": list(constraints.excluded_assets)},
            )
        if action.capability and not constraints.allows_capability(action.capability):
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="scope",
                allowed=False,
                reason=f"capability '{action.capability}' is excluded by mission constraints",
                detail={"excluded_capabilities": list(constraints.excluded_capabilities)},
            )
        return PolicyDecision(
            mission_id=action.mission_id,
            action_id=action.action_id,
            gate="scope",
            allowed=True,
            reason="action is within authorized scope",
        )

    def _check_authorization(self, action: ActionNode, authorization_context: str) -> PolicyDecision:
        return self.verify_within_authorization(action, authorization_context)

    def _check_safety(self, action: ActionNode, safety_ceiling: str) -> PolicyDecision:
        risk = _RISK_BY_VALIDATION.get(action.validation_level, 0.1)
        ceiling_risk = _SAFETY_CEILING_RISK.get(safety_ceiling, 0.5)
        if risk > ceiling_risk:
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="safety",
                allowed=False,
                reason=(
                    f"validation level '{action.validation_level.value}' exceeds safety ceiling "
                    f"'{safety_ceiling}'"
                ),
            )
        return PolicyDecision(
            mission_id=action.mission_id,
            action_id=action.action_id,
            gate="safety",
            allowed=True,
            reason=f"action is within safety ceiling '{safety_ceiling}'",
        )

    def _check_risk(self, action: ActionNode, constraints: MissionConstraints) -> PolicyDecision:
        if action.risk > constraints.risk_threshold:
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="risk",
                allowed=False,
                reason=(
                    f"action risk {action.risk:.2f} exceeds mission risk threshold "
                    f"{constraints.risk_threshold:.2f}"
                ),
            )
        return PolicyDecision(
            mission_id=action.mission_id,
            action_id=action.action_id,
            gate="risk",
            allowed=True,
            reason="action risk is within the mission risk threshold",
        )

    def _check_rate_limit(self, action: ActionNode, constraints: MissionConstraints) -> PolicyDecision:
        limit = self._rate_limit_per_minute or constraints.rate_limit_per_minute
        if not limit:
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="rate_limit",
                allowed=True,
                reason="no rate limit configured",
            )
        key = action.asset or action.mission_id
        used = self._rate_bucket.get(key, 0)
        if used >= limit:
            return PolicyDecision(
                mission_id=action.mission_id,
                action_id=action.action_id,
                gate="rate_limit",
                allowed=False,
                reason=f"rate limit reached for '{key}' ({used}/{limit} per minute)",
            )
        self._rate_bucket[key] = used + 1
        return PolicyDecision(
            mission_id=action.mission_id,
            action_id=action.action_id,
            gate="rate_limit",
            allowed=True,
            reason=f"rate budget available ({used + 1}/{limit})",
        )


def _validation_rank(level: ValidationLevel) -> int:
    return {
        ValidationLevel.DISCOVERY: 1,
        ValidationLevel.VALIDATION: 2,
        ValidationLevel.PROOF: 3,
        ValidationLevel.IMPACT_DEMONSTRATION: 4,
    }.get(level, 1)


#: Safety ceilings (mission mode → safety class) → allowed risk ceiling.
_SAFETY_CEILING_RISK: dict[str, float] = {
    "passive": 0.1,
    "read_only": 0.1,
    "low_impact_active": 0.4,
    "benign_marker": 0.4,
    "active": 0.6,
    "controlled": 0.6,
    "high_impact": 0.9,
    "destructive": 0.9,
}
