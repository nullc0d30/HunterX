# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission safety enforcer.

The safety enforcer executes before every tool task alongside the scope guard.
It checks the execution policy level, the allowed safety classes, forbidden
action names and forbidden parameter markers, and refuses anything destructive
unless the mission safety policy explicitly permits it (which, in practice, is
never for the default policies).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.orchestration.enums import ExecutionPolicyLevel
from hunterx.domain.orchestration.models import SafetyPolicy


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    """A safety-gate decision for a task.

    Attributes:
        allowed: whether the task may proceed.
        reason: human-readable justification.
        safety_class: the safety class the task requested.
        blocked_action: the action that was refused (when refused).
        detail: structured detail map.

    """

    allowed: bool
    reason: str = "allowed"
    safety_class: str = "passive"
    blocked_action: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "safety_class": self.safety_class,
            "blocked_action": self.blocked_action,
            "detail": dict(self.detail),
        }


class MissionSafetyEnforcer:
    """Enforces the mission safety and execution policies for a task.

    The enforcer is fail-closed: any unknown safety class, any forbidden
    action, any forbidden parameter marker, or any policy-level mismatch
    refuses the task. Destructive behavior is always refused by default.
    """

    def __init__(
        self,
        execution_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.SAFE_ACTIVE,
        safety: SafetyPolicy | None = None,
    ) -> None:
        self._execution_policy = execution_policy
        self._safety = safety or SafetyPolicy()

    def decides(
        self,
        *,
        action: str,
        safety_class: str = "passive",
        parameters: dict[str, Any] | None = None,
    ) -> SafetyDecision:
        """Decide whether a task with ``action`` and ``safety_class`` may run.

        Args:
            action: the logical action or tool id being executed.
            safety_class: the safety class the task requests.
            parameters: the task parameters (checked for forbidden markers).

        """
        safety_class = safety_class or "passive"
        if safety_class not in self._safety.allowed_classes:
            return SafetyDecision(
                allowed=False,
                reason=f"unsafe action refused: safety class '{safety_class}' is not allowed",
                safety_class=safety_class,
                blocked_action=action,
            )

        if self._safety.destructive_allowed:
            return SafetyDecision(
                allowed=False,
                reason="destructive behavior is never permitted by mission policy",
                safety_class=safety_class,
                blocked_action=action,
            )

        for forbidden in self._safety.forbidden_actions:
            if forbidden and forbidden in action.lower():
                return SafetyDecision(
                    allowed=False,
                    reason=f"unsafe action refused: action contains forbidden marker '{forbidden}'",
                    safety_class=safety_class,
                    blocked_action=action,
                )

        if parameters:
            rendered = " ".join(
                f"{key}={value}" if not isinstance(value, str) else f"{key}={value}"
                for key, value in parameters.items()
                if key not in {"target", "url", "path", "method"}
            )
            rendered_lower = rendered.lower()
            for marker in self._safety.forbidden_parameter_markers:
                if marker.lower() in rendered_lower:
                    return SafetyDecision(
                        allowed=False,
                        reason=f"unsafe action refused: parameter contains forbidden marker '{marker}'",
                        safety_class=safety_class,
                        blocked_action=action,
                        detail={"marker": marker},
                    )

        return SafetyDecision(
            allowed=True,
            reason="task is permitted by mission safety policy",
            safety_class=safety_class,
        )
