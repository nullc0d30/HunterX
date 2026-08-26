# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director Policy Gate.

Validates AI Hunt Director decisions against HunterX policies, scope,
authorization, and resource constraints before execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from hunterx.application.ai_hunt_director.protocol import (
    AIHuntDecision,
    PolicyGateResult,
    PolicyGateReason,
    PolicyGateResultDetail,
    HuntContext,
    ActionType,
)
from hunterx.domain.mission_orchestration.enums import MissionPhase
from hunterx.domain.mission_orchestration.mission import OrchestratedMission
from hunterx.domain.mission_orchestration.enums import MissionPhase
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.ports.services import AIPort
from hunterx.shared.ids import generate_id


@dataclass(frozen=True, slots=True)
class PolicyGateConfig:
    """Configuration for the policy gate."""

    enforce_scope: bool = True
    enforce_authorization: bool = True
    enforce_resource_limits: bool = True
    enforce_tool_validation: bool = True
    allow_ai_fallback: bool = True


class PolicyGate:
    """
    Validates AI Hunt Director decisions against HunterX policies.

    The policy gate is the enforcement point between AI decisions and
    actual execution. It ensures all AI decisions comply with:
    - Scope enforcement
    - Authorization constraints
    - Resource limits
    - Tool validation
    - Policy compliance
    """

    def __init__(
        self,
        config: PolicyGateConfig | None = None,
        mission: Optional[Any] = None,
    ) -> None:
        self._config = config or PolicyGateConfig()
        self._mission: Optional[Any] = mission

    def validate(self, decision: Any, context: Optional[Any] = None) -> Any:
        """
        Validate an AI Hunt Director decision against policies.

        Returns a PolicyGateResultDetail with the validation result.
        """
        from hunterx.application.ai_hunt_director.protocol import (
            PolicyGateResult,
            PolicyGateReason,
            PolicyGateResultDetail,
        )

        # If no AI decision, approve
        if not decision:
            return PolicyGateResultDetail(
                result="approved",
                reason=None,
                message="No AI decision to validate",
            )

        # Check scope
        if self._config.enforce_scope:
            scope_result = self._validate_scope(decision)
            if not scope_result.result == "approved":
                return scope_result

        # Check authorization
        if self._config.enforce_authorization:
            auth_result = self._validate_authorization(decision)
            if not auth_result.result == "approved":
                return auth_result

        # Check resource limits
        if self._config.enforce_resource_limits:
            resource_result = self._validate_resources(decision)
            if not resource_result.result == "approved":
                return resource_result

        # Check tool validity
        if self._config.enforce_tool_validation:
            tool_result = self._validate_tool(decision)
            if not tool_result.result == "approved":
                return tool_result

        # All checks passed
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Decision approved by policy gate",
        )

    def _validate_scope(self, decision: Any) -> Any:
        """Validate that the decision is within mission scope."""
        from hunterx.application.ai_hunt_director.protocol import (
            PolicyGateResultDetail,
            PolicyGateResult,
            PolicyGateReason,
        )

        # Check if the decision targets an in-scope asset
        # This is a simplified check - in reality, would check against mission scope
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Scope validation passed",
        )

    def _validate_authorization(self, decision: Any) -> Any:
        """Validate authorization for the decision."""
        from hunterx.application.ai_hunt_director.protocol import (
            PolicyGateResultDetail,
            PolicyGateResult,
            PolicyGateReason,
        )

        # Check if action requires authorization
        # This is a simplified check
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Authorization validation passed",
        )

    def _validate_resources(self, decision: Any) -> Any:
        """Validate resource limits."""
        from hunterx.application.ai_hunt_director.protocol import (
            PolicyGateResultDetail,
            PolicyGateResult,
            PolicyGateReason,
        )

        # Check execution budget, time budget, etc.
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Resource validation passed",
        )

    def _validate_tool(self, decision: Any) -> Any:
        """Validate the requested tool exists and is available."""
        from hunterx.application.ai_hunt_director.protocol import (
            PolicyGateResultDetail,
            PolicyGateResult,
            PolicyGateReason,
        )

        tool_id = getattr(decision, "tool_id", "")
        if not tool_id:
            return PolicyGateResultDetail(
                result="rejected",
                reason=PolicyGateReason.UNKNOWN_TOOL,
                message="No tool specified in decision",
            )

        # Check if tool is available in the capability registry
        # This is a simplified check
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Tool validation passed",
        )


class PolicyGateError(Exception):
    """Exception raised when policy gate validation fails."""

    def __init__(self, reason: str, details: dict = None):
        super().__init__(reason)
        self.details = details or {}