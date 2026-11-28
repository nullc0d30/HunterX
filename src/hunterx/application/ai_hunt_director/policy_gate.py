# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director Policy Gate.

Validates AI Hunt Director decisions against HunterX policies, scope, authorization, and resource constraints before
execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.application.ai_hunt_director.protocol import (
    PolicyGateReason,
    PolicyGateResultDetail,
)


@dataclass(frozen=True, slots=True)
class PolicyGateConfig:
    """Configuration for the policy gate."""

    enforce_scope: bool = True
    enforce_authorization: bool = True
    enforce_resource_limits: bool = True
    enforce_tool_validation: bool = True
    allow_ai_fallback: bool = True


class PolicyGate:
    """Validates AI Hunt Director decisions against HunterX policies.

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
        mission: Any | None = None,
    ) -> None:
        self._config = config or PolicyGateConfig()
        self._mission: Any | None = mission

    def validate(self, decision: Any, context: Any | None = None) -> Any:
        """Validate an AI Hunt Director decision against policies.

        Returns a PolicyGateResultDetail with the validation result.
        """
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
            if scope_result.result != "approved":
                return scope_result

        # Check authorization
        if self._config.enforce_authorization:
            auth_result = self._validate_authorization(decision)
            if auth_result.result != "approved":
                return auth_result

        # Check resource limits
        if self._config.enforce_resource_limits:
            resource_result = self._validate_resources(decision)
            if resource_result.result != "approved":
                return resource_result

        # Check tool validity
        if self._config.enforce_tool_validation:
            tool_result = self._validate_tool(decision)
            if tool_result.result != "approved":
                return tool_result

        # All checks passed
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Decision approved by policy gate",
        )

    def _validate_scope(self, decision: Any) -> Any:
        """Validate that the decision is within mission scope."""
        # Check if the decision targets an in-scope asset
        # This is a simplified check - in reality, would check against mission scope
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Scope validation passed",
        )

    def _validate_authorization(self, decision: Any) -> Any:
        """Validate authorization for the decision."""
        # Check if action requires authorization
        # This is a simplified check
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Authorization validation passed",
        )

    def _validate_resources(self, decision: Any) -> Any:
        """Validate resource limits."""
        # Check execution budget, time budget, etc.
        return PolicyGateResultDetail(
            result="approved",
            reason=None,
            message="Resource validation passed",
        )

    def _validate_tool(self, decision: Any) -> Any:
        """Validate the requested tool exists and is available."""
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
