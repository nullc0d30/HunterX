# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive mission planning exceptions.

Every error raised by the adaptive mission planning engine derives from
:class:`AdaptiveMissionPlanningError` and carries the
:data:`HunterXErrorCode.MISSION` code so API/CLI layers can map them
uniformly.
"""

from __future__ import annotations

from hunterx.domain.exceptions.base import HunterXErrorCode
from hunterx.domain.exceptions.domain import DomainError


class AdaptiveMissionPlanningError(DomainError):
    """Base for errors raised by the adaptive mission planning engine."""

    code = HunterXErrorCode.MISSION


class AdaptiveMissionNotFoundError(AdaptiveMissionPlanningError):
    """Raised when an adaptive mission does not exist."""

    def __init__(self, mission_id: str) -> None:
        super().__init__(f"Adaptive mission '{mission_id}' was not found.")
        self.mission_id = mission_id


class AdaptivePlanNotFoundError(AdaptiveMissionPlanningError):
    """Raised when a plan version does not exist."""

    def __init__(self, mission_id: str, plan_version: int) -> None:
        super().__init__(f"Adaptive mission '{mission_id}' has no plan version '{plan_version}'.")
        self.mission_id = mission_id
        self.plan_version = plan_version


class ActionNotFoundError(AdaptiveMissionPlanningError):
    """Raised when an action node does not exist in a mission graph."""

    def __init__(self, action_id: str) -> None:
        super().__init__(f"Action node '{action_id}' was not found.")
        self.action_id = action_id


class AdaptiveMissionStateError(AdaptiveMissionPlanningError):
    """Raised when a mission cannot transition state."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class PolicyBlockedActionError(AdaptiveMissionPlanningError):
    """Raised when an action is blocked by a policy gate."""

    def __init__(self, action_id: str, reason: str) -> None:
        super().__init__(f"Action '{action_id}' blocked by policy: {reason}")
        self.action_id = action_id
        self.reason = reason
