# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive orchestration exception hierarchy.

Failures raised by the orchestration engine: mission not found, invalid mission
state, scope violations, safety violations, and tool-selection failures within
a mission.
"""

from __future__ import annotations

from hunterx.domain.exceptions.base import HunterXError
from hunterx.domain.exceptions.infrastructure import NotFoundError


class OffensiveOrchestrationError(HunterXError):
    """Base error for the offensive orchestration layer."""


class OffensiveMissionNotFoundError(NotFoundError):
    """Raised when an offensive mission does not exist."""

    def __init__(self, mission_id: str) -> None:
        super().__init__("OffensiveMission", mission_id)


class ExecutionPlanNotFoundError(NotFoundError):
    """Raised when an execution plan does not exist."""

    def __init__(self, plan_id: str) -> None:
        super().__init__("ExecutionPlan", plan_id)


class InvalidMissionStateError(OffensiveOrchestrationError):
    """Raised when an operation requires a different mission state."""


class ScopeViolationError(OffensiveOrchestrationError):
    """Raised when a task targets an out-of-scope identifier.

    Attributes:
        identifier: the out-of-scope identifier.
        classification: scope classification (``out-of-scope``, ...).

    """

    def __init__(self, message: str, *, identifier: str = "", classification: str = "") -> None:
        self.identifier = identifier
        self.classification = classification
        super().__init__(message)


class SafetyViolationError(OffensiveOrchestrationError):
    """Raised when a task violates the mission safety policy."""


class ToolSelectionUnavailableError(OffensiveOrchestrationError):
    """Raised when no tool satisfies a step's capability need."""

    def __init__(self, message: str, *, capability: str = "") -> None:
        self.capability = capability
        super().__init__(message)


class RateLimitExceededError(OffensiveOrchestrationError):
    """Raised when a task is refused by a rate-limit gate."""


class MissionCancelledError(OffensiveOrchestrationError):
    """Raised when an operation is attempted on a cancelled mission."""
