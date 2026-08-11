# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission planning exceptions.

Every error raised by the mission planning engine derives from
:class:`MissionPlanningError` and carries the :data:`HunterXErrorCode.MISSION`
code so API/CLI layers can map them uniformly.
"""

from __future__ import annotations

from hunterx.domain.exceptions.base import HunterXErrorCode
from hunterx.domain.exceptions.domain import DomainError


class MissionPlanningError(DomainError):
    """Base for errors raised by the mission planning engine."""

    code = HunterXErrorCode.MISSION


class MissionProfileNotFoundError(MissionPlanningError):
    """Raised when a mission profile is not registered."""

    def __init__(self, profile_id: str) -> None:
        super().__init__(f"Mission profile '{profile_id}' was not found.")
        self.profile_id = profile_id


class MissionTemplateNotFoundError(MissionPlanningError):
    """Raised when a mission template is not registered."""

    def __init__(self, template_id: str) -> None:
        super().__init__(f"Mission template '{template_id}' was not found.")
        self.template_id = template_id


class InvalidMissionRequestError(MissionPlanningError):
    """Raised when a mission request fails validation."""

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


class MissionPlanNotFoundError(MissionPlanningError):
    """Raised when a mission plan does not exist."""

    def __init__(self, plan_id: str) -> None:
        super().__init__(f"Mission plan '{plan_id}' was not found.")
        self.plan_id = plan_id


class InvalidMissionPlanError(MissionPlanningError):
    """Raised when a mission plan (or its parts) violates its invariants."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Invalid mission plan: {message}")


class MissionPlanValidationError(MissionPlanningError):
    """Raised when a mission request fails profile/request validation."""

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


class CheckpointNotFoundError(MissionPlanningError):
    """Raised when a checkpoint does not exist."""

    def __init__(self, checkpoint_id: str) -> None:
        super().__init__(f"Checkpoint '{checkpoint_id}' was not found.")
        self.checkpoint_id = checkpoint_id


class InvalidStateTransitionError(MissionPlanningError):
    """Raised when a mission state transition is not permitted."""

    def __init__(self, source: str, target: str) -> None:
        super().__init__(
            f"Mission cannot transition from '{source}' to '{target}'."
        )
        self.source = source
        self.target = target
