# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission planning use-case service.

A thin application-layer wrapper over the mission planning engine and its
repositories. It mirrors the conventions of :class:`MissionService`: every
operation returns a :class:`Result` and persists through ports.
"""

from __future__ import annotations

from hunterx.domain.exceptions import (
    InvalidMissionRequestError,
    MissionPlanNotFoundError,
)
from hunterx.domain.mission_planning import (
    MissionPlan,
    MissionRequest,
    MissionTimelineEntry,
)
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)
from hunterx.engines.mission_planning.api import MissionPlanningAPI
from hunterx.shared.result import Failure, Result, Success


class MissionPlanningService:
    """Application service for mission planning use cases."""

    def __init__(
        self,
        plans: MissionPlanRepository,
        profiles: MissionProfileRepository | None = None,
        templates: MissionTemplateRepository | None = None,
        checkpoints: CheckpointRepository | None = None,
        timeline: MissionTimelineRepository | None = None,
        api: MissionPlanningAPI | None = None,
    ) -> None:
        self._plans = plans
        self._api = api or MissionPlanningAPI(
            plans=plans,
            profiles=profiles,
            templates=templates,
            checkpoints=checkpoints,
            timeline=timeline,
        )

    def create(self, request: MissionRequest) -> Result[MissionPlan, Exception]:
        """Validate and create a mission plan from a request."""
        try:
            errors = self._api.validate(request)
            if errors:
                return Failure(
                    InvalidMissionRequestError(
                        "mission request failed validation: " + "; ".join(errors),
                        errors=errors,
                    )
                )
            return self._api.create_mission(request)
        except (ValueError, TypeError) as exc:
            return Failure(exc)

    def update(
        self,
        plan_id: str,
        *,
        name: str | None = None,
        targets: tuple[str, ...] | None = None,
        variables: dict[str, object] | None = None,
        config: dict[str, object] | None = None,
        priority: str | None = None,
    ) -> Result[MissionPlan, Exception]:
        """Update editable fields of a mission that has not been executed."""
        return self._api.update_mission(
            plan_id,
            name=name,
            targets=targets,
            variables=variables,
            config=config,
            priority=priority,
        )

    def plan(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Expand a queued mission into a ready plan."""
        return self._api.plan_mission(plan_id)

    def status(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Return the current mission plan."""
        return self._api.status(plan_id)

    def cancel(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Cancel a mission from any active state."""
        return self._api.cancel(plan_id)

    def history(self, mission_id: str) -> Result[list[MissionTimelineEntry], Exception]:
        """Return a mission's timeline entries."""
        return self._api.history(mission_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> list[MissionPlan]:
        """List persisted mission plans."""
        return self._api.list_missions(limit=limit, offset=offset)

    def get(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Fetch a mission plan by identifier."""
        plan = self._plans.get(plan_id)
        if plan is None:
            return Failure(MissionPlanNotFoundError(plan_id))
        return Success(plan)
