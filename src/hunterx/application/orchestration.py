# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive tool orchestration use-case service.

A thin application-layer wrapper over the offensive orchestration engine. It
mirrors the conventions of the other use-case services: operations return a
:class:`Result` and persist through the engine's repository ports.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.orchestration.models import ExecutionPlan, OffensiveMission
from hunterx.domain.ports.orchestration import (
    ExecutionPlanRepository,
    OffensiveMissionRepository,
)
from hunterx.engines.orchestration.api import OffensiveOrchestrationAPI
from hunterx.shared.result import Result


class OffensiveOrchestrationService:
    """Application service for offensive orchestration use cases."""

    def __init__(
        self,
        missions: OffensiveMissionRepository | None = None,
        plans: ExecutionPlanRepository | None = None,
        api: OffensiveOrchestrationAPI | None = None,
        **kwargs: Any,
    ) -> None:
        self._missions = missions
        self._plans = plans
        self._api = api or OffensiveOrchestrationAPI(
            missions=missions,
            plans=plans,
            **{key: value for key, value in kwargs.items()},
        )

    @property
    def api(self) -> OffensiveOrchestrationAPI:
        """Return the underlying orchestration API."""
        return self._api

    def create(
        self,
        *,
        objective: str,
        mission_type: Any,
        scope: Any = None,
        targets: tuple[str, ...] = (),
        exclusions: tuple[str, ...] = (),
        policies: Any = None,
        priority: str = "medium",
    ) -> Result[OffensiveMission, Exception]:
        """Create an offensive mission."""
        return self._api.create_mission(
            objective=objective,
            mission_type=mission_type,
            scope=scope,
            targets=targets,
            exclusions=exclusions,
            policies=policies,
            priority=priority,
        )

    def plan(self, mission_id: str, *, intelligence: Any = None) -> Result[ExecutionPlan, Exception]:
        """Plan a mission into an execution plan."""
        return self._api.plan_mission(mission_id, intelligence=intelligence)

    def run(self, mission_id: str, *, tool_outputs: dict[str, dict[str, Any]] | None = None) -> Result[Any, Exception]:
        """Run a ready mission end to end."""
        return self._api.run_mission(mission_id, tool_outputs=tool_outputs)

    def get(self, mission_id: str) -> OffensiveMission | None:
        """Fetch a mission by identifier."""
        return self._api.get_mission(mission_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> list[OffensiveMission]:
        """List persisted missions."""
        return self._api.list_missions(limit=limit, offset=offset)

    def cancel(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Cancel a mission."""
        return self._api.cancel(mission_id)
