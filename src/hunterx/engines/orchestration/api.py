# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive Tool Orchestration API facade.

A thin facade over :class:`OffensiveOrchestrationEngine` providing a stable
internal API for application services and higher layers.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.orchestration.models import OffensiveMission
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.orchestration import (
    ExecutionPlanRepository,
    OffensiveMissionRepository,
)
from hunterx.engines.orchestration.engine import (
    MissionRun,
    OffensiveOrchestrationEngine,
)
from hunterx.shared.result import Result


class OffensiveOrchestrationAPI:
    """Facade over the offensive orchestration engine.

    Usage::

        api = OffensiveOrchestrationAPI(missions=missions_repo, plans=plans_repo,
                                        execution_engine=engine, tip=tip)
        mission = api.create_mission(objective="assess example.com", mission_type="web-pentest")
        plan = api.plan_mission(mission.mission_id)
        run = api.run_mission(mission.mission_id)
    """

    def __init__(
        self,
        missions: OffensiveMissionRepository | None = None,
        plans: ExecutionPlanRepository | None = None,
        execution_engine: Any = None,
        tip: Any = None,
        stores: Any = None,
        event_bus: EventBusPort | None = None,
        knowledge_graph: Any = None,
        **kwargs: Any,
    ) -> None:
        self.engine = OffensiveOrchestrationEngine(
            missions=missions,
            plans=plans,
            execution_engine=execution_engine,
            tip=tip,
            stores=stores,
            event_bus=event_bus,
            knowledge_graph=knowledge_graph,
            **kwargs,
        )

    def create_mission(
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
        """Create a mission in the CREATED state."""
        return self.engine.create_mission(
            objective=objective,
            mission_type=mission_type,
            scope=scope,
            targets=targets,
            exclusions=exclusions,
            policies=policies,
            priority=priority,
        )

    def plan_mission(self, mission_id: str, *, intelligence: Any = None) -> Result[Any, Exception]:
        """Plan a mission into an execution plan."""
        return self.engine.plan_mission(mission_id, intelligence=intelligence)

    def run_mission(self, mission_id: str, *, tool_outputs: dict[str, dict[str, Any]] | None = None, stop_check: Any = None) -> Result[MissionRun, Exception]:
        """Run a ready mission end to end."""
        return self.engine.run_mission(mission_id, tool_outputs=tool_outputs, stop_check=stop_check)

    def get_mission(self, mission_id: str) -> OffensiveMission | None:
        """Return a mission by identifier."""
        return self.engine.get_mission(mission_id)

    def get_plan(self, plan_id: str) -> Any | None:
        """Return a plan by identifier."""
        return self.engine.get_plan(plan_id)

    def cancel(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Cancel a mission."""
        return self.engine.cancel_mission(mission_id)

    def pause(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Pause a running mission."""
        return self.engine.pause_mission(mission_id)

    def resume(self, mission_id: str) -> Result[OffensiveMission, Exception]:
        """Resume a paused mission."""
        return self.engine.resume_mission(mission_id)

    def list_missions(self, *, limit: int = 100, offset: int = 0) -> list[OffensiveMission]:
        """Return a page of missions."""
        return self.engine.list_missions(limit=limit, offset=offset)
