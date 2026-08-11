# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission engine.

Drives the end-to-end lifecycle of a mission: start → plan → execute
workflow → collect normalized findings → correlate → finalize. The engine
coordinates the planner, workflow engine and repositories through ports, so it
is testable without infrastructure.
"""

from __future__ import annotations

from hunterx.domain.entities import Mission, MissionStatus
from hunterx.domain.events import DomainEvent
from hunterx.domain.exceptions import MissionAlreadyRunningError, MissionNotFoundError
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.repositories import FindingRepository, MissionRepository
from hunterx.domain.services.correlator import CorrelatorService
from hunterx.domain.services.planner import PlannerService
from hunterx.engines.workflow import WorkflowEngine
from hunterx.shared.result import Failure, Result, Success


class MissionEngine:
    """Orchestrate mission execution from start to finish.

    The engine performs each phase as a separate public method so schedulers,
    API handlers and the CLI can drive it at whatever granularity they need.
    """

    def __init__(
        self,
        missions: MissionRepository,
        findings: FindingRepository,
        planner: PlannerService,
        workflows: WorkflowEngine,
        correlator: CorrelatorService,
        event_bus: EventBusPort,
    ) -> None:
        self._missions = missions
        self._findings = findings
        self._planner = planner
        self._workflows = workflows
        self._correlator = correlator
        self._event_bus = event_bus

    def _publish(self, event_type: str, payload: dict[str, object], source: str) -> None:
        if self._event_bus is None:
            return
        self._event_bus.publish(DomainEvent(event_type=event_type, payload=payload, source=source))

    def start(self, mission_id: str) -> Result[Mission, Exception]:
        """Transition a mission to RUNNING and publish the start event."""
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        if mission.status == MissionStatus.RUNNING:
            return Failure(MissionAlreadyRunningError(mission_id))
        try:
            mission.start()
        except Exception as exc:
            return Failure(exc)
        self._missions.save(mission)
        self._publish("mission.started", {"mission_id": mission_id}, "mission.engine")
        return Success(mission)

    def plan(self, mission: Mission) -> Result[object, Exception]:
        """Expand a mission into an execution plan."""
        return Success(self._planner.plan(mission))

    def execute_workflow(self, mission: Mission) -> Result[list[object], Exception]:
        """Run the mission's workflow across its targets."""
        return self._workflows.run(mission.workflow, targets=mission.targets, mission_id=mission.mission_id)

    def finalize(self, mission_id: str, *, failed: bool = False) -> Result[Mission, Exception]:
        """Mark a mission completed or failed and publish the result event."""
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        if failed:
            mission.fail()
            self._publish("mission.failed", {"mission_id": mission_id}, "mission.engine")
        else:
            mission.complete()
            self._publish("mission.completed", {"mission_id": mission_id}, "mission.engine")
        self._missions.save(mission)
        return Success(mission)

    def correlated_findings(self, mission_id: str) -> Result[list[object], Exception]:
        """Return correlation groups over a mission's stored findings."""
        mission = self._missions.get(mission_id)
        if mission is None:
            return Failure(MissionNotFoundError(mission_id))
        findings = list(self._findings.list_by_mission(mission_id, limit=10_000))
        return Success(self._correlator.correlate(findings))
