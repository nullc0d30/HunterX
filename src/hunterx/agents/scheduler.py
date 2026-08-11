# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent scheduler.

Dispatches agent runs on a recurring schedule. This is the agent-level
scheduler; mission-level schedules belong to :mod:`hunterx.scheduler`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from hunterx.agents.context import AgentContext
from hunterx.agents.orchestrator import AgentOrchestrator
from hunterx.shared.result import Failure


@dataclass(frozen=True, slots=True)
class AgentSchedule:
    """A recurring agent dispatch.

    Attributes:
        name: unique schedule name.
        agent_name: agent to dispatch.
        interval_seconds: seconds between dispatches.
        mission_id: mission to attach to the context.
        target: target identifier for the context.
        parameters: extra run parameters.

    """

    name: str
    agent_name: str
    interval_seconds: float
    mission_id: str = ""
    target: str = ""
    parameters: dict[str, object] = field(default_factory=dict)


class AgentScheduler:
    """Schedule agent dispatches in a background thread.

    Each schedule runs independently; a failed dispatch is recorded and does
    not stop future dispatches of that schedule.
    """

    def __init__(self, orchestrator: AgentOrchestrator) -> None:
        self._orchestrator = orchestrator
        self._schedules: dict[str, AgentSchedule] = {}
        self._last_run: dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def register(self, schedule: AgentSchedule) -> None:
        """Register a recurring schedule."""
        self._schedules[schedule.name] = schedule
        self._last_run[schedule.name] = 0.0

    def start(self) -> None:
        """Start the background dispatch loop."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="hunterx-agent-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background dispatch loop."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            for schedule in list(self._schedules.values()):
                if now - self._last_run[schedule.name] >= schedule.interval_seconds:
                    self._last_run[schedule.name] = now
                    self._dispatch(schedule)
            self._stop.wait(1.0)

    def _dispatch(self, schedule: AgentSchedule) -> None:
        context = AgentContext(
            mission_id=schedule.mission_id,
            target=schedule.target,
            parameters=dict(schedule.parameters),
        )
        outcome = self._orchestrator.dispatch(agent_name=schedule.agent_name, context=context)
        if isinstance(outcome, Failure):
            # Recorded only; the loop keeps scheduling.
            return
