# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory orchestration repositories.

Reference implementations of the orchestration repository ports without any
database. Used by the platform composition root as the default persistence
backend and by the test suite.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.orchestration.models import ExecutionPlan, OffensiveMission
from hunterx.domain.orchestration.selection import ToolSelection
from hunterx.domain.ports.orchestration import (
    ExecutionPlanRepository,
    OffensiveMissionRepository,
    ToolSelectionRepository,
)


class InMemoryOffensiveMissionRepository(OffensiveMissionRepository):
    """In-memory :class:`OffensiveMissionRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, OffensiveMission] = {}

    def save(self, mission: OffensiveMission) -> None:
        """Persist (insert or update) a mission."""
        self._store[mission.mission_id] = mission

    def get(self, mission_id: str) -> OffensiveMission | None:
        """Return a mission by identifier, or ``None`` if absent."""
        return self._store.get(mission_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[OffensiveMission]:
        """Return a page of missions ordered by creation time."""
        values = list(self._store.values())
        return values[offset : offset + limit]

    def list_by_state(self, state: str, *, limit: int = 100) -> Sequence[OffensiveMission]:
        """Return missions in a given lifecycle state, most recent first."""
        return [m for m in self._store.values() if m.state.value == state][:limit]

    def delete(self, mission_id: str) -> None:
        """Delete a mission, raising when absent."""
        if mission_id not in self._store:
            raise NotFoundError("OffensiveMission", mission_id)
        del self._store[mission_id]


class InMemoryExecutionPlanRepository(ExecutionPlanRepository):
    """In-memory :class:`ExecutionPlanRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, ExecutionPlan] = {}

    def save(self, plan: ExecutionPlan) -> None:
        """Persist (insert or update) a plan."""
        self._store[plan.plan_id] = plan

    def get(self, plan_id: str) -> ExecutionPlan | None:
        """Return a plan by identifier, or ``None`` if absent."""
        return self._store.get(plan_id)

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[ExecutionPlan]:
        """Return plans belonging to a mission, most recent first."""
        return [p for p in self._store.values() if p.mission_id == mission_id][:limit]

    def delete(self, plan_id: str) -> None:
        """Delete a plan, raising when absent."""
        if plan_id not in self._store:
            raise NotFoundError("ExecutionPlan", plan_id)
        del self._store[plan_id]


class InMemoryToolSelectionRepository(ToolSelectionRepository):
    """In-memory :class:`ToolSelectionRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, ToolSelection] = {}

    def save(self, selection: ToolSelection) -> None:
        """Persist a selection record."""
        self._store[selection.selection_id] = selection

    def get(self, selection_id: str) -> ToolSelection | None:
        """Return a selection by identifier, or ``None`` if absent."""
        return self._store.get(selection_id)

    def list_by_step(self, step_id: str, *, limit: int = 100) -> Sequence[ToolSelection]:
        """Return selections for a step, most recent first."""
        return [s for s in self._store.values() if s.step_id == step_id][:limit]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[ToolSelection]:
        """Return selections for a mission, most recent first."""
        return [s for s in self._store.values() if s.mission_id == mission_id][:limit]


def build_in_memory_orchestration_repositories() -> dict[str, object]:
    """Build all in-memory orchestration repositories keyed by role name."""
    return {
        "offensive_missions": InMemoryOffensiveMissionRepository(),
        "execution_plans": InMemoryExecutionPlanRepository(),
        "tool_selections": InMemoryToolSelectionRepository(),
    }
