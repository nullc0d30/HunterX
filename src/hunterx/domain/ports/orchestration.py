# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Orchestration repository ports.

Persistence contracts for the offensive orchestration layer. Adapters are
provided by the infrastructure layer (in-memory for tests/development, SQL for
production) and wired by the platform assembler.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence

from hunterx.domain.orchestration.models import ExecutionPlan, OffensiveMission
from hunterx.domain.orchestration.selection import ToolSelection


class OffensiveMissionRepository(abc.ABC):
    """Persistence contract for :class:`OffensiveMission` records."""

    @abc.abstractmethod
    def save(self, mission: OffensiveMission) -> None:
        """Persist (insert or update) a mission."""

    @abc.abstractmethod
    def get(self, mission_id: str) -> OffensiveMission | None:
        """Return a mission by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[OffensiveMission]:
        """Return a page of missions ordered by creation time."""

    @abc.abstractmethod
    def list_by_state(self, state: str, *, limit: int = 100) -> Sequence[OffensiveMission]:
        """Return missions in a given lifecycle state, most recent first."""

    @abc.abstractmethod
    def delete(self, mission_id: str) -> None:
        """Delete a mission, raising when absent."""


class ExecutionPlanRepository(abc.ABC):
    """Persistence contract for :class:`ExecutionPlan` records."""

    @abc.abstractmethod
    def save(self, plan: ExecutionPlan) -> None:
        """Persist (insert or update) a plan."""

    @abc.abstractmethod
    def get(self, plan_id: str) -> ExecutionPlan | None:
        """Return a plan by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[ExecutionPlan]:
        """Return plans belonging to a mission, most recent first."""

    @abc.abstractmethod
    def delete(self, plan_id: str) -> None:
        """Delete a plan, raising when absent."""


class ToolSelectionRepository(abc.ABC):
    """Persistence contract for :class:`ToolSelection` records."""

    @abc.abstractmethod
    def save(self, selection: ToolSelection) -> None:
        """Persist a selection record."""

    @abc.abstractmethod
    def get(self, selection_id: str) -> ToolSelection | None:
        """Return a selection by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list_by_step(self, step_id: str, *, limit: int = 100) -> Sequence[ToolSelection]:
        """Return selections for a step, most recent first."""

    @abc.abstractmethod
    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[ToolSelection]:
        """Return selections for a mission, most recent first."""
