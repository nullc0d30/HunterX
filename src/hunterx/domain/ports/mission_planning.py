# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission planning repository ports.

Persistence contracts for mission profiles, templates, plans, checkpoints and
the mission timeline. Application and engine layers depend on these
abstractions; in-memory (tests) and SQL (infrastructure) adapters implement
them.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence

from hunterx.domain.mission_planning import (
    Checkpoint,
    MissionPlan,
    MissionProfile,
    MissionTemplate,
    MissionTimelineEntry,
)


class MissionProfileRepository(abc.ABC):
    """Persistence contract for :class:`MissionProfile` records."""

    @abc.abstractmethod
    def save(self, profile: MissionProfile) -> None:
        """Persist (insert or update) a profile."""

    @abc.abstractmethod
    def get(self, profile_id: str) -> MissionProfile | None:
        """Return a profile by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionProfile]:
        """Return a page of profiles ordered by registration time."""

    @abc.abstractmethod
    def delete(self, profile_id: str) -> None:
        """Delete a profile, raising when absent."""


class MissionTemplateRepository(abc.ABC):
    """Persistence contract for :class:`MissionTemplate` records."""

    @abc.abstractmethod
    def save(self, template: MissionTemplate) -> None:
        """Persist (insert or update) a template."""

    @abc.abstractmethod
    def get(self, template_id: str) -> MissionTemplate | None:
        """Return a template by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionTemplate]:
        """Return a page of templates ordered by registration time."""

    @abc.abstractmethod
    def delete(self, template_id: str) -> None:
        """Delete a template, raising when absent."""


class MissionPlanRepository(abc.ABC):
    """Persistence contract for :class:`MissionPlan` aggregates."""

    @abc.abstractmethod
    def save(self, plan: MissionPlan) -> None:
        """Persist (insert or update) a plan."""

    @abc.abstractmethod
    def get(self, plan_id: str) -> MissionPlan | None:
        """Return a plan by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionPlan]:
        """Return a page of plans ordered by creation time."""

    @abc.abstractmethod
    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[MissionPlan]:
        """Return plans belonging to a mission, most recent first."""

    @abc.abstractmethod
    def list_by_status(self, status: str, *, limit: int = 100) -> Sequence[MissionPlan]:
        """Return plans with the given status, most recent first."""

    @abc.abstractmethod
    def delete(self, plan_id: str) -> None:
        """Delete a plan, raising when absent."""


class CheckpointRepository(abc.ABC):
    """Persistence contract for :class:`Checkpoint` records."""

    @abc.abstractmethod
    def save(self, checkpoint: Checkpoint) -> None:
        """Persist (insert) a checkpoint."""

    @abc.abstractmethod
    def get(self, checkpoint_id: str) -> Checkpoint | None:
        """Return a checkpoint by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list_by_plan(self, plan_id: str, *, limit: int = 100) -> Sequence[Checkpoint]:
        """Return checkpoints for a plan, most recent first."""

    @abc.abstractmethod
    def delete(self, checkpoint_id: str) -> None:
        """Delete a checkpoint, raising when absent."""


class MissionTimelineRepository(abc.ABC):
    """Persistence contract for :class:`MissionTimelineEntry` records."""

    @abc.abstractmethod
    def append(self, entry: MissionTimelineEntry) -> None:
        """Append a timeline entry."""

    @abc.abstractmethod
    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[MissionTimelineEntry]:
        """Return timeline entries for a mission, most recent first."""

    @abc.abstractmethod
    def delete_by_mission(self, mission_id: str) -> None:
        """Delete every timeline entry for a mission."""
