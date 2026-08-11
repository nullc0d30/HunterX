# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory mission planning repositories.

Reference implementations of the mission planning repository ports without any
database. Used by the platform composition root as the default persistence
backend and by the test suite.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.mission_planning import (
    Checkpoint,
    MissionPlan,
    MissionProfile,
    MissionTemplate,
    MissionTimelineEntry,
)
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)


class InMemoryMissionProfileRepository(MissionProfileRepository):
    """In-memory :class:`MissionProfileRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, MissionProfile] = {}

    def save(self, profile: MissionProfile) -> None:
        """Persist (insert or update) a profile."""
        self._store[profile.profile_id] = profile

    def get(self, profile_id: str) -> MissionProfile | None:
        """Return a profile by identifier, or ``None`` if absent."""
        return self._store.get(profile_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionProfile]:
        """Return a page of profiles ordered by registration time."""
        values = list(self._store.values())
        return values[offset : offset + limit]

    def delete(self, profile_id: str) -> None:
        """Delete a profile, raising when absent."""
        if profile_id not in self._store:
            raise NotFoundError("MissionProfile", profile_id)
        del self._store[profile_id]


class InMemoryMissionTemplateRepository(MissionTemplateRepository):
    """In-memory :class:`MissionTemplateRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, MissionTemplate] = {}

    def save(self, template: MissionTemplate) -> None:
        """Persist (insert or update) a template."""
        self._store[template.template_id] = template

    def get(self, template_id: str) -> MissionTemplate | None:
        """Return a template by identifier, or ``None`` if absent."""
        return self._store.get(template_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionTemplate]:
        """Return a page of templates ordered by registration time."""
        values = list(self._store.values())
        return values[offset : offset + limit]

    def delete(self, template_id: str) -> None:
        """Delete a template, raising when absent."""
        if template_id not in self._store:
            raise NotFoundError("MissionTemplate", template_id)
        del self._store[template_id]


class InMemoryMissionPlanRepository(MissionPlanRepository):
    """In-memory :class:`MissionPlanRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, MissionPlan] = {}

    def save(self, plan: MissionPlan) -> None:
        """Persist (insert or update) a plan."""
        self._store[plan.plan_id] = plan

    def get(self, plan_id: str) -> MissionPlan | None:
        """Return a plan by identifier, or ``None`` if absent."""
        return self._store.get(plan_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionPlan]:
        """Return a page of plans ordered by creation time."""
        values = list(self._store.values())
        return values[offset : offset + limit]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[MissionPlan]:
        """Return plans belonging to a mission, most recent first."""
        return [p for p in self._store.values() if p.mission_id == mission_id][:limit]

    def list_by_status(self, status: str, *, limit: int = 100) -> Sequence[MissionPlan]:
        """Return plans with the given status, most recent first."""
        return [p for p in self._store.values() if p.status.value == status][:limit]

    def delete(self, plan_id: str) -> None:
        """Delete a plan, raising when absent."""
        if plan_id not in self._store:
            raise NotFoundError("MissionPlan", plan_id)
        del self._store[plan_id]


class InMemoryCheckpointRepository(CheckpointRepository):
    """In-memory :class:`CheckpointRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Checkpoint] = {}

    def save(self, checkpoint: Checkpoint) -> None:
        """Persist (insert) a checkpoint."""
        self._store[checkpoint.checkpoint_id] = checkpoint

    def get(self, checkpoint_id: str) -> Checkpoint | None:
        """Return a checkpoint by identifier, or ``None`` if absent."""
        return self._store.get(checkpoint_id)

    def list_by_plan(self, plan_id: str, *, limit: int = 100) -> Sequence[Checkpoint]:
        """Return checkpoints for a plan, most recent first."""
        values = sorted(
            (c for c in self._store.values() if c.plan_id == plan_id),
            key=lambda c: c.created_at,
            reverse=True,
        )
        return values[:limit]

    def delete(self, checkpoint_id: str) -> None:
        """Delete a checkpoint, raising when absent."""
        if checkpoint_id not in self._store:
            raise NotFoundError("Checkpoint", checkpoint_id)
        del self._store[checkpoint_id]


class InMemoryMissionTimelineRepository(MissionTimelineRepository):
    """In-memory :class:`MissionTimelineRepository`."""

    def __init__(self) -> None:
        self._store: list[MissionTimelineEntry] = []

    def append(self, entry: MissionTimelineEntry) -> None:
        """Append a timeline entry."""
        self._store.append(entry)

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[MissionTimelineEntry]:
        """Return timeline entries for a mission, most recent first."""
        entries = [e for e in self._store if e.mission_id == mission_id]
        return entries[-limit:]

    def delete_by_mission(self, mission_id: str) -> None:
        """Delete every timeline entry for a mission."""
        self._store = [e for e in self._store if e.mission_id != mission_id]


def build_in_memory_planning_repositories() -> dict[str, object]:
    """Build all in-memory mission planning repositories keyed by role name."""
    return {
        "mission_profiles": InMemoryMissionProfileRepository(),
        "mission_templates": InMemoryMissionTemplateRepository(),
        "mission_plans": InMemoryMissionPlanRepository(),
        "checkpoints": InMemoryCheckpointRepository(),
        "mission_timeline": InMemoryMissionTimelineRepository(),
    }
