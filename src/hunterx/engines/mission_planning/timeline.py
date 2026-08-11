# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission timeline recorder.

Appends JSON-safe facts about a mission's lifecycle to a timeline and exposes
the history. Every state transition and notable planning event produces a
:class:`~hunterx.domain.mission_planning.MissionTimelineEntry`. Records are
also appended to a :class:`MissionTimelineRepository` when one is wired in.
"""

from __future__ import annotations

from hunterx.domain.mission_planning import MissionPlan, MissionPlanningStatus, MissionTimelineEntry
from hunterx.domain.ports.mission_planning import MissionTimelineRepository
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Canonical timeline event types emitted by the planning engine.
EVENT_CREATED = "mission.created"
EVENT_QUEUED = "mission.queued"
EVENT_PLANNING = "mission.planning"
EVENT_PLANNED = "mission.planned"
EVENT_READY = "mission.ready"
EVENT_STARTED = "mission.started"
EVENT_PAUSED = "mission.paused"
EVENT_RESUMED = "mission.resumed"
EVENT_WAITING = "mission.waiting"
EVENT_UNWAITED = "mission.unwaited"
EVENT_RETRYING = "mission.retrying"
EVENT_RETRY_RESUMED = "mission.retry_resumed"
EVENT_COMPLETED = "mission.completed"
EVENT_CANCELLED = "mission.cancelled"
EVENT_FAILED = "mission.failed"
EVENT_ARCHIVED = "mission.archived"
EVENT_PHASE_STARTED = "mission.phase.started"
EVENT_PHASE_COMPLETED = "mission.phase.completed"
EVENT_PHASE_FAILED = "mission.phase.failed"
EVENT_CHECKPOINT_CREATED = "mission.checkpoint.created"
EVENT_CHECKPOINT_RESTORED = "mission.checkpoint.restored"
EVENT_GRAPH_BUILT = "mission.graph.built"

#: Mapping of mission lifecycle state to its canonical timeline event.
_STATUS_EVENTS: dict[MissionPlanningStatus, str] = {
    MissionPlanningStatus.CREATED: EVENT_CREATED,
    MissionPlanningStatus.QUEUED: EVENT_QUEUED,
    MissionPlanningStatus.PLANNING: EVENT_PLANNING,
    MissionPlanningStatus.READY: EVENT_READY,
    MissionPlanningStatus.EXECUTING: EVENT_STARTED,
    MissionPlanningStatus.PAUSED: EVENT_PAUSED,
    MissionPlanningStatus.WAITING: EVENT_WAITING,
    MissionPlanningStatus.RETRYING: EVENT_RETRYING,
    MissionPlanningStatus.COMPLETED: EVENT_COMPLETED,
    MissionPlanningStatus.CANCELLED: EVENT_CANCELLED,
    MissionPlanningStatus.FAILED: EVENT_FAILED,
    MissionPlanningStatus.ARCHIVED: EVENT_ARCHIVED,
}


class MissionTimeline:
    """Append and query mission timeline entries."""

    def __init__(self, repository: MissionTimelineRepository | None = None) -> None:
        self._repository = repository
        self._store: list[MissionTimelineEntry] = []

    def record(
        self,
        mission_id: str,
        event_type: str,
        *,
        plan_id: str | None = None,
        source: str = "mission.planning",
        **payload: object,
    ) -> MissionTimelineEntry:
        """Append a timeline entry and return it."""
        entry = MissionTimelineEntry(
            entry_id=generate_id(),
            mission_id=mission_id,
            plan_id=plan_id,
            event_type=event_type,
            payload=dict(payload),
            source=source,
            occurred_at=utcnow_iso(),
        )
        self._store.append(entry)
        if self._repository is not None:
            self._repository.append(entry)
        return entry

    def record_status(self, plan: MissionPlan) -> MissionTimelineEntry:
        """Append the canonical entry for a plan's current status."""
        event_type = _STATUS_EVENTS.get(plan.status, EVENT_CREATED)
        return self.record(
            plan.mission_id,
            event_type,
            plan_id=plan.plan_id,
            **{"status": plan.status.value, "progress": plan.progress},
        )

    def phase_started(self, plan: MissionPlan, phase_id: str) -> MissionTimelineEntry:
        """Record that a phase began running."""
        return self.record(
            plan.mission_id,
            EVENT_PHASE_STARTED,
            plan_id=plan.plan_id,
            **{"phase_id": phase_id},
        )

    def phase_completed(self, plan: MissionPlan, phase_id: str) -> MissionTimelineEntry:
        """Record that a phase finished successfully."""
        return self.record(
            plan.mission_id,
            EVENT_PHASE_COMPLETED,
            plan_id=plan.plan_id,
            **{"phase_id": phase_id},
        )

    def phase_failed(self, plan: MissionPlan, phase_id: str, reason: str = "") -> MissionTimelineEntry:
        """Record that a phase failed."""
        return self.record(
            plan.mission_id,
            EVENT_PHASE_FAILED,
            plan_id=plan.plan_id,
            **{"phase_id": phase_id, "reason": reason},
        )

    def checkpoint_created(self, plan: MissionPlan, checkpoint_id: str, label: str) -> MissionTimelineEntry:
        """Record that a checkpoint was created."""
        return self.record(
            plan.mission_id,
            EVENT_CHECKPOINT_CREATED,
            plan_id=plan.plan_id,
            **{"checkpoint_id": checkpoint_id, "label": label},
        )

    def checkpoint_restored(self, plan: MissionPlan, checkpoint_id: str) -> MissionTimelineEntry:
        """Record that a checkpoint was restored."""
        return self.record(
            plan.mission_id,
            EVENT_CHECKPOINT_RESTORED,
            plan_id=plan.plan_id,
            **{"checkpoint_id": checkpoint_id},
        )

    def graph_built(self, plan: MissionPlan, node_count: int) -> MissionTimelineEntry:
        """Record that an execution graph was built for the plan."""
        return self.record(
            plan.mission_id,
            EVENT_GRAPH_BUILT,
            plan_id=plan.plan_id,
            **{"node_count": node_count},
        )

    # -- queries -----------------------------------------------------------

    def history(self, mission_id: str) -> list[MissionTimelineEntry]:
        """Return every timeline entry for a mission, oldest first."""
        if self._repository is not None and not self._store:
            self._store = list(self._repository.list_by_mission(mission_id, limit=10_000))
        return [entry for entry in self._store if entry.mission_id == mission_id]

    def events(self, mission_id: str) -> list[str]:
        """Return the ordered event types recorded for a mission."""
        return [entry.event_type for entry in self.history(mission_id)]
