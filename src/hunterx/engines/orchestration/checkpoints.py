# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission checkpoints.

Persist mission checkpoints so a mission can pause, resume and recover from
crashes. A checkpoint captures the mission state, the plan version, the
completed/pending/failed steps and the recorded gate decisions. The snapshot is
JSON-safe and can be restored to continue the mission without redoing completed
destructive or expensive operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class MissionCheckpoint:
    """A point-in-time snapshot of a mission.

    Attributes:
        checkpoint_id: stable checkpoint identifier.
        mission_id: owning mission.
        plan_id: owning plan.
        mission_state: mission lifecycle state at checkpoint time.
        plan_version: plan version at checkpoint time.
        completed_steps: step ids completed at checkpoint time.
        pending_steps: step ids still pending.
        failed_steps: step ids that failed.
        blocked_steps: step ids that were blocked.
        records: gate records collected so far.
        created_at: UTC ISO-8601 timestamp.
        checkpoint_version: checkpoint sequence version.

    """

    checkpoint_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    plan_id: str = ""
    mission_state: str = "running"
    plan_version: int = 1
    label: str = ""
    completed_steps: tuple[str, ...] = ()
    pending_steps: tuple[str, ...] = ()
    failed_steps: tuple[str, ...] = ()
    blocked_steps: tuple[str, ...] = ()
    records: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)
    checkpoint_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "checkpoint_id": self.checkpoint_id,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "mission_state": self.mission_state,
            "plan_version": self.plan_version,
            "completed_steps": list(self.completed_steps),
            "pending_steps": list(self.pending_steps),
            "failed_steps": list(self.failed_steps),
            "blocked_steps": list(self.blocked_steps),
            "records": self.records,
            "created_at": self.created_at,
            "checkpoint_version": self.checkpoint_version,
        }


class MissionCheckpointManager:
    """Creates and restores mission checkpoints.

    The manager is deterministic: ``create`` derives the completed/pending/
    failed/blocked step sets from a mission run result and a plan. ``restore``
    reconstructs the step sets from a checkpoint snapshot.
    """

    def __init__(self, *, repository: Any | None = None) -> None:
        self._repository = repository
        self._store: dict[str, MissionCheckpoint] = {}

    def create(
        self,
        *,
        mission_id: str,
        plan_id: str,
        mission_state: str = "running",
        plan_version: int = 1,
        label: str = "",
        completed_steps: list[str] | None = None,
        pending_steps: list[str] | None = None,
        failed_steps: list[str] | None = None,
        blocked_steps: list[str] | None = None,
        records: dict[str, list[dict[str, object]]] | None = None,
        checkpoint_id: str | None = None,
    ) -> MissionCheckpoint:
        """Create a mission checkpoint from explicit step sets."""
        checkpoint = MissionCheckpoint(
            checkpoint_id=checkpoint_id or generate_id(),
            mission_id=mission_id,
            plan_id=plan_id,
            mission_state=mission_state,
            plan_version=plan_version,
            label=label,
            completed_steps=tuple(completed_steps or ()),
            pending_steps=tuple(pending_steps or ()),
            failed_steps=tuple(failed_steps or ()),
            blocked_steps=tuple(blocked_steps or ()),
            records=records or {},
        )
        self._store[checkpoint.checkpoint_id] = checkpoint
        if self._repository is not None:
            self._repository.save(checkpoint)
        return checkpoint

    def latest(self, plan_id: str) -> MissionCheckpoint | None:
        """Return the most recent checkpoint for a plan, or ``None``."""
        checkpoints = [c for c in self._store.values() if c.plan_id == plan_id]
        if not checkpoints:
            return None
        return max(checkpoints, key=lambda c: c.created_at)

    def get(self, checkpoint_id: str) -> MissionCheckpoint | None:
        """Return a checkpoint by identifier, or ``None``."""
        return self._store.get(checkpoint_id)

    def list(self, plan_id: str, *, limit: int = 100) -> list[MissionCheckpoint]:
        """Return checkpoints for a plan, most recent first."""
        checkpoints = [c for c in self._store.values() if c.plan_id == plan_id]
        checkpoints.sort(key=lambda c: c.created_at, reverse=True)
        return checkpoints[:limit]

    def restore(self, checkpoint_id: str) -> MissionCheckpoint | None:
        """Return the snapshot for a checkpoint (the store keeps it)."""
        return self.get(checkpoint_id)

    def resume_state(self, checkpoint: MissionCheckpoint) -> dict[str, Any]:
        """Return a resume state mapping for a checkpoint.

        The mapping carries the completed/failed/blocked/pending step sets so an
        executor can continue from the checkpoint without repeating completed
        work.
        """
        return {
            "completed": list(checkpoint.completed_steps),
            "pending": list(checkpoint.pending_steps),
            "failed": list(checkpoint.failed_steps),
            "blocked": list(checkpoint.blocked_steps),
            "records": checkpoint.records,
            "plan_version": checkpoint.plan_version,
            "checkpoint_id": checkpoint.checkpoint_id,
        }
