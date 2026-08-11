# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission entity.

A mission is a scheduled or on-demand security operation over a set of
authorized targets. Missions carry state and progress; the mission engine
drives their lifecycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.entities._tidb_fields import TidbEnvelopeMixin
from hunterx.domain.exceptions import InvalidMissionError
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class MissionStatus(Enum):
    """Lifecycle states of a mission."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MissionPriority(Enum):
    """Scheduling priority of a mission."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MissionKind(Enum):
    """Kind of security operation a mission performs."""

    RECON = "recon"
    SCAN = "scan"
    ASSESS = "assess"
    MONITOR = "monitor"
    CUSTOM = "custom"


@dataclass(slots=True)
class Mission(TidbEnvelopeMixin):
    """An atomic security operation.

    Attributes:
        name: human-readable mission name.
        kind: type of operation.
        targets: authorized target identifiers (scope roots).
        workflow: name of the workflow to execute.
        priority: scheduling priority.
        config: mission-scoped configuration.
        status: current lifecycle state.
        progress: completion percentage in ``[0, 100]``.
        mission_id: stable identity.
        updated_at / first_seen / last_seen / version / revision /
        schema_version / deleted_at: TIDB envelope.

    """

    name: str
    workflow: str
    kind: MissionKind = MissionKind.SCAN
    targets: list[str] = field(default_factory=list)
    priority: MissionPriority = MissionPriority.MEDIUM
    config: dict[str, object] = field(default_factory=dict)
    status: MissionStatus = MissionStatus.PENDING
    progress: float = 0.0
    mission_id: str = field(default_factory=generate_id)
    created_at: str = field(default_factory=utcnow_iso)
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    version: int = 1
    revision: int = 1
    schema_version: int = 1
    deleted_at: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise InvalidMissionError("mission name must not be empty.")
        if not self.workflow:
            raise InvalidMissionError("mission workflow must not be empty.")
        if not self.targets:
            raise InvalidMissionError("mission must declare at least one target.")

    # -- state transitions ------------------------------------------------

    def start(self) -> None:
        """Transition to RUNNING."""
        if self.status in (MissionStatus.COMPLETED, MissionStatus.CANCELLED, MissionStatus.FAILED):
            raise InvalidMissionError(
                f"cannot start a mission in state '{self.status.value}'."
            )
        self.status = MissionStatus.RUNNING
        self.started_at = utcnow_iso()

    def set_progress(self, progress: float) -> None:
        """Update completion progress in ``[0, 100]``."""
        if not 0.0 <= progress <= 100.0:
            raise InvalidMissionError("progress must be in [0, 100].")
        self.progress = progress

    def complete(self) -> None:
        """Mark the mission completed."""
        self.status = MissionStatus.COMPLETED
        self.progress = 100.0
        self.finished_at = utcnow_iso()

    def fail(self) -> None:
        """Mark the mission failed."""
        self.status = MissionStatus.FAILED
        self.finished_at = utcnow_iso()

    def cancel(self) -> None:
        """Mark the mission cancelled."""
        self.status = MissionStatus.CANCELLED
        self.finished_at = utcnow_iso()
