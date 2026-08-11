# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Job and schedule models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class JobStatus(Enum):
    """Lifecycle states of a scheduled job."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class Job:
    """A concrete unit of scheduled work.

    Attributes:
        job_type: the operation type (e.g. ``run_mission``).
        payload: JSON-serializable job payload.
        status: current state.
        job_id: stable identity.

    """

    job_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    status: JobStatus = JobStatus.PENDING
    job_id: str = field(default_factory=generate_id)
    created_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True, slots=True)
class Schedule:
    """A recurring trigger for a job type.

    Attributes:
        name: unique schedule name.
        job_type: the operation to trigger.
        interval_seconds: seconds between triggers.
        payload: static payload merged into every triggered job.
        enabled: whether the schedule is active.

    """

    name: str
    job_type: str
    interval_seconds: float
    payload: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
