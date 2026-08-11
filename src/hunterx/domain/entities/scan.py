# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scan entity.

A scan represents a single tool execution pass over a target within a mission.
Scans are the schedulable unit of work that the scheduler dispatches to the
tool executor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.entities._tidb_fields import TidbEnvelopeMixin
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ScanStatus(Enum):
    """Lifecycle states of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(slots=True)
class Scan(TidbEnvelopeMixin):
    """A unit of tool-execution work.

    Attributes:
        mission_id: owning mission.
        tool: tool/plugin name to execute.
        target: target identifier to scan.
        parameters: tool-specific parameters.
        status: current state.
        scan_id: stable identity.
        updated_at / first_seen / last_seen / version / revision /
        schema_version / deleted_at: TIDB envelope.

    """

    mission_id: str
    tool: str
    target: str
    parameters: dict[str, object] = field(default_factory=dict)
    status: ScanStatus = ScanStatus.PENDING
    scan_id: str = field(default_factory=generate_id)
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    version: int = 1
    revision: int = 1
    schema_version: int = 1
    deleted_at: str | None = None
