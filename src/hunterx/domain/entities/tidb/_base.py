# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base for all Target Intelligence Database (TIDB) entities.

TIDB entities are pure domain dataclasses. Every entity carries the shared
system-of-record fields required by the Development Bible (`09 - Database
Design.md` §3, §6): identity, assertion-time stamps (``created_at`` /
``updated_at``), state-time stamps (``first_seen`` / ``last_seen``), and
versioning/soft-delete support (``version``, ``revision``, ``schema_version``,
``deleted_at``).

Entities are deliberately storage-agnostic: the SQL adapter maps them to ORM
rows and back via a generic row mapper (``infrastructure.db.sql.repositories``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class TidbEntity:
    """Shared identity, timestamp and history envelope for a TIDB entity.

    Attributes:
        id: opaque stable identifier (ULID, 26 chars).
        created_at: assertion-time creation stamp (UTC ISO-8601).
        updated_at: assertion-time last-write stamp (UTC ISO-8601).
        first_seen: state-time first-observed stamp.
        last_seen: state-time last-observed stamp.
        version: optimistic-lock version, incremented on every change.
        revision: monotonic revision counter within the entity.
        schema_version: USS schema version that produced this row.
        deleted_at: soft-delete stamp; ``None`` while the entity is live.
        meta: free-form JSON-serializable attributes.

    """

    id: str = field(default_factory=generate_id, kw_only=True)
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)
    updated_at: str | None = field(default=None, kw_only=True)
    first_seen: str | None = field(default=None, kw_only=True)
    last_seen: str | None = field(default=None, kw_only=True)
    version: int = field(default=1, kw_only=True)
    revision: int = field(default=1, kw_only=True)
    schema_version: int = field(default=1, kw_only=True)
    deleted_at: str | None = field(default=None, kw_only=True)
    meta: dict[str, object] = field(default_factory=dict, kw_only=True)

    def touch(self, *, now: str | None = None) -> None:
        """Record a write: bump version/revision and refresh timestamps.

        Args:
            now: explicit UTC ISO timestamp; defaults to the current time.

        """
        import hunterx.shared.time as time_util

        stamp = now or time_util.utcnow_iso()
        self.updated_at = stamp
        self.last_seen = self.last_seen or stamp
        self.version += 1
        self.revision += 1

    def mark_seen(self, *, now: str | None = None) -> None:
        """Record an observation of the entity (first/last seen tracking)."""
        import hunterx.shared.time as time_util

        stamp = now or time_util.utcnow_iso()
        if self.first_seen is None:
            self.first_seen = stamp
        self.last_seen = stamp

    def soft_delete(self, *, now: str | None = None) -> None:
        """Mark the entity deleted without removing the row."""
        import hunterx.shared.time as time_util

        self.deleted_at = now or time_util.utcnow_iso()
        self.updated_at = self.deleted_at
        self.version += 1
        self.revision += 1

    @property
    def is_deleted(self) -> bool:
        """Return ``True`` when the entity is soft-deleted."""
        return self.deleted_at is not None
