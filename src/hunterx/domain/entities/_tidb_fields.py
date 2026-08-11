# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""TIDB envelope mixin for canonical (pre-TIDB) domain entities.

The canonical entities (``Target``, ``Finding``, ``Evidence``, ``Report``,
``Asset``, ``Scan``, ``Mission``) predate the Target Intelligence Database.
This mixin adds the shared system-of-record envelope required by the USS
(`08 - Unified Security Schema.md`): versioning, soft delete and first/last
seen tracking, so the canonical entities can live in the same schema as the
TIDB entities and be mapped by the generic row mapper.

The mixin is implemented with ``getattr``/``setattr`` so it can attach to any
dataclass that declares the envelope fields with defaults.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class TidbEnvelopeMixin:
    """Shared versioning/soft-delete/observation behaviour.

    Requires the owning dataclass to declare, with defaults: ``updated_at``,
    ``first_seen``, ``last_seen``, ``version``, ``revision``,
    ``schema_version`` and ``deleted_at``. Existing ``created_at`` and
    ``metadata`` fields are used as-is when present.
    """

    def touch(self, *, now: str | None = None) -> None:
        """Record a write: bump version/revision and refresh timestamps."""
        import hunterx.shared.time as time_util

        stamp = now or time_util.utcnow_iso()
        self.updated_at = stamp  # type: ignore[attr-defined]
        if self.last_seen is None:  # type: ignore[attr-defined]
            self.last_seen = stamp  # type: ignore[attr-defined]
        self.version += 1  # type: ignore[attr-defined]
        self.revision += 1  # type: ignore[attr-defined]

    def mark_seen(self, *, now: str | None = None) -> None:
        """Record an observation (first/last seen tracking)."""
        import hunterx.shared.time as time_util

        stamp = now or time_util.utcnow_iso()
        if self.first_seen is None:  # type: ignore[attr-defined]
            self.first_seen = stamp  # type: ignore[attr-defined]
        self.last_seen = stamp  # type: ignore[attr-defined]

    def soft_delete(self, *, now: str | None = None) -> None:
        """Mark the entity deleted without removing the row."""
        import hunterx.shared.time as time_util

        self.deleted_at = now or time_util.utcnow_iso()  # type: ignore[attr-defined]
        self.updated_at = self.deleted_at  # type: ignore[attr-defined]
        self.version += 1  # type: ignore[attr-defined]
        self.revision += 1  # type: ignore[attr-defined]

    @property
    def is_deleted(self) -> bool:
        """Return ``True`` when the entity is soft-deleted."""
        return bool(getattr(self, "deleted_at", None))

    @property
    def tidb_meta(self) -> dict[str, Any]:
        """The free-form ``metadata`` map used by the TIDB mapper."""
        return getattr(self, "metadata", getattr(self, "meta", {})) or {}

    def to_tidb_snapshot(self) -> dict[str, Any]:
        """Serialize the envelope for the version-history snapshot."""
        return {
            "id": getattr(self, "target_id", None)
            or getattr(self, "finding_id", None)
            or getattr(self, "artifact_id", None)
            or getattr(self, "report_id", None)
            or getattr(self, "asset_id", None)
            or getattr(self, "scan_id", None)
            or getattr(self, "mission_id", None),
            "created_at": getattr(self, "created_at", None),
            "updated_at": getattr(self, "updated_at", None),
            "first_seen": getattr(self, "first_seen", None),
            "last_seen": getattr(self, "last_seen", None),
            "version": getattr(self, "version", 1),
            "revision": getattr(self, "revision", 1),
            "schema_version": getattr(self, "schema_version", 1),
            "deleted_at": getattr(self, "deleted_at", None),
        }


def tidb_envelope_fields() -> list[tuple[str, object]]:
    """Return the envelope field declarations for the canonical entities.

    Each pair is ``(name, default)`` intended to be merged into a dataclass
    body that also inherits :class:`TidbEnvelopeMixin`.
    """
    from dataclasses import field

    return [
        ("updated_at", None),
        ("first_seen", None),
        ("last_seen", None),
        ("version", 1),
        ("revision", 1),
        ("schema_version", 1),
        ("deleted_at", None),
        ("meta", field(default_factory=dict)),
    ]
