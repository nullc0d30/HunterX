# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Audit and version-history recording for the TIDB.

Append-only audit trail plus field-level change history and version markers.
The :class:`VersioningListener` hooks SQLAlchemy session events and records
every create/update/soft-delete/hard-delete against the TIDB audit tables
(``AuditLog``, ``AuditEvent``, ``ChangeHistory``, ``VersionHistory``). These
records make every change attributable and replayable per the Development
Bible (`09 - Database Design.md` §6). Capability logic never writes these
tables directly; the persistence layer does.
"""

from __future__ import annotations

from typing import Any

import sqlalchemy.event

from hunterx.infrastructure.db.sql.tidb_models import (
    AuditEventModel,
    AuditLogModel,
    ChangeHistoryModel,
    TimelineEventModel,
    VersionHistoryModel,
)
from hunterx.infrastructure.db.sql.tidb_models._base import TidbModelMixin
from hunterx.shared.ids import generate_id
from hunterx.shared.json_safe import to_json_safe
from hunterx.shared.time import utcnow_iso

# Audit models carry the same envelope (they extend ``TidbModelMixin``) but are
# themselves never versioned — recording them would recurse forever.
_AUDIT_MODEL_CLASSES: tuple[type, ...] = (
    AuditLogModel,
    AuditEventModel,
    ChangeHistoryModel,
    VersionHistoryModel,
    TimelineEventModel,
)

# Envelope/noise columns excluded from field-level change history.
_HISTORY_SKIP = {"id", "created_at", "updated_at", "version", "revision"}


def _is_versioned(obj: object) -> bool:
    """Return ``True`` when ``obj`` is a versioned TIDB model row."""
    if not isinstance(obj, TidbModelMixin):
        return False
    return not isinstance(obj, _AUDIT_MODEL_CLASSES)


def _snapshot(row: TidbModelMixin) -> dict[str, object]:
    """Capture a JSON-safe snapshot of a model row's columns.

    Values are passed through the canonical :func:`to_json_safe` boundary so
    audit/history payloads are JSON-native Python structures even before the
    engine serializer runs — a parser object that leaked into a JSON column
    (e.g. a JavaScript ``JSToken``) can never crash the commit and is preserved
    with its semantic fields for forensics.
    """
    data: dict[str, object] = {}
    for column in row.__table__.columns:
        key = column.key
        value = getattr(row, key)
        data[key] = to_json_safe(value) if value is not None else None
    return data


def _before_snapshot(row: TidbModelMixin) -> dict[str, object]:
    """Reconstruct the last-flushed column state of a possibly dirty row."""
    state = inspect_safe(row)
    committed = getattr(state, "committed_state", {}) or {}
    before: dict[str, object] = {}
    for column in row.__table__.columns:
        key = column.key
        if key in committed:
            before[key] = to_json_safe(committed[key]) if committed[key] is not None else None
        else:
            value = getattr(row, key)
            before[key] = to_json_safe(value) if value is not None else None
    return before


def inspect_safe(row: TidbModelMixin) -> Any:
    """Return the SQLAlchemy inspection state for a row."""
    from sqlalchemy import inspect

    return inspect(row)


def _object_type(row: TidbModelMixin) -> str:
    """Return the stable type name for an object."""
    return row.__class__.__name__.replace("Model", "").lower()


def _field_changes(
    before: dict[str, object], after: dict[str, object]
) -> list[tuple[str, object, object]]:
    """Return ``(field, old, new)`` tuples for every changed field."""
    changes: list[tuple[str, object, object]] = []
    for key, new_value in after.items():
        if key in _HISTORY_SKIP:
            continue
        old_value = before.get(key)
        if old_value != new_value:
            changes.append((key, old_value, new_value))
    return changes


class VersioningListener:
    """Records audit/history rows on TIDB model flushes.

    Install once per :class:`SessionFactory` via :meth:`install`. The listener
    reads before-states from the ORM's committed state, so it does not issue
    extra SELECTs and is safe to use on high-volume tables.
    """

    def __init__(
        self,
        *,
        actor: str | None = None,
        source: str = "tidb",
        request_id: str | None = None,
    ) -> None:
        self._actor = actor
        self._source = source
        self._request_id = request_id

    def install(self, session_factory: Any) -> None:
        """Attach the flush hooks to a session factory's sessions."""
        session_maker = getattr(session_factory, "_session_factory", session_factory)
        sqlalchemy.event.listen(session_maker, "before_flush", self._before_flush)

    def _before_flush(self, session: Any, _flush_context: Any, _instances: Any) -> None:
        now = utcnow_iso()
        for obj in list(session.new):
            if _is_versioned(obj):
                self._record_create(session, obj, now)
        for obj in list(session.dirty):
            if _is_versioned(obj) and obj not in session.new:
                self._record_update(session, obj, now)
        for obj in list(session.deleted):
            if _is_versioned(obj):
                self._record_delete(session, obj, now)

    def _record_create(self, session: Any, row: TidbModelMixin, now: str) -> None:
        after = _snapshot(row)
        object_type = _object_type(row)
        object_id = str(row.id)
        object_version = int(row.version)
        session.add(
            AuditLogModel(
                id=generate_id(),
                actor=self._actor,
                action="create",
                object_type=object_type,
                object_id=object_id,
                object_version=object_version,
                before=None,
                after=after,
                ip_address=None,
                user_agent=None,
                request_id=self._request_id,
                occurred_at=now,
                created_at=now,
            )
        )
        session.add(
            VersionHistoryModel(
                id=generate_id(),
                entity_type=object_type,
                entity_id=object_id,
                recorded_version=object_version,
                recorded_revision=int(row.revision),
                status="current",
                reason="create",
                snapshot=after,
                created_by=self._actor,
                created_at=now,
            )
        )
        session.add(
            TimelineEventModel(
                id=generate_id(),
                entity_type=object_type,
                entity_id=object_id,
                event_type=f"{object_type}.created",
                title=f"{object_type} created",
                payload=after,
                source=self._source,
                occurred_at=now,
                created_at=now,
            )
        )

    def _record_update(self, session: Any, row: TidbModelMixin, now: str) -> None:
        before = _before_snapshot(row)
        after = _snapshot(row)
        object_type = _object_type(row)
        object_id = str(row.id)
        object_version = int(row.version)

        action = "delete" if before.get("deleted_at") is None and after.get("deleted_at") is not None else "update"

        session.add(
            AuditLogModel(
                id=generate_id(),
                actor=self._actor,
                action=action,
                object_type=object_type,
                object_id=object_id,
                object_version=object_version,
                before=before,
                after=after,
                ip_address=None,
                user_agent=None,
                request_id=self._request_id,
                occurred_at=now,
                created_at=now,
            )
        )
        for field, old_value, new_value in _field_changes(before, after):
            session.add(
                ChangeHistoryModel(
                    id=generate_id(),
                    entity_type=object_type,
                    entity_id=object_id,
                    field_name=field,
                    old_value=old_value,
                    new_value=new_value,
                    changed_by=self._actor,
                    changed_at=now,
                    created_at=now,
                )
            )
        session.add(
            VersionHistoryModel(
                id=generate_id(),
                entity_type=object_type,
                entity_id=object_id,
                recorded_version=object_version,
                recorded_revision=int(row.revision),
                status="current",
                reason=action,
                snapshot=after,
                created_by=self._actor,
                created_at=now,
            )
        )
        session.add(
            TimelineEventModel(
                id=generate_id(),
                entity_type=object_type,
                entity_id=object_id,
                event_type=f"{object_type}.updated",
                title=f"{object_type} updated",
                payload=_field_changes(before, after),
                source=self._source,
                occurred_at=now,
                created_at=now,
            )
        )

    def _record_delete(self, session: Any, row: TidbModelMixin, now: str) -> None:
        before = _snapshot(row)
        object_type = _object_type(row)
        object_id = str(row.id)
        session.add(
            AuditLogModel(
                id=generate_id(),
                actor=self._actor,
                action="delete",
                object_type=object_type,
                object_id=object_id,
                object_version=int(row.version),
                before=before,
                after=None,
                ip_address=None,
                user_agent=None,
                request_id=self._request_id,
                occurred_at=now,
                created_at=now,
            )
        )
        session.add(
            TimelineEventModel(
                id=generate_id(),
                entity_type=object_type,
                entity_id=object_id,
                event_type=f"{object_type}.deleted",
                title=f"{object_type} deleted",
                payload=before,
                source=self._source,
                occurred_at=now,
                created_at=now,
            )
        )


def install_versioning(session_factory: Any, **kwargs: object) -> VersioningListener:
    """Create and attach a :class:`VersioningListener` to a session factory."""
    listener = VersioningListener(**kwargs)
    listener.install(session_factory)
    return listener
