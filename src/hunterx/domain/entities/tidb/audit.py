# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Audit and history Target Intelligence Database entities.

Append-only audit trail plus version/history records that make every change
to the TIDB attributable and replayable. These tables are written by the
persistence layer (via the versioning listener) and must never be edited by
capability logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class AuditLog(TidbEntity):
    """A single audit event.

    Attributes:
        actor: acting user/service identifier.
        action: verb (create, update, delete, login, export, ...).
        object_type: type of object affected (finding, target, ...).
        object_id: identifier of the affected object.
        object_version: version of the object at event time.
        before: snapshot of the object before the change.
        after: snapshot of the object after the change.
        ip_address: originating IP.
        user_agent: client user-agent.
        request_id: correlating request identifier.
        occurred_at: UTC ISO-8601 timestamp.

    """

    actor: str | None = None
    action: str = "update"
    object_type: str = ""
    object_id: str | None = None
    object_version: int | None = None
    before: dict[str, object] | None = None
    after: dict[str, object] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    occurred_at: str | None = None


@dataclass(slots=True)
class AuditEvent(TidbEntity):
    """A structured domain event recorded for audit.

    Attributes:
        event_type: stable machine name (e.g. ``finding.severity-changed``).
        aggregate_id: owning aggregate identifier.
        aggregate_type: aggregate type.
        payload: JSON-safe event data.
        actor: acting user/service identifier.
        source: originating component.
        occurred_at: UTC ISO-8601 timestamp.

    """

    event_type: str = ""
    aggregate_id: str | None = None
    aggregate_type: str | None = None
    payload: dict[str, object] = field(default_factory=dict)
    actor: str | None = None
    source: str = "system"
    occurred_at: str | None = None


@dataclass(slots=True)
class ChangeHistory(TidbEntity):
    """A single field-level change to an entity.

    Attributes:
        entity_type: type of entity changed.
        entity_id: identifier of the entity changed.
        field_name: name of the changed field.
        old_value: previous value.
        new_value: new value.
        changed_by: actor making the change.
        changed_at: UTC ISO-8601 timestamp.

    """

    entity_type: str = ""
    entity_id: str | None = None
    field_name: str = ""
    old_value: object = None
    new_value: object = None
    changed_by: str | None = None
    changed_at: str | None = None


@dataclass(slots=True)
class VersionHistory(TidbEntity):
    """A version marker for a versioned entity.

    Attributes:
        entity_type: type of entity versioned.
        entity_id: identifier of the entity versioned.
        recorded_version: monotonically increasing version number.
        recorded_revision: monotonically increasing revision number.
        status: version status (draft, current, superseded, ...).
        reason: reason for the version.
        snapshot: full JSON-safe entity snapshot.
        created_by: actor creating the version.

    """

    entity_type: str = ""
    entity_id: str | None = None
    recorded_version: int = 1
    recorded_revision: int = 1
    status: str = "current"
    reason: str = ""
    snapshot: dict[str, object] = field(default_factory=dict)
    created_by: str | None = None


@dataclass(slots=True)
class TimelineEvent(TidbEntity):
    """A general-purpose timeline event for any entity.

    Attributes:
        entity_type: type of entity the event belongs to.
        entity_id: identifier of the entity the event belongs to.
        event_type: stable machine name.
        title: human-readable title.
        payload: JSON-safe event data.
        source: originating component.
        occurred_at: UTC ISO-8601 timestamp.

    """

    entity_type: str = ""
    entity_id: str | None = None
    event_type: str = ""
    title: str = ""
    payload: dict[str, object] = field(default_factory=dict)
    source: str = "system"
    occurred_at: str | None = None
