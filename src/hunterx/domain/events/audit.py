# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Audit event types.

Typed audit events recorded for compliance and forensics: authentication,
authorization, configuration changes, mission lifecycle, tool execution,
plugin lifecycle and database changes. These ride the same event bus as every
other event and are additionally persisted by the event store.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.events import DomainEvent
from hunterx.domain.events.enums import EventCategory, EventSeverity


def _audit(category: EventCategory, event_type: str, payload: dict[str, Any], *, source: str) -> DomainEvent:
    return DomainEvent(
        event_type=event_type,
        payload=payload,
        source=source,
        category=category,
        severity=EventSeverity.NOTICE,
    )


def _audit_scoped(
    category: EventCategory,
    event_type: str,
    payload: dict[str, Any],
    *,
    source: str,
    mission_id: str | None = None,
    execution_id: str | None = None,
) -> DomainEvent:
    return DomainEvent(
        event_type=event_type,
        payload=payload,
        source=source,
        category=category,
        severity=EventSeverity.NOTICE,
        mission_id=mission_id,
        execution_id=execution_id,
    )


class AuditEventFactory:
    """Convenience constructors for the seven audit event kinds."""

    @staticmethod
    def authentication(actor: str, *, succeeded: bool, detail: str = "", source: str = "security") -> DomainEvent:
        """Record an authentication attempt."""
        return _audit(
            EventCategory.SECURITY,
            "security.authenticated" if succeeded else "security.denied",
            {"actor": actor, "succeeded": succeeded, "detail": detail},
            source=source,
        )

    @staticmethod
    def authorization(
        actor: str, action: str, *, allowed: bool, resource: str = "", source: str = "security"
    ) -> DomainEvent:
        """Record an authorization decision."""
        event_type = "security.authorized" if allowed else "security.denied"
        return _audit(
            EventCategory.SECURITY,
            event_type,
            {"actor": actor, "action": action, "allowed": allowed, "resource": resource},
            source=source,
        )

    @staticmethod
    def configuration_change(
        key: str, *, before: Any = None, after: Any = None, actor: str = "system", source: str = "config"
    ) -> DomainEvent:
        """Record a configuration change."""
        return _audit(
            EventCategory.CONFIGURATION,
            "configuration.updated",
            {"key": key, "before": before, "after": after, "actor": actor},
            source=source,
        )

    @staticmethod
    def mission_lifecycle(mission_id: str, state: str, *, source: str = "mission.engine") -> DomainEvent:
        """Record a mission lifecycle transition."""
        return _audit_scoped(
            EventCategory.MISSION,
            f"mission.{state}",
            {"mission_id": mission_id, "state": state},
            source=source,
            mission_id=mission_id,
        )

    @staticmethod
    def tool_execution(
        tool: str,
        *,
        succeeded: bool,
        duration_ms: int = 0,
        mission_id: str | None = None,
        source: str = "tool.executor",
    ) -> DomainEvent:
        """Record a tool execution."""
        return _audit_scoped(
            EventCategory.TOOL,
            "tool.executed",
            {
                "tool": tool,
                "succeeded": succeeded,
                "duration_ms": duration_ms,
                "mission_id": mission_id,
            },
            source=source,
            mission_id=mission_id,
        )

    @staticmethod
    def plugin_lifecycle(plugin: str, version: str, state: str, *, source: str = "plugin.manager") -> DomainEvent:
        """Record a plugin lifecycle transition."""
        return _audit(
            EventCategory.PLUGIN,
            f"plugin.{state}",
            {"plugin": plugin, "version": version, "state": state},
            source=source,
        )

    @staticmethod
    def database_change(
        operation: str, table: str, *, record_id: str | None = None, fields: list[str] | None = None, source: str = "db"
    ) -> DomainEvent:
        """Record a database change."""
        return _audit(
            EventCategory.DATABASE,
            "database.updated",
            {"operation": operation, "table": table, "record_id": record_id, "fields": fields or []},
            source=source,
        )
