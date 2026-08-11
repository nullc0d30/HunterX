# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Event enums.

Shared enums that give every event its category, severity, priority and
payload-version stamp. These are pure values: they carry no behavior and are
safe to import from any layer.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class EventCategory(StrEnum):
    """Subsystem a given event belongs to.

    Categories are the routing prefix of every event type (e.g. ``mission.*``).
    """

    MISSION = "mission"
    EXECUTION = "execution"
    TOOL = "tool"
    RECON = "recon"
    DNS = "dns"
    HOST = "host"
    TOPOLOGY = "topology"
    TECHNOLOGY = "technology"
    WEB = "web"
    JAVASCRIPT = "javascript"
    API = "api"
    AUTH = "auth"
    AUTHORIZATION = "authorization"
    CLOUD = "cloud"
    VULNERABILITY = "vulnerability"
    PLUGIN = "plugin"
    DATABASE = "database"
    KNOWLEDGE = "knowledge"
    AI = "ai"
    WORKFLOW = "workflow"
    SECURITY = "security"
    REPORTING = "reporting"
    SYSTEM = "system"
    CONFIGURATION = "configuration"
    USER = "user"
    TARGET = "target"
    CAMPAIGN = "campaign"


class EventSeverity(StrEnum):
    """Operational severity of an event."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventPriority(IntEnum):
    """Delivery priority of an event.

    Higher-priority subscribers are invoked before lower-priority ones when an
    event matches multiple handlers.
    """

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class EventStatus(StrEnum):
    """Delivery state of a persisted event."""

    RECEIVED = "received"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD = "dead"
