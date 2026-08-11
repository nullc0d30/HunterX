# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin event helpers."""

from __future__ import annotations

from typing import Any

from hunterx.domain.events import DomainEvent


def emit(event_type: str, payload: dict[str, Any], *, source: str = "plugin") -> DomainEvent:
    """Build a domain event carrying ``payload``.

    Plugins normally call :meth:`~hunterx.plugins.sdk.context.PluginContext.emit`
    instead; this helper is for direct, framework-free use in tests and tools.
    """
    return DomainEvent(event_type=event_type, payload=payload, source=source)
