# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent state."""

from __future__ import annotations

from enum import Enum


class AgentState(Enum):
    """Lifecycle states of an agent."""

    IDLE = "idle"
    ACTIVE = "active"
    BLOCKED = "blocked"
    STOPPED = "stopped"
