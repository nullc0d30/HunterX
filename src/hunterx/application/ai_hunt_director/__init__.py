# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director abstraction.

The AI Hunt Director is the primary decision-making authority for autonomous
security assessment missions. It receives the mission context, observations,
and available capabilities, and determines the next action to take.
"""

from __future__ import annotations

from hunterx.application.ai_hunt_director.director import AIHuntDirector
from hunterx.application.ai_hunt_director.protocol import (
    ActionType,
    AIHuntDecision,
    AIHuntDirectorProtocol,
    HuntContext,
    ToolCapability,
)

__all__ = [
    "ActionType",
    "AIHuntDecision",
    "AIHuntDirector",
    "AIHuntDirectorProtocol",
    "HuntContext",
    "ToolCapability",
]