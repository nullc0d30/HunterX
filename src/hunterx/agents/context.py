# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AgentContext:
    """The execution context handed to an agent for a single run.

    Attributes:
        mission_id: owning mission.
        target: target identifier the agent should operate on.
        parameters: agent-specific run parameters.
        workspace: scratch data shared across agents in a run.

    """

    mission_id: str
    target: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    workspace: dict[str, Any] = field(default_factory=dict)
