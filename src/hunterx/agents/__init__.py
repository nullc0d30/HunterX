# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Multi-agent platform.

Provides the abstract :class:`~hunterx.agents.base.SecurityAgent` contract,
the agent registry, orchestrator and shared agent infrastructure. Concrete
agents (recon, scanner, analyst, reporter) are provided by plugins.
"""

from __future__ import annotations

from hunterx.agents.base import AgentCapability, SecurityAgent
from hunterx.agents.context import AgentContext
from hunterx.agents.memory import AgentMemory
from hunterx.agents.messaging import AgentMessage
from hunterx.agents.orchestrator import AgentOrchestrator
from hunterx.agents.registry import AgentRegistry
from hunterx.agents.state import AgentState

__all__ = [
    "SecurityAgent",
    "AgentCapability",
    "AgentRegistry",
    "AgentOrchestrator",
    "AgentContext",
    "AgentMemory",
    "AgentMessage",
    "AgentState",
]
