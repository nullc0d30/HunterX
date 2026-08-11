# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent abstraction.

An agent is a specialized worker that performs a bounded set of security
operations. Agents declare their capabilities, run within an orchestrated
lifecycle, and communicate exclusively through :class:`AgentMessage`.
"""

from __future__ import annotations

import abc
from enum import Enum

from hunterx.agents.context import AgentContext
from hunterx.agents.memory import AgentMemory
from hunterx.agents.messaging import AgentMessage
from hunterx.agents.state import AgentState


class AgentCapability(Enum):
    """Capabilities an agent can declare."""

    RECON = "recon"
    SCAN = "scan"
    DETECT = "detect"
    ANALYZE = "analyze"
    CORRELATE = "correlate"
    REPORT = "report"
    ENRICH = "enrich"


class SecurityAgent(abc.ABC):
    """Base class for all agents.

    Subclasses implement :meth:`run`, which receives the agent context and
    returns a list of messages to hand off to the orchestrator.
    """

    #: Unique agent name (e.g. ``"recon.agent"``).
    name: str = ""
    #: Human-readable description.
    description: str = ""
    #: Capabilities this agent provides.
    capabilities: tuple[AgentCapability, ...] = ()

    def __init__(self, memory: AgentMemory | None = None) -> None:
        self._memory = memory or AgentMemory()
        self._state = AgentState.IDLE

    @property
    def memory(self) -> AgentMemory:
        """Return this agent's working memory."""
        return self._memory

    @abc.abstractmethod
    def run(self, context: AgentContext) -> list[AgentMessage]:
        """Execute the agent's work and return hand-off messages."""

    def can(self, capability: AgentCapability) -> bool:
        """Return ``True`` if the agent declares ``capability``."""
        return capability in self.capabilities

    @property
    def state(self) -> AgentState:
        """Return the agent's current lifecycle state."""
        return self._state

    def _transition(self, state: AgentState) -> None:
        self._state = state
