# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent registry."""

from __future__ import annotations

from threading import RLock

from hunterx.agents.base import SecurityAgent
from hunterx.domain.exceptions import DuplicateRegistrationError, PluginNotFoundError


class AgentRegistry:
    """Thread-safe registry of available agents."""

    def __init__(self) -> None:
        self._agents: dict[str, SecurityAgent] = {}
        self._lock = RLock()

    def register(self, agent: SecurityAgent) -> None:
        """Register an agent instance by its name."""
        with self._lock:
            if agent.name in self._agents:
                raise DuplicateRegistrationError(agent.name)
            self._agents[agent.name] = agent

    def unregister(self, name: str) -> None:
        """Remove an agent by name."""
        with self._lock:
            self._agents.pop(name, None)

    def get(self, name: str) -> SecurityAgent:
        """Return an agent by name or raise :class:`PluginNotFoundError`."""
        with self._lock:
            agent = self._agents.get(name)
        if agent is None:
            raise PluginNotFoundError(name)
        return agent

    def list(self) -> list[SecurityAgent]:
        """Return all registered agents."""
        with self._lock:
            return list(self._agents.values())
