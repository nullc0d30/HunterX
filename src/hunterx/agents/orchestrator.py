# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent orchestrator.

Routes messages to the right agents and sequences multi-agent runs. The
orchestrator is dependency-injection friendly: agents are supplied by a
registry, and routing policy is pluggable.
"""

from __future__ import annotations

from hunterx.agents.base import AgentCapability, SecurityAgent
from hunterx.agents.context import AgentContext
from hunterx.agents.messaging import AgentMessage
from hunterx.agents.registry import AgentRegistry
from hunterx.domain.exceptions import OperationError, PluginNotFoundError
from hunterx.shared.result import Failure, Result, Success


class AgentOrchestrator:
    """Dispatch work to capable agents and fan their results back."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def dispatch(
        self,
        *,
        capability: AgentCapability | None = None,
        agent_name: str | None = None,
        context: AgentContext,
    ) -> Result[list[AgentMessage], Exception]:
        """Run the agent(s) matching ``capability`` or ``agent_name``.

        Only one of ``capability`` / ``agent_name`` may be given. Returns the
        collected messages produced by the executed agents.
        """
        if agent_name is not None and capability is not None:
            return Failure(OperationError("Specify either agent_name or capability, not both."))

        agents: list[SecurityAgent]
        if agent_name is not None:
            try:
                agents = [self._registry.get(agent_name)]
            except PluginNotFoundError as exc:
                return Failure(exc)
        elif capability is not None:
            agents = [agent for agent in self._registry.list() if agent.can(capability)]
        else:
            return Failure(OperationError("Specify agent_name or capability to dispatch."))

        messages: list[AgentMessage] = []
        for agent in agents:
            try:
                messages.extend(agent.run(context))
            except Exception as exc:
                return Failure(exc)
        return Success(messages)
