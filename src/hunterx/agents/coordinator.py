# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent coordinator.

Runs a multi-phase agent pipeline (recon → scan → analyze) for a mission by
dispatching to agents at each phase and merging their results. This is the
mission-level counterpart to the lower-level :class:`AgentOrchestrator`.
"""

from __future__ import annotations

from collections.abc import Iterable

from hunterx.agents.context import AgentContext
from hunterx.agents.messaging import AgentMessage
from hunterx.agents.orchestrator import AgentOrchestrator
from hunterx.shared.result import Failure, Result, Success

#: Default phase pipeline: ordered capability groups.
_PIPELINE: tuple[tuple[str, ...], ...] = (
    ("recon.enumerate", "recon.fingerprint"),
    ("scan.vulnerabilities",),
    ("analyze.correlate", "analyze.prioritize"),
)


class AgentCoordinator:
    """Coordinate a phased agent run over a mission.

    Each phase dispatches work to the named agents; if a phase has no agent
    registered, it is skipped without failing the mission.
    """

    def __init__(self, orchestrator: AgentOrchestrator, *, pipeline: tuple[tuple[str, ...], ...] = _PIPELINE) -> None:
        self._orchestrator = orchestrator
        self._pipeline = pipeline

    def run_mission(self, mission_id: str, *, targets: Iterable[str]) -> Result[list[AgentMessage], Exception]:
        """Execute the pipeline across every target and merge the results."""
        all_messages: list[AgentMessage] = []
        for phase in self._pipeline:
            for target in targets:
                for agent_name in phase:
                    context = AgentContext(mission_id=mission_id, target=target)
                    outcome = self._orchestrator.dispatch(agent_name=agent_name, context=context)
                    if isinstance(outcome, Failure):
                        return outcome
                    all_messages.extend(outcome.value)
        return Success(all_messages)

    @staticmethod
    def collect_findings(messages: Iterable[AgentMessage]) -> list[dict[str, object]]:
        """Extract ``finding``-kind payloads from merged agent messages."""
        return [message.payload for message in messages if message.kind == "finding"]
