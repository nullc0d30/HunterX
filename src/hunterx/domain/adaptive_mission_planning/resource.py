# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource- and time-aware planning.

The planner understands CPU, memory, network, concurrency, tool limits, target
rate limits and the mission budget. It avoids launching dozens of redundant
tools, supports deadlines, time budgets, priority windows, scheduled
reassessment and long-running tasks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.adaptive_mission_planning.enums import ActionStatus
from hunterx.domain.adaptive_mission_planning.graph import AdaptiveExecutionGraph
from hunterx.domain.adaptive_mission_planning.models import MissionConstraints


@dataclass(frozen=True, slots=True)
class ResourceState:
    """Current resource consumption of a mission."""

    running_actions: int = 0
    queued_actions: int = 0
    used_seconds: int = 0
    planned_seconds: int = 0
    concurrency: int = 0
    tool_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize the resource state to a JSON-safe mapping."""
        return {
            "running_actions": self.running_actions,
            "queued_actions": self.queued_actions,
            "used_seconds": self.used_seconds,
            "planned_seconds": self.planned_seconds,
            "concurrency": self.concurrency,
            "tool_counts": self.tool_counts,
        }


class ResourcePlanner:
    """Decide whether new actions may be scheduled under resource budgets."""

    def __init__(self, *, tool_limit_per_minute: int = 10) -> None:
        self.tool_limit_per_minute = tool_limit_per_minute

    def state(self, graph: AdaptiveExecutionGraph) -> ResourceState:
        """Compute the resource state of ``graph``."""
        running = graph.actions_in_status(ActionStatus.RUNNING)
        queued = [
            action
            for action in graph.actions.values()
            if action.status in (ActionStatus.APPROVED, ActionStatus.SCHEDULED)
        ]
        tool_counts: dict[str, int] = {}
        for action in graph.actions.values():
            tool = action.selected_tool or (action.tool_candidate_set[0] if action.tool_candidate_set else "")
            if tool:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
        return ResourceState(
            running_actions=len(running),
            queued_actions=len(queued),
            planned_seconds=sum(action.timeout_seconds for action in graph.actions.values()),
            concurrency=max(0, len(graph.parallel_groups())),
            tool_counts=tool_counts,
        )

    def can_schedule(
        self,
        state: ResourceState,
        constraints: MissionConstraints,
        *,
        action_seconds: int = 0,
    ) -> bool:
        """Return ``True`` when scheduling another action is within budget."""
        if constraints.max_concurrency and state.running_actions >= constraints.max_concurrency:
            return False
        if constraints.time_budget_seconds and state.used_seconds + action_seconds > constraints.time_budget_seconds:
            return False
        return not (
            constraints.execution_budget_seconds
            and state.planned_seconds > constraints.execution_budget_seconds
        )
class TimePlanner:
    """Time-aware planning: deadlines, budgets and pause/resume windows."""

    def __init__(self, *, elapsed_provider: object | None = None) -> None:
        self._elapsed = elapsed_provider

    def over_budget(self, used_seconds: int, constraints: MissionConstraints) -> bool:
        """Return ``True`` when the mission has exhausted its time budget."""
        return bool(constraints.time_budget_seconds and used_seconds >= constraints.time_budget_seconds)

    def remaining_seconds(self, used_seconds: int, constraints: MissionConstraints) -> int:
        """Return the remaining time budget (``0`` when unbounded)."""
        if not constraints.time_budget_seconds:
            return 0
        return max(0, constraints.time_budget_seconds - used_seconds)
