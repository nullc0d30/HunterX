from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..reasoning.goals import Goal, GoalPriority, GoalType
from ...utils.utils import logger

from .capabilities import AgentCapability
from .registry import AgentRegistry
from .task import AgentTask, TaskPriority


@dataclass
class AgentPlan:
    id: str
    tasks: List[AgentTask] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    total_tasks: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_task(self, task: AgentTask) -> None:
        self.tasks.append(task)
        self.total_tasks = len(self.tasks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tasks": [t.to_dict() for t in self.tasks],
            "created_at": self.created_at.isoformat(),
            "total_tasks": self.total_tasks,
            "metadata": self.metadata,
        }


class AgentPlanner:
    def __init__(self, registry: Optional[AgentRegistry] = None):
        self._registry = registry or AgentRegistry()
        self._plans: Dict[str, AgentPlan] = {}

    def create_plan(self, goals: List[Goal]) -> AgentPlan:
        plan = AgentPlan(id=str(uuid.uuid4()))
        for goal in goals:
            agent = self._select_agent(goal)
            if agent:
                task = AgentTask.create(
                    agent_id=agent.agent_id,
                    goal=goal,
                    priority=self._map_priority(goal.priority),
                )
                plan.add_task(task)
                logger.info(f"AgentPlanner: assigned goal {goal.type.value} to {agent.name}")
            else:
                logger.warning(f"AgentPlanner: no agent available for goal {goal.type.value}")
        return plan

    def create_goal(
        self,
        goal_type: GoalType,
        objective: str,
        context: Optional[Dict[str, Any]] = None,
        priority: GoalPriority = GoalPriority.MEDIUM,
        source_agent: str = "",
    ) -> Goal:
        return Goal.create(
            goal_type=goal_type,
            objective=objective,
            context=context,
            priority=priority,
            source_agent=source_agent,
        )

    def _select_agent(self, goal: Goal) -> Any:
        goal_type_str = goal.type.value
        for capability in AgentCapability:
            if capability.value == goal_type_str:
                agents = self._registry.find_by_capability(capability)
                if agents:
                    return agents[0]
        return None

    def _map_priority(self, priority: GoalPriority) -> TaskPriority:
        mapping = {
            GoalPriority.CRITICAL: TaskPriority.CRITICAL,
            GoalPriority.HIGH: TaskPriority.HIGH,
            GoalPriority.MEDIUM: TaskPriority.MEDIUM,
            GoalPriority.LOW: TaskPriority.LOW,
            GoalPriority.INFO: TaskPriority.INFO,
        }
        return mapping.get(priority, TaskPriority.MEDIUM)

    def get_plan(self, plan_id: str) -> Optional[AgentPlan]:
        return self._plans.get(plan_id)
