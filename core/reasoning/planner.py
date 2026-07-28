from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .goals import Goal, GoalPriority


@dataclass
class ReasoningPlan:
    id: str
    goals: List[Goal] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    total_goals: int = 0
    estimated_cost: float = 0.0
    estimated_duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_goal(self, goal: Goal) -> None:
        self.goals.append(goal)
        self.total_goals = len(self.goals)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "goals": [g.to_dict() for g in self.goals],
            "created_at": self.created_at.isoformat(),
            "total_goals": self.total_goals,
            "estimated_cost": self.estimated_cost,
            "estimated_duration_ms": self.estimated_duration_ms,
            "metadata": self.metadata,
        }


class ReasoningPlanner:
    def __init__(self) -> None:
        self._plans: Dict[str, ReasoningPlan] = {}

    def create_plan(self, goals: List[Goal]) -> ReasoningPlan:
        plan = ReasoningPlan(
            id=str(uuid.uuid4()),
            goals=sorted(goals, key=lambda g: self._priority_order(g.priority)),
        )
        plan.total_goals = len(plan.goals)
        plan.estimated_cost = sum(0.001 for _ in plan.goals)
        plan.estimated_duration_ms = sum(500 for _ in plan.goals)
        self._plans[plan.id] = plan
        return plan

    def get_plan(self, plan_id: str) -> Optional[ReasoningPlan]:
        return self._plans.get(plan_id)

    def prioritize_goals(self, goals: List[Goal]) -> List[Goal]:
        return sorted(goals, key=lambda g: self._priority_order(g.priority))

    def estimate_cost(self, goal: Goal) -> float:
        base_cost = 0.001
        if goal.max_cost > 0:
            return min(base_cost, goal.max_cost)
        return base_cost

    def estimate_duration(self, goal: Goal) -> float:
        base_duration = 500.0
        if goal.max_latency_ms > 0:
            return min(base_duration, goal.max_latency_ms)
        return base_duration

    def _priority_order(self, priority: GoalPriority) -> int:
        order = {
            GoalPriority.CRITICAL: 0,
            GoalPriority.HIGH: 1,
            GoalPriority.MEDIUM: 2,
            GoalPriority.LOW: 3,
            GoalPriority.INFO: 4,
        }
        return order.get(priority, 99)
