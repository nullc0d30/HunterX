from typing import Any, Dict, List

from ...reasoning.formatter import ReasoningResult
from ...reasoning.goals import Goal, GoalPriority, GoalType
from ..base import SecurityAgent
from ..capabilities import AgentCapability


class PurpleTeamAgent(SecurityAgent):
    def __init__(self, agent_id: str = ""):
        super().__init__(agent_id=agent_id, name="PurpleTeamAgent", version="1.0.0")
        self._capabilities = [AgentCapability.PURPLE_TEAM]

    def _on_execute(self, goal: Goal) -> ReasoningResult:
        return self._reason(goal)

    def _on_create_goals(self, objective: str, context: Dict[str, Any]) -> List[Goal]:
        return [
            Goal.create(
                goal_type=GoalType.PURPLE_TEAM,
                objective=f"Purple team analysis: {objective}",
                context=context,
                priority=GoalPriority.MEDIUM,
                source_agent=self._name,
            ),
        ]

    def _on_priority(self) -> int:
        return 7
