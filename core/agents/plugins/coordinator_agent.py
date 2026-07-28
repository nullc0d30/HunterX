from typing import Any, Dict, List

from ...reasoning.consensus import ConsensusEngine
from ...reasoning.formatter import ReasoningResult
from ...reasoning.goals import Goal, GoalPriority, GoalType
from ..base import SecurityAgent
from ..capabilities import AgentCapability


class CoordinatorAgent(SecurityAgent):
    def __init__(self, agent_id: str = ""):
        super().__init__(agent_id=agent_id, name="CoordinatorAgent", version="1.0.0")
        self._capabilities = [AgentCapability.COORDINATION]
        self._consensus = ConsensusEngine()

    def _on_execute(self, goal: Goal) -> ReasoningResult:
        return self._reason(goal)

    def _on_create_goals(self, objective: str, context: Dict[str, Any]) -> List[Goal]:
        return [
            Goal.create(
                goal_type=GoalType.CUSTOM,
                objective=f"Coordination: {objective}",
                context=context,
                priority=GoalPriority.HIGH,
                source_agent=self._name,
            ),
        ]

    def _on_priority(self) -> int:
        return 0

    def _on_supports_parallel(self) -> bool:
        return True
