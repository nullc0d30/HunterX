from typing import Any, Dict, List

from ...reasoning.formatter import ReasoningResult
from ...reasoning.goals import Goal, GoalPriority, GoalType
from ..base import SecurityAgent
from ..capabilities import AgentCapability


class VerificationAgent(SecurityAgent):
    def __init__(self, agent_id: str = ""):
        super().__init__(agent_id=agent_id, name="VerificationAgent", version="1.0.0")
        self._capabilities = [AgentCapability.VERIFICATION]

    def _on_execute(self, goal: Goal) -> ReasoningResult:
        return self._reason(goal)

    def _on_create_goals(self, objective: str, context: Dict[str, Any]) -> List[Goal]:
        return [
            Goal.create(
                goal_type=GoalType.VERIFICATION,
                objective=f"Verification: {objective}",
                context=context,
                priority=GoalPriority.HIGH,
                source_agent=self._name,
            ),
        ]

    def _on_verify(self, result: ReasoningResult) -> bool:
        return result.confidence >= 0.6 and len(result.validation_errors) == 0

    def _on_priority(self) -> int:
        return 6
