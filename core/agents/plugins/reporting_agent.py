from typing import Any, Dict, List

from ...reasoning.formatter import ReasoningResult
from ...reasoning.goals import Goal, GoalPriority, GoalType
from ..base import SecurityAgent
from ..capabilities import AgentCapability


class ReportingAgent(SecurityAgent):
    def __init__(self, agent_id: str = ""):
        super().__init__(agent_id=agent_id, name="ReportingAgent", version="1.0.0")
        self._capabilities = [AgentCapability.REPORTING, AgentCapability.SUMMARIZATION, AgentCapability.MITIGATION]

    def _on_execute(self, goal: Goal) -> ReasoningResult:
        return self._reason(goal)

    def _on_create_goals(self, objective: str, context: Dict[str, Any]) -> List[Goal]:
        return [
            Goal.create(
                goal_type=GoalType.REPORTING,
                objective=f"Reporting: {objective}",
                context=context,
                priority=GoalPriority.MEDIUM,
                source_agent=self._name,
            ),
        ]

    def _on_report(self) -> Dict[str, Any]:
        return {
            "agent": self._name,
            "type": "reporting",
            "findings_summary": "Reporting ready",
        }

    def _on_priority(self) -> int:
        return 8
