from __future__ import annotations

import threading
from typing import List, Optional

from ..reasoning.consensus import ConsensusEngine
from ..reasoning.engine import ReasoningOrchestrator
from ..reasoning.formatter import ReasoningResult
from ..reasoning.goals import Goal, GoalPriority, GoalStatus
from ..utils import logger

from .base import SecurityAgent
from .capabilities import AgentCapability
from .context import AgentContext
from .events import EventBus
from .messaging import MessageBus
from .registry import AgentRegistry


class AgentCoordinator:
    def __init__(
        self,
        registry: Optional[AgentRegistry] = None,
        reasoning: Optional[ReasoningOrchestrator] = None,
        event_bus: Optional[EventBus] = None,
        message_bus: Optional[MessageBus] = None,
    ):
        self._registry = registry or AgentRegistry()
        self._reasoning = reasoning
        self._event_bus = event_bus or EventBus()
        self._message_bus = message_bus or MessageBus()
        self._consensus = ConsensusEngine()
        self._lock = threading.RLock()
        self._coordination_id: Optional[str] = None

    def coordinate_goals(
        self,
        goals: List[Goal],
        context: Optional[AgentContext] = None,
    ) -> List[ReasoningResult]:
        results: List[ReasoningResult] = []
        for goal in goals:
            result = self._route_goal(goal, context)
            results.append(result)
        return results

    def _route_goal(self, goal: Goal, context: Optional[AgentContext] = None) -> ReasoningResult:
        agents = self._find_capable_agents(goal)
        if not agents:
            logger.warning(f"No capable agents for goal: {goal.type.value}")
            goal.status = GoalStatus.FAILED
            return ReasoningResult(
                goal_id=goal.id, goal_type=goal.type.value, objective=goal.objective,
                response="No capable agents available", confidence=0.0,
                confidence_level="insufficient_data", provider="", model="",
                latency_ms=0, cost=0, validation_errors=["No capable agents"],
            )

        if len(agents) == 1:
            return agents[0].execute(goal)

        if goal.priority == GoalPriority.CRITICAL:
            responses = []
            for agent in agents:
                try:
                    responses.append(agent.execute(goal))
                except Exception as e:
                    logger.error(f"Agent {agent.name} failed: {e}")

            if responses:
                individual_responses = [
                    self._consensus.IndividualResponse(
                        provider=r.provider or agent.name,
                        model=r.model or "",
                        content=r.response,
                        confidence=r.confidence,
                        latency_ms=r.latency_ms,
                    )
                    for r, agent in zip(responses, agents[:len(responses)])
                ]
                consensus = self._consensus.reach_consensus(individual_responses)
                return ReasoningResult(
                    goal_id=goal.id, goal_type=goal.type.value, objective=goal.objective,
                    response=consensus.final_response, confidence=consensus.agreement,
                    confidence_level=consensus.agreement_level.value,
                    provider=", ".join(r.provider for r in individual_responses),
                    model=individual_responses[0].model if individual_responses else "",
                    latency_ms=sum(r.latency_ms for r in individual_responses),
                    cost=0, consensus=consensus,
                )

        return agents[0].execute(goal)

    def _find_capable_agents(self, goal: Goal) -> List[SecurityAgent]:
        goal_type_str = goal.type.value
        for capability in AgentCapability:
            if capability.value == goal_type_str:
                return self._registry.find_by_capability(capability)
        return []
