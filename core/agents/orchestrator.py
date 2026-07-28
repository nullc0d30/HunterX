from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from ..reasoning.engine import ReasoningOrchestrator
from ..reasoning.formatter import ReasoningResult
from ..reasoning.goals import Goal, GoalPriority
from ..utils import logger

from .base import SecurityAgent
from .context import AgentContext
from .coordinator import AgentCoordinator
from .events import EventBus, EventType
from .memory import AgentMemory
from .messaging import MessageBus
from .planner import AgentPlanner
from .registry import AgentRegistry
from .scheduler import AgentScheduler
from .state import StateManager, WorkflowState
from .task import AgentTask
from .workflow import Workflow, WorkflowEngine, WorkflowStep


class AgentOrchestrator:
    def __init__(
        self,
        registry: Optional[AgentRegistry] = None,
        reasoning: Optional[ReasoningOrchestrator] = None,
        scheduler: Optional[AgentScheduler] = None,
        coordinator: Optional[AgentCoordinator] = None,
        planner: Optional[AgentPlanner] = None,
        workflow_engine: Optional[WorkflowEngine] = None,
        event_bus: Optional[EventBus] = None,
        message_bus: Optional[MessageBus] = None,
        state_manager: Optional[StateManager] = None,
        agent_memory: Optional[AgentMemory] = None,
    ):
        self._registry = registry or AgentRegistry()
        self._reasoning = reasoning
        self._scheduler = scheduler or AgentScheduler(registry, state_manager, event_bus)
        self._coordinator = coordinator or AgentCoordinator(registry, reasoning, event_bus, message_bus)
        self._planner = planner or AgentPlanner(registry)
        self._workflow_engine = workflow_engine or WorkflowEngine(event_bus, state_manager)
        self._event_bus = event_bus or EventBus()
        self._message_bus = message_bus or MessageBus()
        self._state_manager = state_manager or StateManager()
        self._agent_memory = agent_memory or AgentMemory()
        self._context: Optional[AgentContext] = None
        self._results: Dict[str, ReasoningResult] = {}

    @property
    def registry(self) -> AgentRegistry:
        return self._registry

    @property
    def context(self) -> Optional[AgentContext]:
        return self._context

    def initialize(self, context: Optional[AgentContext] = None) -> None:
        self._context = context
        for agent_entry in self._registry.list_agents():
            agent_id = agent_entry.get("agent_id", "")
            agent = self._registry.get(agent_id)
            if agent and self._reasoning:
                agent.initialize(context=self._context, reasoning=self._reasoning)
        logger.info(f"Orchestrator: initialized with {self._registry.count()} agents")

    def register_agent(self, agent: SecurityAgent) -> None:
        self._registry.register(agent)
        if self._context and self._reasoning:
            agent.initialize(context=self._context, reasoning=self._reasoning)

    def create_goal(
        self,
        objective: str,
        context: Optional[Dict[str, Any]] = None,
        priority: GoalPriority = GoalPriority.MEDIUM,
    ) -> Goal:
        return Goal.create(
            goal_type=context.get("goal_type", "custom") if context else "custom",
            objective=objective,
            context=context or {},
            priority=priority,
            source_agent="orchestrator",
        )

    def submit_goal(self, goal: Goal) -> ReasoningResult:
        result = self._coordinator.coordinate_goals([goal], self._context)
        if result:
            self._results[goal.id] = result[0]
            self._event_bus.publish_event(
                EventType.REASONING_COMPLETED, "orchestrator",
                {"goal_id": goal.id, "goal_type": goal.type.value},
            )
            return result[0]
        raise RuntimeError(f"Failed to process goal {goal.id}")

    def submit_goals(self, goals: List[Goal]) -> List[ReasoningResult]:
        results = []
        for goal in goals:
            result = self.submit_goal(goal)
            results.append(result)
        return results

    def submit_task(self, task: AgentTask) -> None:
        self._scheduler.schedule(task)

    def submit_tasks(self, tasks: List[AgentTask]) -> None:
        self._scheduler.schedule_batch(tasks)

    def start_scheduler(self, max_concurrent: int = 5) -> None:
        self._scheduler.start(max_concurrent)

    def stop_scheduler(self) -> None:
        self._scheduler.stop()

    def create_workflow(self, name: str, steps: List[WorkflowStep]) -> Workflow:
        workflow = Workflow(
            id=str(uuid.uuid4()),
            name=name,
            steps=steps,
        )
        self._workflow_engine.register(workflow)
        return workflow

    def run_workflow(self, workflow_id: str) -> WorkflowState:
        return self._workflow_engine.run(workflow_id)

    def run_workflow_sync(self, workflow_id: str) -> WorkflowState:
        return self._workflow_engine.run(workflow_id)

    def get_workflow(self, workflow_id: str):
        return self._workflow_engine.get(workflow_id)

    def list_workflows(self):
        return self._workflow_engine.list_workflows()

    def get_results(self) -> Dict[str, ReasoningResult]:
        return dict(self._results)

    def get_result(self, goal_id: str):
        return self._results.get(goal_id)

    def get_agent_memory(self) -> AgentMemory:
        return self._agent_memory

    def health(self) -> Dict[str, Any]:
        return {
            "orchestrator": "running",
            "agents": self._registry.count(),
            "agents_healthy": len(self._registry.list_healthy()),
            "scheduler_running": self._scheduler.running,
            "scheduler_queue_size": len(self._scheduler.get_queue()),
            "workflows": len(self._workflow_engine.list_workflows()),
            "results_cached": len(self._results),
        }

    def shutdown(self) -> None:
        self._scheduler.stop()
        self._registry.shutdown_all()
        logger.info("Orchestrator: shutdown complete")
