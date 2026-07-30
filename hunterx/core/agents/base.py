from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..reasoning.engine import ReasoningOrchestrator
from ..reasoning.formatter import ReasoningResult
from ..reasoning.goals import Goal
from ...utils.utils import logger

from .capabilities import AgentCapability
from .context import AgentContext
from .state import AgentState


class SecurityAgent(ABC):
    def __init__(self, agent_id: str = "", name: str = "", version: str = "1.0.0"):
        self._id = agent_id or str(uuid.uuid4())
        self._name = name or self.__class__.__name__
        self._version = version
        self._state = AgentState.CREATED
        self._capabilities: List[AgentCapability] = []
        self._context: Optional[AgentContext] = None
        self._reasoning: Optional[ReasoningOrchestrator] = None
        self._metadata: Dict[str, Any] = {}
        self._created_at: datetime = datetime.utcnow()

    @property
    def agent_id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def capabilities(self) -> List[AgentCapability]:
        return self._capabilities

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._metadata

    def initialize(self, context: Optional[AgentContext] = None, reasoning: Optional[ReasoningOrchestrator] = None) -> None:
        self._context = context
        self._reasoning = reasoning
        self._state = AgentState.INITIALIZING
        self._on_initialize()
        self._state = AgentState.IDLE
        logger.info(f"Agent {self._name} ({self._id[:8]}) initialized")

    def shutdown(self) -> None:
        self._state = AgentState.SHUTTING_DOWN
        self._on_shutdown()
        self._state = AgentState.SHUTDOWN
        logger.info(f"Agent {self._name} ({self._id[:8]}) shutdown")

    def health(self) -> Dict[str, Any]:
        return {
            "agent_id": self._id,
            "name": self._name,
            "version": self._version,
            "state": self._state.value,
            "capabilities": [c.value for c in self._capabilities],
            "created_at": self._created_at.isoformat(),
            "metadata": self._metadata,
        }

    def accepts(self, goal: Goal) -> bool:
        return self._on_accept(goal)

    def execute(self, goal: Goal) -> ReasoningResult:
        self._state = AgentState.BUSY
        try:
            result = self._on_execute(goal)
            self._state = AgentState.IDLE
            return result
        except Exception as e:
            self._state = AgentState.ERROR
            logger.error(f"Agent {self._name} execution failed: {e}")
            raise

    def observe(self, event: Any) -> None:
        self._on_observe(event)

    def create_goals(self, objective: str, context: Optional[Dict[str, Any]] = None) -> List[Goal]:
        return self._on_create_goals(objective, context or {})

    def consume_reasoning(self, result: ReasoningResult) -> None:
        self._on_consume_reasoning(result)

    def verify(self, result: ReasoningResult) -> bool:
        return self._on_verify(result)

    def report(self) -> Dict[str, Any]:
        return self._on_report()

    def learn(self, result: ReasoningResult) -> None:
        self._on_learn(result)

    def estimate_cost(self, goal: Goal) -> float:
        return self._on_estimate_cost(goal)

    def estimate_duration(self, goal: Goal) -> float:
        return self._on_estimate_duration(goal)

    def priority(self) -> int:
        return self._on_priority()

    def supports_parallel(self) -> bool:
        return self._on_supports_parallel()

    def supports_streaming(self) -> bool:
        return self._on_supports_streaming()

    def _on_initialize(self) -> None: ...

    def _on_shutdown(self) -> None: ...

    def _on_accept(self, goal: Goal) -> bool:
        goal_type_str = goal.type.value
        return any(goal_type_str in cap.value for cap in self._capabilities)

    @abstractmethod
    def _on_execute(self, goal: Goal) -> ReasoningResult: ...

    def _on_observe(self, event: Any) -> None: ...

    def _on_create_goals(self, objective: str, context: Dict[str, Any]) -> List[Goal]:
        return []

    def _on_consume_reasoning(self, result: ReasoningResult) -> None: ...

    def _on_verify(self, result: ReasoningResult) -> bool:
        return result.confidence >= 0.5

    def _on_report(self) -> Dict[str, Any]:
        return self.health()

    def _on_learn(self, result: ReasoningResult) -> None: ...

    def _on_estimate_cost(self, goal: Goal) -> float:
        return 0.001

    def _on_estimate_duration(self, goal: Goal) -> float:
        return 1000.0

    def _on_priority(self) -> int:
        return 5

    def _on_supports_parallel(self) -> bool:
        return False

    def _on_supports_streaming(self) -> bool:
        return False

    def _reason(self, goal: Goal) -> ReasoningResult:
        if not self._reasoning:
            raise RuntimeError("Reasoning engine not set")
        return self._reasoning.reason(goal)

    def to_dict(self) -> Dict[str, Any]:
        return self.health()
