from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from ..utils import logger

from .events import EventBus, EventType
from .state import StateManager, WorkflowState
from .task import AgentTask


class WorkflowStepType(str, Enum):
    TASK = "task"
    CONDITION = "condition"
    PARALLEL = "parallel"
    LOOP = "loop"
    SUB_WORKFLOW = "sub_workflow"
    WAIT = "wait"


@dataclass
class WorkflowStep:
    id: str
    type: WorkflowStepType
    name: str
    task: Optional[AgentTask] = None
    condition: Optional[Callable[[], bool]] = None
    substeps: List[WorkflowStep] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    max_iterations: int = 1
    wait_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "depends_on": self.depends_on,
            "max_iterations": self.max_iterations,
            "wait_seconds": self.wait_seconds,
            "metadata": self.metadata,
        }


@dataclass
class Workflow:
    id: str
    name: str
    steps: List[WorkflowStep] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    state: WorkflowState = WorkflowState.PENDING
    checkpoint_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_step(self, step: WorkflowStep) -> None:
        self.steps.append(step)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at.isoformat(),
            "state": self.state.value,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class WorkflowEngine:
    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        state_manager: Optional[StateManager] = None,
    ):
        self._event_bus = event_bus or EventBus()
        self._state_manager = state_manager or StateManager()
        self._lock = threading.RLock()
        self._workflows: Dict[str, Workflow] = {}
        self._step_results: Dict[str, Any] = {}
        self._running: bool = False

    def register(self, workflow: Workflow) -> str:
        with self._lock:
            self._workflows[workflow.id] = workflow
        return workflow.id

    def get(self, workflow_id: str) -> Optional[Workflow]:
        with self._lock:
            return self._workflows.get(workflow_id)

    def run(self, workflow_id: str) -> WorkflowState:
        workflow = self.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_id}")

        workflow.state = WorkflowState.RUNNING
        self._event_bus.publish_event(EventType.WORKFLOW_STARTED, "workflow_engine", {"workflow_id": workflow_id})

        try:
            completed: Set[str] = set()
            max_iterations = 100
            iteration = 0

            while len(completed) < len(workflow.steps) and iteration < max_iterations:
                iteration += 1
                for step in workflow.steps:
                    if step.id in completed:
                        continue
                    if not self._dependencies_met(step, completed):
                        continue
                    self._execute_step(step, workflow)
                    completed.add(step.id)
                    self._event_bus.publish_event(
                        EventType.WORKFLOW_STEP_COMPLETED, "workflow_engine",
                        {"workflow_id": workflow_id, "step_id": step.id, "step_name": step.name},
                    )

            if len(completed) == len(workflow.steps):
                workflow.state = WorkflowState.COMPLETED
                self._event_bus.publish_event(EventType.WORKFLOW_COMPLETED, "workflow_engine", {"workflow_id": workflow_id})
            else:
                workflow.state = WorkflowState.FAILED
                self._event_bus.publish_event(EventType.WORKFLOW_FAILED, "workflow_engine", {"workflow_id": workflow_id})

        except Exception as e:
            workflow.state = WorkflowState.FAILED
            logger.error(f"Workflow {workflow_id} failed: {e}")
            self._event_bus.publish_event(EventType.WORKFLOW_FAILED, "workflow_engine", {"workflow_id": workflow_id, "error": str(e)})

        return workflow.state

    def resume(self, workflow_id: str) -> WorkflowState:
        return self.run(workflow_id)

    def cancel(self, workflow_id: str) -> bool:
        workflow = self.get(workflow_id)
        if workflow:
            workflow.state = WorkflowState.CANCELLED
            return True
        return False

    def list_workflows(self) -> List[Workflow]:
        with self._lock:
            return list(self._workflows.values())

    def _execute_step(self, step: WorkflowStep, workflow: Workflow) -> None:
        if step.type == WorkflowStepType.TASK:
            self._step_results[step.id] = {"status": "completed", "step_id": step.id}
        elif step.type == WorkflowStepType.WAIT:
            import time
            time.sleep(step.wait_seconds)
            self._step_results[step.id] = {"status": "completed", "waited": step.wait_seconds}
        elif step.type == WorkflowStepType.CONDITION:
            result = step.condition() if step.condition else True
            self._step_results[step.id] = {"status": "completed", "condition_result": result}

    def _dependencies_met(self, step: WorkflowStep, completed: Set[str]) -> bool:
        if not step.depends_on:
            return True
        return all(dep in completed for dep in step.depends_on)
