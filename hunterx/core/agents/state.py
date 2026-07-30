from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentState(str, Enum):
    CREATED = "created"
    INITIALIZING = "initializing"
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    SHUTTING_DOWN = "shutting_down"
    SHUTDOWN = "shutdown"
    PAUSED = "paused"
    RECOVERING = "recovering"


class WorkflowState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"


class TaskState(str, Enum):
    PENDING = "pending"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class StateSnapshot:
    agent_id: str
    state: AgentState
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class StateManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._states: Dict[str, AgentState] = {}
        self._snapshots: Dict[str, List[StateSnapshot]] = {}
        self._checkpoints: Dict[str, Dict[str, Any]] = {}

    def set_state(self, agent_id: str, state: AgentState) -> None:
        with self._lock:
            old = self._states.get(agent_id)
            self._states[agent_id] = state
            snapshot = StateSnapshot(agent_id=agent_id, state=state, data={"old_state": old.value if old else None})
            if agent_id not in self._snapshots:
                self._snapshots[agent_id] = []
            self._snapshots[agent_id].append(snapshot)

    def get_state(self, agent_id: str) -> Optional[AgentState]:
        with self._lock:
            return self._states.get(agent_id)

    def get_history(self, agent_id: str, limit: int = 20) -> List[StateSnapshot]:
        with self._lock:
            snapshots = self._snapshots.get(agent_id, [])
            return snapshots[-limit:]

    def save_checkpoint(self, agent_id: str, data: Dict[str, Any]) -> str:
        checkpoint_id = f"{agent_id}-{datetime.utcnow().timestamp()}"
        with self._lock:
            self._checkpoints[checkpoint_id] = {
                "agent_id": agent_id,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }
        return checkpoint_id

    def load_checkpoint(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cp = self._checkpoints.get(checkpoint_id)
            return cp.get("data") if cp else None

    def get_all_states(self) -> Dict[str, str]:
        with self._lock:
            return {k: v.value for k, v in self._states.items()}

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "states": {k: v.value for k, v in self._states.items()},
                "checkpoints": list(self._checkpoints.keys()),
            }
