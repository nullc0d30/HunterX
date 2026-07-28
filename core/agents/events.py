from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class EventType(str, Enum):
    TASK_STARTED = "task_started"
    TASK_FINISHED = "task_finished"
    TASK_FAILED = "task_failed"
    GOAL_CREATED = "goal_created"
    GOAL_COMPLETED = "goal_completed"
    REASONING_COMPLETED = "reasoning_completed"
    PAYLOAD_SELECTED = "payload_selected"
    FINDING_DETECTED = "finding_detected"
    RISK_UPDATED = "risk_updated"
    VERIFICATION_PASSED = "verification_passed"
    VERIFICATION_FAILED = "verification_failed"
    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_STEP_COMPLETED = "workflow_step_completed"
    WORKFLOW_COMPLETED = "workflow_completed"
    WORKFLOW_FAILED = "workflow_failed"
    AGENT_REGISTERED = "agent_registered"
    AGENT_UNREGISTERED = "agent_unregistered"
    AGENT_STATE_CHANGED = "agent_state_changed"
    AGENT_ERROR = "agent_error"
    AGENT_HEALTH_CHECK = "agent_health_check"
    CONSENSUS_REACHED = "consensus_reached"
    CONSENSUS_FAILED = "consensus_failed"
    EVIDENCE_SHARED = "evidence_shared"
    CUSTOM = "custom"


@dataclass
class Event:
    id: str
    type: EventType
    source: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "source": self.source,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "metadata": self.metadata,
        }


EventHandler = Callable[[Event], None]


class EventBus:
    _instance: Optional[EventBus] = None
    _lock: threading.RLock = threading.RLock()

    def __new__(cls) -> EventBus:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._subscribers: Dict[EventType, List[EventHandler]] = {}
                    cls._instance._history: List[Event] = []
                    cls._instance._max_history = 1000
                    cls._instance._wildcard_subscribers: List[EventHandler] = []
        return cls._instance

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        self._wildcard_subscribers.append(handler)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        if event_type in self._subscribers:
            self._subscribers[event_type] = [h for h in self._subscribers[event_type] if h != handler]

    def publish(self, event: Event) -> None:
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        for handler in self._wildcard_subscribers:
            try:
                handler(event)
            except Exception:
                import traceback
                traceback.print_exc()

        handlers = self._subscribers.get(event.type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                import traceback
                traceback.print_exc()

    def publish_event(
        self,
        event_type: EventType,
        source: str,
        data: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Event:
        event = Event(
            id=str(uuid.uuid4()),
            type=event_type,
            source=source,
            data=data or {},
            correlation_id=correlation_id,
        )
        self.publish(event)
        return event

    def get_history(self, event_type: Optional[EventType] = None, limit: int = 50) -> List[Event]:
        if event_type:
            filtered = [e for e in self._history if e.type == event_type]
        else:
            filtered = list(self._history)
        return filtered[-limit:]

    def clear_history(self) -> None:
        self._history.clear()
