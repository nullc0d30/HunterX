from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class MessageType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    BROADCAST = "broadcast"
    NOTIFICATION = "notification"
    CANCELLATION = "cancellation"
    TIMEOUT = "timeout"
    ERROR = "error"
    CUSTOM = "custom"


@dataclass
class AgentMessage:
    id: str
    type: MessageType
    sender: str
    recipient: str
    payload: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    ttl_seconds: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "sender": self.sender,
            "recipient": self.recipient,
            "payload": self.payload,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "metadata": self.metadata,
        }


MessageHandler = Callable[[AgentMessage], None]


class MessageBus:
    _instance: Optional[MessageBus] = None
    _lock: threading.RLock = threading.RLock()

    def __new__(cls) -> MessageBus:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._handlers: Dict[str, List[MessageHandler]] = {}
                    cls._instance._broadcast_handlers: List[MessageHandler] = []
                    cls._instance._history: List[AgentMessage] = []
                    cls._instance._max_history = 500
        return cls._instance

    def register(self, agent_id: str, handler: MessageHandler) -> None:
        if agent_id not in self._handlers:
            self._handlers[agent_id] = []
        self._handlers[agent_id].append(handler)

    def unregister(self, agent_id: str) -> None:
        self._handlers.pop(agent_id, None)

    def subscribe_broadcast(self, handler: MessageHandler) -> None:
        self._broadcast_handlers.append(handler)

    def send(self, message: AgentMessage) -> None:
        self._history.append(message)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        handlers = self._handlers.get(message.recipient, [])
        for handler in handlers:
            try:
                handler(message)
            except Exception:
                import traceback
                traceback.print_exc()

    def broadcast(self, message: AgentMessage) -> None:
        message.type = MessageType.BROADCAST
        self._history.append(message)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        for handler in self._broadcast_handlers:
            try:
                handler(message)
            except Exception:
                import traceback
                traceback.print_exc()

    def send_message(
        self,
        sender: str,
        recipient: str,
        payload: Dict[str, Any],
        message_type: MessageType = MessageType.REQUEST,
        correlation_id: Optional[str] = None,
    ) -> AgentMessage:
        msg = AgentMessage(
            id=str(uuid.uuid4()),
            type=message_type,
            sender=sender,
            recipient=recipient,
            payload=payload,
            correlation_id=correlation_id,
        )
        self.send(msg)
        return msg

    def get_history(self, limit: int = 50) -> List[AgentMessage]:
        return self._history[-limit:]
