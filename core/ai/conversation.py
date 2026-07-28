from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import Message, MessageRole


@dataclass
class Conversation:
    id: str
    system_prompt: str = ""
    messages: List[Message] = field(default_factory=list)
    summary: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    token_count: int = 0
    max_tokens: int = 16384
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_message(self, message: Message) -> None:
        self.messages.append(message)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "system_prompt": self.system_prompt,
            "message_count": len(self.messages),
            "summary": self.summary,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "token_count": self.token_count,
            "max_tokens": self.max_tokens,
        }


class ConversationManager:
    def __init__(self, max_history: int = 100, max_token_limit: int = 16384):
        self._conversations: Dict[str, Conversation] = {}
        self._lock = threading.RLock()
        self._max_history = max_history
        self._max_token_limit = max_token_limit

    def create(
        self,
        system_prompt: str = "",
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Conversation:
        conv_id = conversation_id or str(uuid.uuid4())
        conv = Conversation(
            id=conv_id,
            system_prompt=system_prompt,
            max_tokens=self._max_token_limit,
            metadata=metadata or {},
        )
        if system_prompt:
            conv.add_message(Message.system(system_prompt))
        with self._lock:
            self._conversations[conv_id] = conv
        return conv

    def get_conversation(self, conversation_id: str) -> Optional[Conversation]:
        with self._lock:
            return self._conversations.get(conversation_id)

    def add_user_message(self, conversation_id: str, content: str) -> Optional[Message]:
        conv = self.get_conversation(conversation_id)
        if not conv:
            return None
        msg = Message.user(content)
        conv.add_message(msg)
        self._enforce_limits(conv)
        return msg

    def add_assistant_message(self, conversation_id: str, content: str) -> Optional[Message]:
        conv = self.get_conversation(conversation_id)
        if not conv:
            return None
        msg = Message.assistant(content)
        conv.add_message(msg)
        return msg

    def add_system_message(self, conversation_id: str, content: str) -> Optional[Message]:
        conv = self.get_conversation(conversation_id)
        if not conv:
            return None
        msg = Message.system(content)
        conv.add_message(msg)
        return msg

    def get_messages(self, conversation_id: str) -> List[Message]:
        conv = self.get_conversation(conversation_id)
        if not conv:
            return []
        return conv.messages

    def get_formatted_messages(self, conversation_id: str) -> List[Dict[str, Any]]:
        conv = self.get_conversation(conversation_id)
        if not conv:
            return []
        return [m.to_dict() for m in conv.messages]

    def clear_conversation(self, conversation_id: str) -> bool:
        with self._lock:
            conv = self._conversations.get(conversation_id)
            if not conv:
                return False
            conv.messages.clear()
            conv.summary = ""
            conv.token_count = 0
            conv.updated_at = datetime.utcnow()
            return True

    def delete_conversation(self, conversation_id: str) -> bool:
        with self._lock:
            if conversation_id in self._conversations:
                del self._conversations[conversation_id]
                return True
            return False

    def list_conversations(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [conv.to_dict() for conv in self._conversations.values()]

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._conversations)
            total_messages = sum(len(c.messages) for c in self._conversations.values())
            return {
                "total_conversations": total,
                "total_messages": total_messages,
                "avg_messages_per_conversation": round(total_messages / max(1, total), 1),
            }

    def set_summary(self, conversation_id: str, summary: str) -> bool:
        conv = self.get_conversation(conversation_id)
        if not conv:
            return False
        conv.summary = summary
        return True

    def _enforce_limits(self, conv: Conversation) -> None:
        if len(conv.messages) > self._max_history:
            excess = len(conv.messages) - self._max_history
            remove_system = []
            remove_count = 0
            for i, msg in enumerate(conv.messages):
                if msg.role == MessageRole.SYSTEM:
                    remove_system.append(i)
                elif remove_count < excess:
                    remove_count += 1

            for i in reversed(remove_system[:excess]):
                conv.messages.pop(i)
            remaining = excess - len(remove_system[:excess])
            if remaining > 0:
                non_system_indices = [
                    i for i, msg in enumerate(conv.messages) if msg.role != MessageRole.SYSTEM
                ]
                for i in reversed(non_system_indices[:remaining]):
                    conv.messages.pop(i)
