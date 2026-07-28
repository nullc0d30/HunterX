from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional



@dataclass
class AgentMemoryEntry:
    agent_id: str
    key: str
    value: Any
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)
    ttl_seconds: Optional[float] = 3600.0
    source_goal_id: Optional[str] = None

    def is_expired(self) -> bool:
        if self.ttl_seconds is None:
            return False
        return (time.time() - self.timestamp) > self.ttl_seconds


class AgentMemory:
    def __init__(self, max_entries: int = 10000):
        self._lock = threading.RLock()
        self._entries: Dict[str, Dict[str, AgentMemoryEntry]] = {}
        self._max_entries = max_entries

    def store(self, agent_id: str, key: str, value: Any, confidence: float = 1.0, source_goal_id: Optional[str] = None, ttl: Optional[float] = None) -> None:
        with self._lock:
            if agent_id not in self._entries:
                self._entries[agent_id] = {}
            self._entries[agent_id][key] = AgentMemoryEntry(
                agent_id=agent_id, key=key, value=value,
                confidence=confidence, source_goal_id=source_goal_id, ttl_seconds=ttl,
            )
            self._evict_if_needed()

    def retrieve(self, agent_id: str, key: str) -> Optional[Any]:
        with self._lock:
            agent_entries = self._entries.get(agent_id, {})
            entry = agent_entries.get(key)
            if entry and entry.is_expired():
                del agent_entries[key]
                return None
            return entry.value if entry else None

    def search(self, agent_id: str, query: str) -> List[AgentMemoryEntry]:
        results: List[AgentMemoryEntry] = []
        query_lower = query.lower()
        with self._lock:
            agent_entries = self._entries.get(agent_id, {})
            for entry in agent_entries.values():
                if entry.is_expired():
                    continue
                if query_lower in entry.key.lower() or query_lower in str(entry.value).lower():
                    results.append(entry)
        return results

    def forget(self, agent_id: str, key: str) -> bool:
        with self._lock:
            agent_entries = self._entries.get(agent_id, {})
            if key in agent_entries:
                del agent_entries[key]
                return True
            return False

    def clear_agent(self, agent_id: str) -> None:
        with self._lock:
            self._entries.pop(agent_id, None)

    def clear_all(self) -> None:
        with self._lock:
            self._entries.clear()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = sum(len(e) for e in self._entries.values())
            return {
                "total_entries": total,
                "total_agents": len(self._entries),
                "max_entries": self._max_entries,
            }

    def _evict_if_needed(self) -> None:
        total = sum(len(e) for e in self._entries.values())
        if total > self._max_entries:
            all_entries: List[AgentMemoryEntry] = []
            for agent_entries in self._entries.values():
                all_entries.extend(agent_entries.values())
            all_entries.sort(key=lambda e: (e.confidence, e.timestamp))
            to_remove = total - self._max_entries
            for entry in all_entries[:to_remove]:
                agent_entries = self._entries.get(entry.agent_id, {})
                if entry.key in agent_entries:
                    del agent_entries[entry.key]
