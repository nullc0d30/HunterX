from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .formatter import ReasoningResult


@dataclass
class ReasoningMemoryEntry:
    goal_id: str
    goal_type: str
    objective: str
    response: str
    confidence: float
    provider: str
    model: str
    timestamp: float = field(default_factory=time.time)
    ttl_seconds: Optional[float] = 3600.0

    def is_expired(self) -> bool:
        if self.ttl_seconds is None:
            return False
        return (time.time() - self.timestamp) > self.ttl_seconds


class ReasoningMemory:
    def __init__(self, max_entries: int = 1000):
        self._lock = threading.RLock()
        self._entries: Dict[str, ReasoningMemoryEntry] = {}
        self._max_entries = max_entries

    def store(self, result: ReasoningResult) -> str:
        entry = ReasoningMemoryEntry(
            goal_id=result.goal_id,
            goal_type=result.goal_type,
            objective=result.objective,
            response=result.response,
            confidence=result.confidence,
            provider=result.provider,
            model=result.model,
        )
        with self._lock:
            self._entries[result.goal_id] = entry
            self._evict_if_needed()
        return result.goal_id

    def retrieve(self, goal_id: str) -> Optional[ReasoningMemoryEntry]:
        with self._lock:
            entry = self._entries.get(goal_id)
            if entry and entry.is_expired():
                del self._entries[goal_id]
                return None
            return entry

    def search(self, query: str, min_confidence: float = 0.0) -> List[ReasoningMemoryEntry]:
        results: List[ReasoningMemoryEntry] = []
        query_lower = query.lower()
        with self._lock:
            for entry in self._entries.values():
                if entry.is_expired():
                    continue
                if entry.confidence < min_confidence:
                    continue
                if query_lower in entry.objective.lower() or query_lower in entry.response.lower():
                    results.append(entry)
        return sorted(results, key=lambda e: e.confidence, reverse=True)

    def get_recent(self, limit: int = 10) -> List[ReasoningMemoryEntry]:
        with self._lock:
            entries = [e for e in self._entries.values() if not e.is_expired()]
            entries.sort(key=lambda e: e.timestamp, reverse=True)
            return entries[:limit]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            active = sum(1 for e in self._entries.values() if not e.is_expired())
            return {
                "total_entries": len(self._entries),
                "active_entries": active,
                "expired_entries": len(self._entries) - active,
                "max_entries": self._max_entries,
            }

    def clear_expired(self) -> int:
        removed = 0
        with self._lock:
            expired = [k for k, v in self._entries.items() if v.is_expired()]
            for k in expired:
                del self._entries[k]
                removed += 1
        return removed

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def _evict_if_needed(self) -> None:
        if len(self._entries) > self._max_entries:
            sorted_entries = sorted(self._entries.values(), key=lambda e: (e.confidence, e.timestamp))
            to_remove = len(self._entries) - self._max_entries
            for entry in sorted_entries[:to_remove]:
                del self._entries[entry.goal_id]
