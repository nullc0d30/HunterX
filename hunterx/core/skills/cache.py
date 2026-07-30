from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .result import SkillResult


@dataclass
class CacheEntry:
    key: str
    result: SkillResult
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 300.0
    access_count: int = 0

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds


class SkillCache:
    def __init__(self, max_entries: int = 1000, default_ttl: float = 300.0):
        self._lock = threading.RLock()
        self._entries: Dict[str, CacheEntry] = {}
        self._max_entries = max_entries
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0

    def get(self, skill_id: str, target: str, params: Optional[Dict[str, Any]] = None) -> Optional[SkillResult]:
        key = self._make_key(skill_id, target, params)
        with self._lock:
            entry = self._entries.get(key)
            if entry and not entry.is_expired():
                entry.access_count += 1
                self._hits += 1
                return entry.result
            if entry:
                del self._entries[key]
            self._misses += 1
            return None

    def set(self, skill_id: str, target: str, result: SkillResult, params: Optional[Dict[str, Any]] = None, ttl: Optional[float] = None) -> None:
        key = self._make_key(skill_id, target, params)
        with self._lock:
            self._entries[key] = CacheEntry(
                key=key,
                result=result,
                ttl_seconds=ttl or self._default_ttl,
            )
            self._evict_if_needed()

    def invalidate(self, skill_id: str, target: str) -> None:
        key = self._make_key(skill_id, target)
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._hits = 0
            self._misses = 0

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries": len(self._entries),
                "max_entries": self._max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": self._hits / total if total > 0 else 0.0,
                "default_ttl_seconds": self._default_ttl,
            }

    def _make_key(self, skill_id: str, target: str, params: Optional[Dict[str, Any]] = None) -> str:
        raw = f"{skill_id}:{target}:{json.dumps(params or {}, sort_keys=True)}"
        return f"{skill_id}:{hashlib.sha256(raw.encode()).hexdigest()}"

    def _evict_if_needed(self) -> None:
        if len(self._entries) > self._max_entries:
            sorted_entries = sorted(self._entries.values(), key=lambda e: (e.access_count, e.created_at))
            to_remove = len(self._entries) - self._max_entries
            for entry in sorted_entries[:to_remove]:
                del self._entries[entry.key]
