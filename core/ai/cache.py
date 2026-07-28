from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..utils import logger


@dataclass
class CacheEntry:
    key: str
    value: str
    created_at: float = 0.0
    expires_at: float = 0.0
    hit_count: int = 0
    token_count: int = 0

    def is_expired(self) -> bool:
        return 0 < self.expires_at < time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key[:16],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "hit_count": self.hit_count,
            "token_count": self.token_count,
        }


class AICache:
    def __init__(
        self,
        db_path: Optional[str] = None,
        default_ttl: int = 3600,
        max_size: int = 10000,
        enable_memory: bool = True,
    ):
        self._default_ttl = default_ttl
        self._max_size = max_size
        self._enable_memory = enable_memory
        self._memory: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "ai_cache.db"
        )
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL DEFAULT 0,
                    hit_count INTEGER DEFAULT 0,
                    token_count INTEGER DEFAULT 0
                )
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_expires
                ON ai_cache(expires_at)
            """)
            self._conn.commit()
            self._cleanup_expired()
        except Exception as e:
            logger.warning(f"AICache: SQLite init failed ({e}), using memory only")
            self._conn = None

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            if self._enable_memory and key in self._memory:
                entry = self._memory[key]
                if not entry.is_expired():
                    entry.hit_count += 1
                    self._hits += 1
                    return entry.value
                else:
                    del self._memory[key]

            if self._conn:
                try:
                    row = self._conn.execute(
                        "SELECT value, expires_at, hit_count FROM ai_cache WHERE key = ?",
                        (key,),
                    ).fetchone()
                    if row:
                        if row[1] == 0 or row[1] > time.time():
                            self._conn.execute(
                                "UPDATE ai_cache SET hit_count = hit_count + 1 WHERE key = ?",
                                (key,),
                            )
                            self._conn.commit()
                            self._hits += 1
                            if self._enable_memory:
                                self._memory[key] = CacheEntry(
                                    key=key, value=row[0], expires_at=row[1], hit_count=row[2] + 1,
                                )
                            return row[0]
                        else:
                            self._conn.execute("DELETE FROM ai_cache WHERE key = ?", (key,))
                            self._conn.commit()
                except Exception:
                    pass

            self._misses += 1
            return None

    def set(
        self,
        key: str,
        value: str,
        ttl: Optional[int] = None,
        token_count: int = 0,
    ) -> None:
        with self._lock:
            now = time.time()
            expires_at = now + (ttl if ttl is not None else self._default_ttl)

            if self._enable_memory:
                if len(self._memory) >= self._max_size:
                    self._evict_memory()
                self._memory[key] = CacheEntry(
                    key=key, value=value, created_at=now,
                    expires_at=expires_at, token_count=token_count,
                )

            if self._conn:
                try:
                    self._conn.execute(
                        """INSERT OR REPLACE INTO ai_cache
                           (key, value, created_at, expires_at, hit_count, token_count)
                           VALUES (?, ?, ?, ?, COALESCE((SELECT hit_count FROM ai_cache WHERE key = ?), 0), ?)""",
                        (key, value, now, expires_at, key, token_count),
                    )
                    self._conn.commit()
                except Exception:
                    pass

    def has(self, key: str) -> bool:
        return self.get(key) is not None

    def compute_key(self, messages: List[Dict[str, Any]], model: str, temperature: float = 0.0) -> str:
        data = json.dumps({"m": messages, "model": model, "t": round(temperature, 1)}, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def compute_semantic_key(self, text: str) -> str:
        normalized = " ".join(text.lower().split())[:500]
        return hashlib.sha256(normalized.encode()).hexdigest()

    def clear(self) -> None:
        with self._lock:
            self._memory.clear()
            if self._conn:
                try:
                    self._conn.execute("DELETE FROM ai_cache")
                    self._conn.commit()
                except Exception:
                    pass

    def get_stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "enabled": True,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / max(1, total), 3),
            "memory_entries": len(self._memory),
            "db_path": self._db_path,
            "default_ttl": self._default_ttl,
            "max_size": self._max_size,
        }

    def get_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        if self._conn:
            try:
                rows = self._conn.execute(
                    "SELECT key, created_at, expires_at, hit_count, token_count FROM ai_cache ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [
                    {"key": r[0][:16], "created_at": r[1], "expires_at": r[2], "hit_count": r[3], "token_count": r[4]}
                    for r in rows
                ]
            except Exception:
                pass
        return list(self._memory.values())[:limit]

    def _cleanup_expired(self) -> int:
        if self._conn:
            try:
                result = self._conn.execute(
                    "DELETE FROM ai_cache WHERE expires_at > 0 AND expires_at < ?",
                    (time.time(),),
                )
                self._conn.commit()
                return result.rowcount
            except Exception:
                pass
        return 0

    def _evict_memory(self) -> None:
        if not self._memory:
            return
        oldest = min(self._memory.keys(), key=lambda k: self._memory[k].created_at)
        del self._memory[oldest]

    def close(self) -> None:
        try:
            if self._conn:
                self._conn.close()
        except Exception:
            pass
