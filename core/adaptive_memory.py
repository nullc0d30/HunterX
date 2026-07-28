# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .utils import logger


@dataclass
class MemoryEntry:
    id: str
    entry_type: str
    key: str
    value: Any
    context: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 1
    ttl_days: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "entry_type": self.entry_type,
            "key": self.key,
            "value": self.value,
            "context": self.context,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "access_count": self.access_count,
        }


class AdaptiveMemory:
    def __init__(
        self,
        storage_path: Optional[str] = None,
        use_sqlite: bool = True,
    ):
        self._lock = threading.RLock()
        self._memory: Dict[str, Dict[str, MemoryEntry]] = {}
        self._storage_path = storage_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "adaptive_memory"
        )
        self._use_sqlite = use_sqlite
        self._db_path = os.path.join(self._storage_path, "memory.db")
        self._json_path = os.path.join(self._storage_path, "memory.json")

        os.makedirs(self._storage_path, exist_ok=True)

        if use_sqlite:
            self._init_sqlite()
        else:
            self._load_json()

    def _init_sqlite(self) -> None:
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS memory (
                    id TEXT PRIMARY KEY,
                    entry_type TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    context TEXT DEFAULT '{}',
                    confidence REAL DEFAULT 1.0,
                    created_at TEXT DEFAULT (datetime('now')),
                    last_accessed TEXT DEFAULT (datetime('now')),
                    access_count INTEGER DEFAULT 1,
                    ttl_days INTEGER
                )
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_memory_type_key
                ON memory(entry_type, key)
            """)
            self._conn.commit()
            logger.info(f"AdaptiveMemory: initialized SQLite at {self._db_path}")
        except Exception as e:
            logger.warning(f"AdaptiveMemory: SQLite init failed ({e}), falling back to JSON")
            self._use_sqlite = False
            self._load_json()

    def _load_json(self) -> None:
        if os.path.exists(self._json_path):
            try:
                with open(self._json_path) as f:
                    data = json.load(f)
                    for entry_type, entries in data.items():
                        if entry_type not in self._memory:
                            self._memory[entry_type] = {}
                        for key, entry_data in entries.items():
                            self._memory[entry_type][key] = MemoryEntry(**entry_data)
                logger.info(f"AdaptiveMemory: loaded {sum(len(v) for v in self._memory.values())} entries from JSON")
            except Exception as e:
                logger.warning(f"AdaptiveMemory: JSON load failed ({e})")

    def _save_json(self) -> None:
        try:
            data = {}
            for entry_type, entries in self._memory.items():
                data[entry_type] = {k: v.to_dict() for k, v in entries.items()}
            with open(self._json_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"AdaptiveMemory: JSON save failed ({e})")

    def store(
        self,
        entry_type: str,
        key: str,
        value: Any,
        context: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        ttl_days: Optional[int] = None,
    ) -> MemoryEntry:
        with self._lock:
            entry = MemoryEntry(
                id=str(uuid.uuid4()),
                entry_type=entry_type,
                key=key,
                value=value,
                context=context or {},
                confidence=confidence,
                ttl_days=ttl_days,
            )

            if self._use_sqlite:
                try:
                    self._conn.execute(
                        """INSERT OR REPLACE INTO memory
                           (id, entry_type, key, value, context, confidence, created_at, last_accessed, access_count, ttl_days)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            entry.id, entry.entry_type, entry.key,
                            json.dumps(entry.value) if not isinstance(entry.value, str) else entry.value,
                            json.dumps(entry.context), entry.confidence,
                            entry.created_at.isoformat(), entry.last_accessed.isoformat(),
                            entry.access_count, entry.ttl_days,
                        ),
                    )
                    self._conn.commit()
                except Exception as e:
                    logger.debug(f"AdaptiveMemory: SQLite store failed ({e})")

            if entry_type not in self._memory:
                self._memory[entry_type] = {}
            self._memory[entry_type][key] = entry

            if not self._use_sqlite:
                self._save_json()

            return entry

    def recall(self, entry_type: str, key: str) -> Optional[Any]:
        with self._lock:
            if entry_type in self._memory and key in self._memory[entry_type]:
                entry = self._memory[entry_type][key]
                entry.access_count += 1
                entry.last_accessed = datetime.utcnow()
                return entry.value
            return None

    def recall_entry(self, entry_type: str, key: str) -> Optional[MemoryEntry]:
        with self._lock:
            if entry_type in self._memory and key in self._memory[entry_type]:
                entry = self._memory[entry_type][key]
                entry.access_count += 1
                entry.last_accessed = datetime.utcnow()
                return entry
            return None

    def search(
        self,
        entry_type: str,
        query: str,
        threshold: float = 0.5,
    ) -> List[MemoryEntry]:
        with self._lock:
            results = []
            if entry_type not in self._memory:
                return results
            query_lower = query.lower()
            for key, entry in self._memory[entry_type].items():
                if query_lower in key.lower():
                    results.append(entry)
                elif isinstance(entry.value, str) and query_lower in entry.value.lower():
                    results.append(entry)
                elif isinstance(entry.value, dict):
                    if any(query_lower in str(v).lower() for v in entry.value.values()):
                        results.append(entry)
            return results

    def get_by_type(self, entry_type: str) -> List[MemoryEntry]:
        with self._lock:
            return list(self._memory.get(entry_type, {}).values())

    def record_successful_payload(
        self,
        payload: str,
        category: str,
        target_fingerprint: str,
        confidence: float = 1.0,
    ) -> None:
        self.store(
            entry_type="successful_payloads",
            key=f"{category}:{payload[:64]}",
            value=payload,
            context={
                "category": category,
                "target_fingerprint": target_fingerprint,
                "payload_length": len(payload),
            },
            confidence=confidence,
        )

    def record_blocked_payload(
        self,
        payload: str,
        category: str,
        block_reason: str = "waf",
    ) -> None:
        self.store(
            entry_type="blocked_payloads",
            key=f"{category}:{payload[:64]}",
            value=payload,
            context={
                "category": category,
                "block_reason": block_reason,
            },
            confidence=0.0,
        )

    def record_false_positive(
        self,
        finding_id: str,
        reason: str,
        category: str,
    ) -> None:
        self.store(
            entry_type="false_positives",
            key=finding_id,
            value={"finding_id": finding_id, "reason": reason, "category": category},
            confidence=0.0,
        )

    def record_target_fingerprint(
        self,
        target: str,
        fingerprint: Dict[str, Any],
    ) -> None:
        self.store(
            entry_type="target_fingerprints",
            key=target,
            value=fingerprint,
        )

    def is_blocked(self, payload: str, category: str) -> bool:
        key = f"{category}:{payload[:64]}"
        return self.recall("blocked_payloads", key) is not None

    def is_false_positive(self, finding_id: str) -> bool:
        return self.recall("false_positives", finding_id) is not None

    def get_successful_payloads(
        self,
        category: Optional[str] = None,
    ) -> List[MemoryEntry]:
        entries = self.get_by_type("successful_payloads")
        if category:
            return [e for e in entries if e.context.get("category") == category]
        return entries

    def get_target_fingerprint(
        self, target: str
    ) -> Optional[Dict[str, Any]]:
        return self.recall("target_fingerprints", target)

    def cleanup_expired(self) -> int:
        removed = 0
        with self._lock:
            now = datetime.utcnow()
            for entry_type in list(self._memory.keys()):
                for key in list(self._memory[entry_type].keys()):
                    entry = self._memory[entry_type][key]
                    if entry.ttl_days:
                        age = (now - entry.created_at).days
                        if age > entry.ttl_days:
                            del self._memory[entry_type][key]
                            removed += 1
        if self._use_sqlite:
            try:
                self._conn.execute("DELETE FROM memory WHERE ttl_days IS NOT NULL AND datetime('now') > datetime(created_at, '+' || ttl_days || ' days')")
                self._conn.commit()
            except Exception:
                pass
        return removed

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            stats = {
                "total_entries": sum(len(v) for v in self._memory.values()),
                "by_type": {t: len(v) for t, v in self._memory.items()},
                "storage": "sqlite" if self._use_sqlite else "json",
            }
            return stats

    def close(self) -> None:
        if self._use_sqlite:
            try:
                self._conn.close()
            except Exception:
                pass
