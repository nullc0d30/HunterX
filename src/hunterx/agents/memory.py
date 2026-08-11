# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent memory."""

from __future__ import annotations

import threading
from typing import Any


class AgentMemory:
    """A bounded, thread-safe working memory for a single agent.

    Stores observations and results as key/value entries. Used for the
    lifetime of a mission run; long-term knowledge belongs in the knowledge
    engine instead.
    """

    def __init__(self, *, max_entries: int = 1000) -> None:
        self._max_entries = max_entries
        self._entries: dict[str, Any] = {}
        self._lock = threading.RLock()

    def store(self, key: str, value: Any) -> None:
        """Store or overwrite an entry."""
        with self._lock:
            if key not in self._entries and len(self._entries) >= self._max_entries:
                # Evict the oldest entry to keep the memory bounded.
                self._entries.pop(next(iter(self._entries)))
            self._entries[key] = value

    def retrieve(self, key: str) -> Any | None:
        """Return an entry by key or ``None``."""
        with self._lock:
            return self._entries.get(key)

    def forget(self, key: str) -> None:
        """Remove an entry by key."""
        with self._lock:
            self._entries.pop(key, None)

    def snapshot(self) -> dict[str, Any]:
        """Return a shallow copy of all entries."""
        with self._lock:
            return dict(self._entries)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._entries.clear()
