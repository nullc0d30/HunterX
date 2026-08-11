# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution cache.

Stores normalized execution results keyed by (tool, target, configuration).
Caching is opt-in per execution context and honors the cache TTL configured at
platform level. Cached results are returned only when still fresh and valid.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time

from hunterx.domain.execution import ExecutionContext, ExecutionResult


class ExecutionCache:
    """Thread-safe result cache for tool executions.

    Usage::

        cache = ExecutionCache(ttl_s=3600)
        key = cache.key_for(context)
        if (hit := cache.get(key)) is not None:
            return hit
        result = ...  # run the tool
        cache.set(key, result)
    """

    def __init__(self, *, ttl_s: int = 0) -> None:
        self._ttl_s = ttl_s
        self._entries: dict[str, tuple[float, ExecutionResult]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def key_for(context: ExecutionContext) -> str:
        """Build a deterministic cache key for ``context``.

        The key covers the tool, target, profile, tool version and the
        configuration. Correlation and execution ids never take part, so
        equivalent executions share a key.
        """
        payload = {
            "tool_id": context.tool_id,
            "target": context.target,
            "profile": context.profile,
            "tool_version": context.tool_version,
            "configuration": context.configuration,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return digest

    def get(self, key: str) -> ExecutionResult | None:
        """Return a fresh cached result or ``None`` when absent/expired."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, result = entry
            if self._expired(stored_at):
                del self._entries[key]
                return None
            return result

    def set(self, key: str, result: ExecutionResult) -> None:
        """Store ``result`` under ``key`` with the current timestamp."""
        with self._lock:
            self._entries[key] = (time.monotonic(), result)

    def invalidate(self, key: str) -> None:
        """Remove an entry by key (idempotent)."""
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        """Remove all cached entries."""
        with self._lock:
            self._entries.clear()

    def purge_expired(self) -> int:
        """Remove expired entries; return the number purged."""
        with self._lock:
            expired = [key for key, (stored_at, _) in self._entries.items() if self._expired(stored_at)]
            for key in expired:
                del self._entries[key]
            return len(expired)

    def size(self) -> int:
        """Return the number of live entries."""
        with self._lock:
            return len(self._entries)

    def _expired(self, stored_at: float) -> bool:
        if self._ttl_s <= 0:
            return False
        return time.monotonic() - stored_at > self._ttl_s
