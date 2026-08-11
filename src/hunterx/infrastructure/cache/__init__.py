# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cache adapters."""

from __future__ import annotations

import threading
import time
from typing import Any

from hunterx.domain.ports.messaging import CachePort


class MemoryCache(CachePort):
    """Thread-safe in-process cache with optional TTLs.

    Values are stored together with their expiry timestamps. Used for
    development, tests, and single-node deployments.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float | None]] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        """Return the cached value for ``key``, expiring stale entries."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at is not None and expires_at <= time.monotonic():
                self._store.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any, *, ttl_seconds: int | None = None) -> None:
        """Store ``value`` under ``key`` with an optional TTL."""
        expires_at = time.monotonic() + ttl_seconds if ttl_seconds else None
        with self._lock:
            self._store[key] = (value, expires_at)

    def delete(self, key: str) -> None:
        """Delete the cached value for ``key``."""
        with self._lock:
            self._store.pop(key, None)

    def flush(self) -> None:
        """Remove all cached entries."""
        with self._lock:
            self._store.clear()


class NullCache(CachePort):
    """A cache that stores nothing; useful to disable caching."""

    def get(self, key: str) -> Any | None:
        """Return ``None``; this cache never stores values."""
        return None

    def set(self, key: str, value: Any, *, ttl_seconds: int | None = None) -> None:
        """Discard the write; nothing is cached."""
        return None

    def delete(self, key: str) -> None:
        """Discard the delete; nothing is cached."""
        return None

    def flush(self) -> None:
        """No-op; nothing is cached."""
        return None
