# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool lock manager.

Prevents concurrent executions of the same tool on the same target. Locks are
keyed by ``tool_id:target`` by default and support a blocking acquire with
timeout. Re-entrant so nested executions from one thread are safe.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable

from hunterx.domain.exceptions import ToolLockError


class ToolLockManager:
    """Acquire/release execution locks per (tool, target).

    Usage::

        locks = ToolLockManager()
        with locks.locked(tool_id="nmap", target="10.0.0.5"):
            ...  # exclusive execution
    """

    def __init__(self) -> None:
        self._locks: dict[str, threading.RLock] = {}
        self._guard = threading.Lock()

    def _key(self, tool_id: str, target: str) -> str:
        return f"{tool_id}:{target}"

    def _ensure(self, key: str) -> threading.RLock:
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._locks[key] = lock
            return lock

    def acquire(self, tool_id: str, target: str, *, timeout_s: float = 0.0, blocking: bool = True) -> None:
        """Acquire the lock for ``tool_id``/``target``.

        Raises:
            ToolLockError: when acquisition fails (timeout or non-blocking).

        """
        lock = self._ensure(self._key(tool_id, target))
        acquired = lock.acquire(blocking=blocking, timeout=timeout_s if blocking and timeout_s > 0 else -1)
        if not acquired:
            raise ToolLockError(self._key(tool_id, target), reason="could not acquire within timeout")

    def release(self, tool_id: str, target: str) -> None:
        """Release the lock for ``tool_id``/``target`` (idempotent)."""
        lock = self._locks.get(self._key(tool_id, target))
        if lock is not None:
            with contextlib.suppress(RuntimeError):
                lock.release()

    def locked(self, tool_id: str, target: str, *, timeout_s: float = 0.0) -> _ToolLockGuard:
        """Return a context manager that acquires and releases the lock."""
        return _ToolLockGuard(self, tool_id, target, timeout_s=timeout_s)

    def is_locked(self, tool_id: str, target: str) -> bool:
        """Return ``True`` when the key is currently held by this thread."""
        lock = self._locks.get(self._key(tool_id, target))
        return bool(lock is not None and lock._is_owned())  # noqa: SLF001 - thread-safety introspection


class _ToolLockGuard:
    """Context manager for :class:`ToolLockManager` locks."""

    def __init__(self, manager: ToolLockManager, tool_id: str, target: str, *, timeout_s: float) -> None:
        self._manager = manager
        self._tool_id = tool_id
        self._target = target
        self._timeout_s = timeout_s

    def __enter__(self) -> None:
        self._manager.acquire(self._tool_id, self._target, timeout_s=self._timeout_s)

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self._manager.release(self._tool_id, self._target)


LockStrategy = Callable[[str, str], "_ToolLockGuard"]
