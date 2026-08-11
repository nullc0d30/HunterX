# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool queue.

A FIFO queue of pending tool executions consumed by the scheduler. Enqueueing
is bounded by the resource manager's queue capacity and rejects items that
violate concurrency policy (same tool+target already queued) when enforced.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.execution import ExecutionContext


@dataclass(slots=True)
class QueueItem:
    """A single pending execution request.

    Attributes:
        context: the execution context to run.
        attempts: number of attempts already made.
        queued_at: monotonic timestamp when the item was enqueued.
        metadata: caller-supplied free-form metadata.

    """

    context: ExecutionContext
    attempts: int = 0
    queued_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolQueue:
    """Thread-safe FIFO queue of :class:`QueueItem` executions.

    Usage::

        queue = ToolQueue(capacity=100)
        queue.enqueue(context)
        item = queue.dequeue()       # None when empty
        queue.acknowledge(item)
    """

    def __init__(self, *, capacity: int = 0, deduplicate: bool = False) -> None:
        self._items: deque[QueueItem] = deque()
        self._capacity = capacity
        self._deduplicate = deduplicate
        self._pending: set[str] = set()
        self._lock = threading.RLock()

    def enqueue(self, context: ExecutionContext, **metadata: Any) -> QueueItem:
        """Add ``context`` to the tail of the queue.

        Raises:
            RuntimeError: when the queue is full.

        """
        item = QueueItem(context=context, queued_at=time.monotonic(), metadata=metadata)
        key = self._identity(context)
        with self._lock:
            if self._deduplicate and key in self._pending:
                raise RuntimeError(f"execution for '{key}' already queued")
            if self._capacity and len(self._items) >= self._capacity:
                raise RuntimeError(f"queue capacity of {self._capacity} reached")
            self._items.append(item)
            if self._deduplicate:
                self._pending.add(key)
        return item

    def dequeue(self) -> QueueItem | None:
        """Remove and return the head item, or ``None`` when empty."""
        with self._lock:
            if not self._items:
                return None
            item = self._items.popleft()
            self._pending.discard(self._identity(item.context))
            return item

    def acknowledge(self, item: QueueItem) -> None:
        """Mark an item fully processed (no-op, retained for symmetry)."""

    def size(self) -> int:
        """Return the number of pending items."""
        with self._lock:
            return len(self._items)

    def clear(self) -> None:
        """Drop all pending items."""
        with self._lock:
            self._items.clear()
            self._pending.clear()

    @staticmethod
    def _identity(context: ExecutionContext) -> str:
        return f"{context.tool_id}:{context.target}"
