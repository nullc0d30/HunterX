# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Task scheduler.

Pulls items from the tool queue and dispatches each to a runner. The scheduler
respects the resource manager's parallel-jobs cap and runs until the queue is
empty. It is the production loop that drives queued executions.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from hunterx.domain.execution import ExecutionContext, ExecutionResult
from hunterx.tools.sdk.queue import QueueItem, ToolQueue
from hunterx.tools.sdk.resources import ResourceManager

QueueRunner = Callable[[ExecutionContext], ExecutionResult]


class TaskScheduler:
    """Consume the tool queue and run items through ``runner``.

    Usage::

        scheduler = TaskScheduler(queue, resources)
        scheduler.run(runner)                    # drain the queue
        scheduler.drain(runner, max_items=10)    # process up to N items
    """

    def __init__(self, queue: ToolQueue, resources: ResourceManager) -> None:
        self._queue = queue
        self._resources = resources
        self._stop = threading.Event()

    def run(self, runner: QueueRunner) -> list[ExecutionResult]:
        """Drain the queue, running each item through ``runner``.

        Stops early when :meth:`stop` is called. Returns the results produced.
        """
        return self._drain(runner, max_items=None)

    def drain(self, runner: QueueRunner, *, max_items: int = 0) -> list[ExecutionResult]:
        """Process up to ``max_items`` queued items (``0`` = unlimited)."""
        return self._drain(runner, max_items=max_items)

    def stop(self) -> None:
        """Ask :meth:`run` to return after the current item."""
        self._stop.set()

    def _drain(self, runner: QueueRunner, *, max_items: int | None) -> list[ExecutionResult]:
        results: list[ExecutionResult] = []
        processed = 0
        self._stop.clear()
        while True:
            if max_items and processed >= max_items:
                break
            if self._stop.is_set():
                break
            item: QueueItem | None = self._queue.dequeue()
            if item is None:
                break
            processed += 1
            lease = self._resources.try_acquire(item.context)
            if lease is None:
                self._queue.enqueue(item.context, **item.metadata)
                continue
            try:
                results.append(runner(item.context))
            finally:
                lease.release()
                self._queue.acknowledge(item)
        return results
