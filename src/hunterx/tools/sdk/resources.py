# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource manager.

Budgets platform-wide execution resources: CPU, memory, disk, network, threads,
parallel jobs and queue depth. A shared semaphore caps concurrent executions;
usage accounting tracks current utilization for telemetry.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from hunterx.domain.execution import ExecutionContext, ResourceLimits


@dataclass(slots=True)
class ResourceUsage:
    """Current platform resource utilization snapshot.

    Attributes:
        active_executions: number of executions currently running.
        queue_depth: number of executions waiting to run.
        cpu_percent: tracked CPU utilization.
        memory_mb: tracked resident memory.
        disk_mb: tracked scratch disk usage.
        threads: tracked active threads.

    """

    active_executions: int = 0
    queue_depth: int = 0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    disk_mb: float = 0.0
    threads: int = 0


class ResourceManager:
    """Enforce and track resource limits across tool executions.

    Usage::

        manager = ResourceManager(max_parallel_jobs=4, max_queue_size=100)
        with manager.acquire(context):
            ...  # run the tool
    """

    def __init__(
        self,
        *,
        max_parallel_jobs: int = 0,
        max_queue_size: int = 0,
        default_limits: ResourceLimits | None = None,
    ) -> None:
        self._max_parallel = max_parallel_jobs
        self._max_queue = max_queue_size
        self._default_limits = default_limits or ResourceLimits()
        self._semaphore = threading.BoundedSemaphore(
            max_parallel_jobs if max_parallel_jobs > 0 else 1
        ) if max_parallel_jobs > 0 else None
        self._lock = threading.RLock()
        self._usage = ResourceUsage()

    # -- admission ----------------------------------------------------------

    def acquire(self, context: ExecutionContext) -> _ResourceLease:
        """Block until a parallel slot is free and return a lease.

        Raises:
            RuntimeError: when the global parallel cap would be exceeded and
                the caller chose non-blocking acquisition (use ``try_acquire``).

        """
        if self._semaphore is not None:
            self._semaphore.acquire()
        with self._lock:
            self._usage.active_executions += 1
        return _ResourceLease(self)

    def try_acquire(self, context: ExecutionContext) -> _ResourceLease | None:
        """Acquire a parallel slot without blocking; return ``None`` when busy."""
        if self._semaphore is not None and not self._semaphore.acquire(blocking=False):
            return None
        with self._lock:
            self._usage.active_executions += 1
        return _ResourceLease(self)

    def release(self, lease: _ResourceLease | None) -> None:
        """Release a previously acquired slot."""
        if lease is None:
            return
        with self._lock:
            self._usage.active_executions = max(0, self._usage.active_executions - 1)
        if self._semaphore is not None:
            self._semaphore.release()

    # -- queue accounting -----------------------------------------------------

    def reserve_queue(self) -> None:
        """Reserve a queue slot; raises when the queue is full."""
        with self._lock:
            if self._max_queue and self._usage.queue_depth >= self._max_queue:
                raise RuntimeError(f"queue capacity of {self._max_queue} reached")
            self._usage.queue_depth += 1

    def release_queue(self) -> None:
        """Release a reserved queue slot."""
        with self._lock:
            self._usage.queue_depth = max(0, self._usage.queue_depth - 1)

    # -- accounting ----------------------------------------------------------

    def track_usage(
        self,
        *,
        cpu_percent: float = 0.0,
        memory_mb: float = 0.0,
        disk_mb: float = 0.0,
        threads: int = 0,
    ) -> None:
        """Record observed resource utilization (delta-free absolute values)."""
        with self._lock:
            if cpu_percent:
                self._usage.cpu_percent = cpu_percent
            if memory_mb:
                self._usage.memory_mb = memory_mb
            if disk_mb:
                self._usage.disk_mb = disk_mb
            if threads:
                self._usage.threads = threads

    def usage(self) -> ResourceUsage:
        """Return a snapshot of current utilization."""
        with self._lock:
            return ResourceUsage(
                active_executions=self._usage.active_executions,
                queue_depth=self._usage.queue_depth,
                cpu_percent=self._usage.cpu_percent,
                memory_mb=self._usage.memory_mb,
                disk_mb=self._usage.disk_mb,
                threads=self._usage.threads,
            )

    def limits_for(self, context: ExecutionContext) -> ResourceLimits:
        """Return the effective limits for ``context``.

        Execution-level limits override the platform defaults field-by-field.
        """
        execution = context.resource_limits
        merged = ResourceLimits(
            max_cpu_percent=execution.max_cpu_percent or self._default_limits.max_cpu_percent,
            max_memory_mb=execution.max_memory_mb or self._default_limits.max_memory_mb,
            max_disk_mb=execution.max_disk_mb or self._default_limits.max_disk_mb,
            network_allowed=execution.network_allowed and self._default_limits.network_allowed,
            max_threads=execution.max_threads or self._default_limits.max_threads,
            max_parallel_jobs=self._max_parallel,
            max_queue_size=self._max_queue,
            timeout_seconds=execution.timeout_seconds or self._default_limits.timeout_seconds,
        )
        return merged


class _ResourceLease:
    """A held parallel-execution slot; release via the manager."""

    def __init__(self, manager: ResourceManager) -> None:
        self._manager = manager
        self._held = True

    def release(self) -> None:
        """Release the slot (idempotent)."""
        if self._held:
            self._manager.release(self)
            self._held = False

    def __enter__(self) -> _ResourceLease:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.release()
