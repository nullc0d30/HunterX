# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scheduler service.

Triggers scheduled jobs and dispatches them to the work queue. The scheduler
is independent from the agent scheduler: it handles mission-level operations
while the agent scheduler handles recurring agent dispatches.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from hunterx.domain.exceptions import ScheduleConflictError
from hunterx.domain.ports.messaging import QueuePort
from hunterx.scheduler.jobs import Job, JobStatus, Schedule


class SchedulerService:
    """Register schedules and fire their jobs into a queue.

    A background loop checks due schedules and enqueues jobs. Handlers can be
    registered per job type to run jobs synchronously instead.
    """

    def __init__(self, queue: QueuePort) -> None:
        self._queue = queue
        self._schedules: dict[str, Schedule] = {}
        self._handlers: dict[str, Callable[[Job], None]] = {}
        self._last_run: dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- configuration -----------------------------------------------------

    def register_schedule(self, schedule: Schedule) -> None:
        """Register a recurring schedule.

        Raises:
            ScheduleConflictError: if the name is already registered.

        """
        if schedule.name in self._schedules:
            raise ScheduleConflictError(f"Schedule '{schedule.name}' already exists.")
        self._schedules[schedule.name] = schedule
        self._last_run[schedule.name] = 0.0

    def unregister_schedule(self, name: str) -> None:
        """Remove a schedule by name."""
        self._schedules.pop(name, None)
        self._last_run.pop(name, None)

    def register_handler(self, job_type: str, handler: Callable[[Job], None]) -> None:
        """Register a synchronous handler for a job type."""
        self._handlers[job_type] = handler

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start the scheduler loop."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="hunterx-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the scheduler loop."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # -- job dispatch ------------------------------------------------------

    def dispatch(self, job_type: str, payload: dict[str, object] | None = None) -> str:
        """Dispatch a job of ``job_type`` immediately.

        Returns the job identifier. If a synchronous handler is registered,
        the job runs inline; otherwise it is enqueued.
        """
        job = Job(job_type=job_type, payload=payload or {})
        handler = self._handlers.get(job_type)
        if handler is not None:
            handler(job)
            job.status = JobStatus.COMPLETED
            return job.job_id
        return self._queue.enqueue(job_type, job.payload)

    # -- internals ---------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            for schedule in list(self._schedules.values()):
                if not schedule.enabled:
                    continue
                if now - self._last_run[schedule.name] >= schedule.interval_seconds:
                    self._last_run[schedule.name] = now
                    self._queue.enqueue(schedule.job_type, dict(schedule.payload))
            self._stop.wait(1.0)

    def schedules(self) -> list[Schedule]:
        """Return the registered schedules."""
        return list(self._schedules.values())
