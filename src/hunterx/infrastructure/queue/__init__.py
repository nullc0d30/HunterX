# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Work-queue adapters."""

from __future__ import annotations

import queue
import threading
import uuid
from typing import Any

from hunterx.domain.ports.messaging import QueuePort


class MemoryQueue(QueuePort):
    """An in-process FIFO work queue with acknowledgements.

    Supports enqueue, blocking dequeue with timeout, and ack/nack for
    at-least-once semantics. Suitable for development and single-node runs.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[tuple[str, str, dict[str, Any]]] = queue.Queue()
        self._inflight: dict[str, tuple[str, dict[str, Any]]] = {}
        self._lock = threading.RLock()

    def enqueue(self, job_type: str, payload: dict[str, Any]) -> str:
        """Queue a job and return its identifier."""
        job_id = uuid.uuid4().hex
        self._queue.put((job_id, job_type, payload))
        return job_id

    def dequeue(self, *, timeout_seconds: float = 5.0) -> tuple[str, str, dict[str, Any]] | None:
        """Claim a job, returning ``(job_id, job_type, payload)`` or ``None``."""
        try:
            job_id, job_type, payload = self._queue.get(timeout=timeout_seconds)
        except queue.Empty:
            return None
        with self._lock:
            self._inflight[job_id] = (job_type, payload)
        return job_id, job_type, payload

    def ack(self, job_id: str) -> None:
        """Mark a claimed job as successfully processed."""
        with self._lock:
            self._inflight.pop(job_id, None)

    def nack(self, job_id: str, *, requeue: bool = False) -> None:
        """Reject a claimed job, optionally returning it to the queue."""
        with self._lock:
            entry = self._inflight.pop(job_id, None)
        if requeue and entry is not None:
            self._queue.put((job_id, entry[0], entry[1]))


class NullQueue(QueuePort):
    """A queue that accepts work but never dispatches it."""

    def enqueue(self, job_type: str, payload: dict[str, Any]) -> str:
        """Acknowledge the job but never queue it; return an identifier."""
        return uuid.uuid4().hex

    def dequeue(self, *, timeout_seconds: float = 5.0) -> tuple[str, str, dict[str, Any]] | None:
        """Never return work."""
        return None

    def ack(self, job_id: str) -> None:
        """No-op; no jobs are tracked."""

    def nack(self, job_id: str, *, requeue: bool = False) -> None:
        """No-op; no jobs are tracked."""
        return None
