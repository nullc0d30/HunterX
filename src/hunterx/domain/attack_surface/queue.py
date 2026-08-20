# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal assessment queue.

A target-agnostic queue of scheduled capabilities against discovered surfaces.
Every item bundles ``surface · capability · context · authentication state ·
authorization state · strategy · priority · status · attempts · evidence ·
verification state`` — nothing target-specific. The queue is the scheduler's
work source; the completion gate treats its exhaustion as one of the mandatory
completion criteria.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from hunterx.domain.attack_surface.enums import AssessmentStatus, VerificationState
from hunterx.domain.attack_surface.models import AssessmentTask, SurfaceContext


class AssessmentQueue:
    """A priority-aware queue of :class:`AssessmentTask` items.

    Deduplication is by ``surface × capability × context``: the same
    capability against the same surface under the same context is never queued
    twice, while a *changed* context (a new session, a new authorization scope)
    legitimately produces a new task.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, AssessmentTask] = {}
        self._by_dedup: dict[str, str] = {}

    # -- mutation -----------------------------------------------------------

    def submit(
        self,
        *,
        surface_key: str,
        capability_id: str,
        context: SurfaceContext | None = None,
        mission_id: str = "",
        strategy: str = "",
        priority: float = 50.0,
        assignment_id: str = "",
    ) -> AssessmentTask:
        """Submit an assessment task (deduplicated by surface×capability×context).

        A duplicate submission returns the existing task unchanged, so repeated
        discovery of the same surface never floods the queue.
        """
        context = context if context is not None else SurfaceContext()
        task = AssessmentTask(
            mission_id=mission_id,
            surface_key=surface_key,
            capability_id=capability_id,
            context=context,
            strategy=strategy,
            priority=priority,
            assignment_id=assignment_id,
            status=AssessmentStatus.READY,
        )
        dedup = task.dedup_key()
        existing = self._by_dedup.get(dedup)
        if existing is not None:
            return self._tasks[existing]
        self._tasks[task.task_id] = task
        self._by_dedup[dedup] = task.task_id
        return task

    def get(self, task_id: str) -> AssessmentTask | None:
        """Return a task by id (``None`` when absent)."""
        return self._tasks.get(task_id)

    def mark(self, task_id: str, status: AssessmentStatus) -> AssessmentTask | None:
        """Transition a task's runtime status."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task.mark(status)
        return task

    def record_attempt(self, task_id: str) -> AssessmentTask | None:
        """Record an execution attempt on a task."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task.record_attempt()
        return task

    def record_evidence(self, task_id: str, evidence: dict[str, Any]) -> AssessmentTask | None:
        """Attach an evidence record to a task."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task.record_evidence(evidence)
        return task

    def settle(self, task_id: str, verification_state: VerificationState) -> AssessmentTask | None:
        """Record the verification verdict for a task."""
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task.settle(verification_state)
        return task

    # -- reads --------------------------------------------------------------

    def tasks(self, status: AssessmentStatus | None = None) -> list[AssessmentTask]:
        """Return tasks, optionally filtered by status, newest first."""
        values = list(self._tasks.values())
        if status is not None:
            values = [task for task in values if task.status is status]
        return sorted(values, key=lambda task: task.created_at, reverse=True)

    def by_surface(self, surface_key: str) -> list[AssessmentTask]:
        """Return tasks for a surface, highest scheduling priority first."""
        tasks = [task for task in self._tasks.values() if task.surface_key == surface_key]
        return sorted(tasks, key=lambda task: (task.priority, task.created_at))

    def ready(self) -> list[AssessmentTask]:
        """Return actionable tasks ordered by scheduling priority (low = soon)."""
        tasks = [task for task in self._tasks.values() if task.status.is_actionable]
        return sorted(tasks, key=lambda task: (task.priority, task.created_at))

    def remaining(self) -> int:
        """Return the number of actionable tasks still in the queue."""
        return sum(1 for task in self._tasks.values() if task.status.is_actionable)

    def total(self) -> int:
        """Return the number of submitted tasks."""
        return len(self._tasks)

    def exhausted(self) -> bool:
        """Return ``True`` when no actionable assessment work remains."""
        return not any(task.status.is_actionable for task in self._tasks.values())

    def summary(self) -> dict[str, Any]:
        """Serialize a compact queue summary."""
        actionable = self.ready()
        by_status: dict[str, int] = {}
        for task in self._tasks.values():
            by_status[task.status.value] = by_status.get(task.status.value, 0) + 1
        return {
            "total": self.total(),
            "remaining": len(actionable),
            "by_status": by_status,
            "next": [task.to_dict() for task in actionable[:5]],
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the whole queue to a JSON-safe mapping."""
        return {"tasks": [task.to_dict() for task in self._tasks.values()]}


def schedule_assignments(
    queue: AssessmentQueue,
    assignments: Iterable[Any],
    *,
    mission_id: str,
    strategy: str = "differential",
) -> list[AssessmentTask]:
    """Submit one task per applicable assignment (returns the submitted tasks)."""
    tasks: list[AssessmentTask] = []
    for assignment in assignments:
        if not getattr(assignment, "applicable", True):
            continue
        priority = round(100.0 * (1.0 - max(0.0, min(1.0, float(getattr(assignment, "priority", 0.5))))), 2)
        tasks.append(
            queue.submit(
                surface_key=assignment.surface_key,
                capability_id=assignment.capability_id,
                context=assignment.context,
                mission_id=mission_id,
                strategy=strategy,
                priority=priority,
                assignment_id=assignment.assignment_id,
            )
        )
    return tasks


def queued_keys(tasks: Sequence[AssessmentTask]) -> list[str]:
    """Return the surface keys of a collection of tasks (deduplicated)."""
    return sorted({task.surface_key for task in tasks})


__all__ = ["AssessmentQueue", "queued_keys", "schedule_assignments"]
