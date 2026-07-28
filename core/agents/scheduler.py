from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..utils import logger

from .events import EventBus, EventType
from .registry import AgentRegistry
from .state import StateManager
from .task import AgentTask, TaskPriority, TaskStatus


@dataclass
class ScheduleEntry:
    task: AgentTask
    scheduled_at: float = 0.0
    priority_score: float = 0.0


class AgentScheduler:
    def __init__(
        self,
        registry: Optional[AgentRegistry] = None,
        state_manager: Optional[StateManager] = None,
        event_bus: Optional[EventBus] = None,
    ):
        self._registry = registry or AgentRegistry()
        self._state_manager = state_manager or StateManager()
        self._event_bus = event_bus or EventBus()
        self._lock = threading.RLock()
        self._queue: List[ScheduleEntry] = []
        self._running: bool = False
        self._worker: Optional[threading.Thread] = None
        self._max_concurrent: int = 5
        self._active_tasks: Dict[str, threading.Thread] = {}

    @property
    def running(self) -> bool:
        return self._running

    def schedule(self, task: AgentTask) -> None:
        with self._lock:
            score = self._calculate_priority(task)
            entry = ScheduleEntry(task=task, priority_score=score)
            self._queue.append(entry)
            self._queue.sort(key=lambda e: e.priority_score, reverse=True)
            task.status = TaskStatus.SCHEDULED
            logger.info(f"Scheduler: queued task {task.id[:8]} for agent {task.agent_id[:8]} (priority={task.priority.name})")

    def schedule_batch(self, tasks: List[AgentTask]) -> None:
        for task in tasks:
            self.schedule(task)

    def start(self, max_concurrent: int = 5) -> None:
        self._max_concurrent = max_concurrent
        self._running = True
        self._worker = threading.Thread(target=self._process_loop, daemon=True, name="scheduler")
        self._worker.start()
        logger.info(f"Scheduler: started with max_concurrent={max_concurrent}")

    def stop(self) -> None:
        self._running = False
        logger.info("Scheduler: stopped")

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            for entry in self._queue:
                if entry.task.id == task_id:
                    entry.task.status = TaskStatus.CANCELLED
                    self._queue.remove(entry)
                    return True
            if task_id in self._active_tasks:
                self._active_tasks[task_id].id  # mark
                return True
            return False

    def get_queue(self) -> List[AgentTask]:
        with self._lock:
            return [e.task for e in self._queue]

    def get_active_count(self) -> int:
        with self._lock:
            return len(self._active_tasks)

    def _process_loop(self) -> None:
        while self._running:
            try:
                self._process_next()
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

    def _process_next(self) -> None:
        with self._lock:
            if len(self._active_tasks) >= self._max_concurrent:
                return
            if not self._queue:
                return

            ready = []
            for entry in self._queue:
                if self._dependencies_met(entry.task):
                    ready.append(entry)

            if not ready:
                return

            entry = ready[0]
            self._queue.remove(entry)
            task = entry.task
            task.status = TaskStatus.RUNNING

            thread = threading.Thread(
                target=self._execute_task,
                args=(task,),
                daemon=True,
                name=f"task-{task.id[:8]}",
            )
            self._active_tasks[task.id] = thread
            thread.start()

    def _execute_task(self, task: AgentTask) -> None:
        self._event_bus.publish_event(EventType.TASK_STARTED, "scheduler", {"task_id": task.id})
        agent = self._registry.get(task.agent_id)

        if not agent:
            task.status = TaskStatus.FAILED
            task.error = f"Agent {task.agent_id} not found"
            self._event_bus.publish_event(EventType.TASK_FAILED, "scheduler", {"task_id": task.id, "error": task.error})
            with self._lock:
                self._active_tasks.pop(task.id, None)
            return

        try:
            result = agent.execute(task.goal)
            task.result = result
            task.status = TaskStatus.COMPLETED
            self._event_bus.publish_event(EventType.TASK_FINISHED, "scheduler", {"task_id": task.id})
        except Exception as e:
            task.error = str(e)
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.SCHEDULED
                with self._lock:
                    score = self._calculate_priority(task)
                    self._queue.append(ScheduleEntry(task=task, priority_score=score))
                    self._queue.sort(key=lambda e: e.priority_score, reverse=True)
                logger.info(f"Scheduler: requeued task {task.id[:8]} (retry {task.retry_count}/{task.max_retries})")
            else:
                task.status = TaskStatus.FAILED
                self._event_bus.publish_event(EventType.TASK_FAILED, "scheduler", {"task_id": task.id, "error": task.error})
        finally:
            with self._lock:
                self._active_tasks.pop(task.id, None)

    def _dependencies_met(self, task: AgentTask) -> bool:
        for dep_id in task.depends_on:
            for entry in self._queue:
                if entry.task.id == dep_id and entry.task.status != TaskStatus.COMPLETED:
                    return False
        return True

    def _calculate_priority(self, task: AgentTask) -> float:
        base = {
            TaskPriority.CRITICAL: 1000,
            TaskPriority.HIGH: 500,
            TaskPriority.MEDIUM: 100,
            TaskPriority.LOW: 50,
            TaskPriority.INFO: 10,
        }.get(task.priority, 100)

        retry_bonus = task.retry_count * 50
        return float(base + retry_bonus)
