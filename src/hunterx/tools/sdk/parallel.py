# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parallel execution manager.

Runs multiple execution units concurrently under the resource manager's
parallel-jobs cap. Each unit is a ``Callable[[ExecutionContext], ExecutionResult]``
so the manager stays decoupled from the pipeline internals.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor

from hunterx.domain.execution import ExecutionContext, ExecutionResult

ParallelUnit = Callable[[ExecutionContext], ExecutionResult]


class ParallelExecutionManager:
    """Run execution units concurrently, bounded by a worker pool.

    Usage::

        manager = ParallelExecutionManager(max_workers=4)
        futures = [manager.submit(run_fn, context) for context in contexts]
        results = manager.collect(futures)
    """

    def __init__(self, max_workers: int = 0) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers if max_workers > 0 else 1,
            thread_name_prefix="hx-parallel",
        )

    def submit(self, unit: ParallelUnit, context: ExecutionContext) -> Future[ExecutionResult]:
        """Schedule ``unit`` for ``context`` and return its future."""
        return self._executor.submit(unit, context)

    def collect(self, futures: list[Future[ExecutionResult]]) -> list[ExecutionResult]:
        """Return results for ``futures`` in submission order.

        Individual unit failures propagate as the corresponding future's
        exception, matching sequential semantics.
        """
        results: list[ExecutionResult] = []
        for future in futures:
            try:
                results.append(future.result())
            except Exception as error:  # noqa: BLE001 - surfaced to the caller
                raise error
        return results

    def shutdown(self) -> None:
        """Release the worker pool."""
        self._executor.shutdown(wait=True, cancel_futures=False)
