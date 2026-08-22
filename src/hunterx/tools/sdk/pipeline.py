# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution pipeline.

Orchestrates the full lifecycle of one tool execution::

    register → install → validate → verify → prepare → execute
    → monitor → collect output → validate output → normalize → store
    → generate events → cleanup

Each stage is guarded so a failure produces a structured :class:`ExecutionResult`
with a classified failure kind instead of an unhandled exception.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from hunterx.domain.exceptions import (
    SandboxError,
    ToolCancellationError,
    ToolDependencyError,
    ToolHealthError,
    ToolLockError,
    ToolQueueError,
    ToolRetryableError,
    ToolTimeoutError,
)
from hunterx.domain.execution import (
    ExecutionContext,
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
    FailureKind,
    RetryPolicy,
)
from hunterx.plugins.manifest import PermissionFlag
from hunterx.tools.sdk import result as results
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.dependencies import DependencyResolver
from hunterx.tools.sdk.events import ExecutionEventBus
from hunterx.tools.sdk.health import HealthChecker
from hunterx.tools.sdk.monitor import ExecutionMonitor
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.sdk.resources import ResourceManager
from hunterx.tools.sdk.retry import RetryManager
from hunterx.tools.sdk.sandbox import ExecutionSandbox
from hunterx.tools.sdk.session import ExecutionSession
from hunterx.tools.sdk.timeout import TimeoutManager


@dataclass(slots=True)
class PipelineResult:
    """Outcome of running the pipeline for one execution.

    Attributes:
        result: the execution result produced by the lifecycle.
        session: the execution session (timing, artifacts, output summary).
        attempts: number of attempts actually executed.

    """

    result: ExecutionResult
    session: ExecutionSession
    attempts: int = 1


StageHook = Callable[[str, ExecutionContext, ExecutionResult | None], None]


class ExecutionPipeline:
    """Run one tool execution through every lifecycle stage.

    The pipeline is created by the execution engine with its dependencies and
    invoked with a ready execution context. Stage hooks allow observability
    (logging, metrics) without modifying the pipeline.
    """

    def __init__(
        self,
        *,
        adapter: ToolAdapter,
        sandbox: ExecutionSandbox,
        resources: ResourceManager,
        timeout: TimeoutManager,
        retry: RetryManager,
        dependencies: DependencyResolver,
        health: HealthChecker,
        monitor: ExecutionMonitor,
        events: ExecutionEventBus,
    ) -> None:
        self._adapter = adapter
        self._sandbox = sandbox
        self._resources = resources
        self._timeout = timeout
        self._retry = retry
        self._dependencies = dependencies
        self._health = health
        self._monitor = monitor
        self._events = events
        self._stage_hooks: list[StageHook] = []

    def on_stage(self, hook: StageHook) -> None:
        """Register a callback invoked before/after lifecycle stages."""
        self._stage_hooks.append(hook)

    def run(self, context: ExecutionContext) -> PipelineResult:
        """Execute the lifecycle for ``context`` and return the outcome.

        The pipeline never raises for execution failures; those are captured in
        the returned :class:`ExecutionResult`. Infrastructure misconfiguration
        surfaces as :class:`ExecutionError`.
        """
        session = ExecutionSession.create(context)
        attempt = 0
        policy = context.retry_policy or RetryPolicy()

        while True:
            attempt += 1
            self._notify_stage("begin", context, None)
            result = self._attempt(context, session)
            self._notify_stage("end", context, result)
            if result.status.is_success:
                return PipelineResult(result=result, session=session, attempts=attempt)
            if self._retry.eligible(policy, result.failure_kind, attempt - 1):
                delay = self._retry.delay_for(policy, attempt - 1)
                self._events.retried(context.execution_id, context.tool_id, attempt, result.failure_kind.value)
                if delay:
                    time.sleep(delay)
                continue
            return PipelineResult(result=result, session=session, attempts=attempt)

    # -- lifecycle ---------------------------------------------------------

    def _attempt(self, context: ExecutionContext, session: ExecutionSession) -> ExecutionResult:
        try:
            self._dependencies.assert_satisfied(context.tool_id)
            self._health.assert_healthy(context.tool_id, requirement=context.tool_version)
        except ToolDependencyError as error:
            return self._fail(context, session, FailureKind.MISSING_DEPENDENCY, error)
        except ToolHealthError as error:
            return self._fail(context, session, FailureKind.RETRYABLE, error)

        try:
            self._enforce_permissions(context)
        except SandboxError as error:
            return self._fail(context, session, FailureKind.SANDBOX_VIOLATION, error)

        session.begin()
        result = results.start_execution(results.new_result(context))
        self._events.started(context.execution_id, context.tool_id, context.correlation_id)
        self._monitor.report(context, status=ExecutionStatus.RUNNING, phase="execute")

        self._timeout.arm(context)
        output = OutputCollector()
        try:
            with self._resources.acquire(context):
                self._timeout.check(context)
                self._adapter.prepare(context)
                self._monitor.report(context, status=ExecutionStatus.RUNNING, phase="prepared")
                self._timeout.check(context)
                self._adapter.run(context, output)
                self._timeout.check(context)
        except ToolTimeoutError as error:
            return self._timeout_result(context, session, error)
        except ToolCancellationError as error:
            return self._fail(context, session, FailureKind.CANCELLED, error, status=ExecutionStatus.CANCELLED)
        except Exception as error:  # noqa: BLE001 - classified as execution failure
            return self._classify(context, session, result, error)

        collected = output.build()
        self._events.output_collected(
            context.execution_id,
            context.tool_id,
            [fmt.value for fmt in collected.formats],
            _output_size(collected),
        )
        self._monitor.report(context, status=ExecutionStatus.RUNNING, phase="collected")

        ok, errors = self._adapter.validate_output(context, collected)
        if not ok:
            # Attach the collected output so the failure carries the truthful
            # exit code / stdout / stderr. Previously the failure kept the
            # default (exit_code=0) output while the error text said
            # "exit code 1" — a contradiction in the report.
            return self._fail(
                context,
                session,
                FailureKind.OUTPUT_INVALID,
                Exception("; ".join(errors)),
                output=collected,
            )

        normalized = self._adapter.normalize(context, collected)
        self._events.normalization_complete(context.execution_id, context.tool_id, len(normalized.findings))
        self._monitor.report(context, status=ExecutionStatus.RUNNING, phase="normalized")
        result.normalized = True

        final = results.finish_success(result, collected)
        self._adapter.cleanup(context)
        results.mark_events(final)
        session.finish(final)
        self._events.completed(context.execution_id, context.tool_id, session.output_summary())
        self._monitor.report(context, status=final.status, phase="completed")
        return final

    def _enforce_permissions(self, context: ExecutionContext) -> None:
        """Ensure the execution grants every permission the adapter requests."""
        requested = getattr(self._adapter.descriptor, "permissions", ())
        for flag in requested:
            if flag:
                self._sandbox.enforce_permission(context, PermissionFlag(flag))

    def _classify(self, context: ExecutionContext, session: ExecutionSession, result: ExecutionResult, error: Exception) -> ExecutionResult:
        kind = _classify_failure(error)
        return self._fail(context, session, kind, error, result=result)

    def _timeout_result(self, context: ExecutionContext, session: ExecutionSession, error: ToolTimeoutError) -> ExecutionResult:
        self._events.timed_out(context.execution_id, context.tool_id, context.timeout_effective)
        return self._fail(
            context,
            session,
            FailureKind.TIMEOUT,
            error,
            status=ExecutionStatus.TIMED_OUT,
        )

    def _fail(
        self,
        context: ExecutionContext,
        session: ExecutionSession,
        kind: FailureKind,
        error: Exception,
        *,
        status: ExecutionStatus = ExecutionStatus.FAILED,
        result: ExecutionResult | None = None,
        output: ExecutionOutput | None = None,
    ) -> ExecutionResult:
        final = results.finish_failure(
            result or results.new_result(context),
            error=str(error),
            kind=kind,
            status=status,
            output=output,
        )
        session.finish(final)
        self._events.failed(context.execution_id, context.tool_id, kind.value, str(error))
        self._monitor.report(context, status=status, phase="failed")
        return final

    def _notify_stage(self, stage: str, context: ExecutionContext, result: ExecutionResult | None) -> None:
        for hook in self._stage_hooks:
            hook(stage, context, result)


def _classify_failure(error: Exception) -> FailureKind:
    """Map an exception to a retry/rollback policy failure kind."""
    if isinstance(error, ToolRetryableError):
        return FailureKind.RETRYABLE
    if isinstance(error, ToolLockError):
        return FailureKind.RETRYABLE
    if isinstance(error, ToolQueueError):
        return FailureKind.RETRYABLE
    if isinstance(error, SandboxError):
        return FailureKind.SANDBOX_VIOLATION
    if isinstance(error, ToolDependencyError):
        return FailureKind.MISSING_DEPENDENCY
    return FailureKind.NOT_RETRYABLE


def _output_size(output: ExecutionOutput) -> int:
    """Approximate captured output size in bytes (for telemetry)."""
    import json as _json

    size = len(output.stdout) + len(output.stderr) + len(output.xml) + len(output.txt) + len(output.yaml) + len(output.html)
    if output.json is not None:
        size += len(_json.dumps(output.json, default=str))
    size += sum(len(path) for path in output.files)
    size += sum(len(path) for path in output.screenshots)
    size += sum(len(path) for path in output.pcap_references)
    size += len(output.binary)
    return size
