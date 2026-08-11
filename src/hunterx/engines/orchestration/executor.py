# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission executor.

The executor walks the mission dependency graph and runs each step through the
Tool Integration SDK :class:`ExecutionEngine`, enforcing scope, safety and
rate-limit gates before every task, selecting tools capability-first, retrying
only retryable failures, falling back to capability-equivalent tools, and
collecting canonical results.

The executor never reasons directly over raw stdout: every result is produced
from the engine's normalized output (``ExecutionOutput.json``) and projected
into a canonical :class:`StepOutcome`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.orchestration.enums import FailureClass, MissionType, TaskState
from hunterx.domain.orchestration.models import ExecutionPlan, MissionStep
from hunterx.engines.orchestration.dedup import (
    ExecutionDeduplicator,
    ExecutionRecord,
    execution_hash,
)
from hunterx.engines.orchestration.fallback import FallbackDecision, FallbackEngine
from hunterx.engines.orchestration.graph import MissionDependencyGraph
from hunterx.engines.orchestration.ratelimit import RateLimiter, normalize_domain
from hunterx.engines.orchestration.retry import FailureReport, RetryEngine
from hunterx.engines.orchestration.safety import MissionSafetyEnforcer
from hunterx.engines.orchestration.scope import MissionScopeGuard
from hunterx.engines.orchestration.selector import MissionToolSelector
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine


@dataclass(slots=True)
class StepOutcome:
    """The canonical outcome of one executed step.

    Attributes:
        step_id: the executed step.
        state: terminal :class:`TaskState`.
        tool_id: the tool that ran (primary or fallback).
        execution_id: the execution id produced by the engine.
        duration_ms: execution duration.
        output: the normalized JSON output (canonical result).
        error: error message on failure.
        failure_class: canonical failure classification.
        evidence_count: number of evidence records in the output.
        findings_count: number of findings in the output.
        deduplicated: whether the step reused a cached execution.
        fallback: the fallback decision applied (when any).
        started_at / completed_at: timestamps.

    """

    step_id: str = ""
    state: TaskState = TaskState.COMPLETED
    tool_id: str = ""
    execution_id: str = ""
    duration_ms: int = 0
    output: dict[str, Any] | None = None
    error: str = ""
    failure_class: FailureClass = FailureClass.PERMANENT
    evidence_count: int = 0
    findings_count: int = 0
    deduplicated: bool = False
    fallback: FallbackDecision | None = None
    started_at: str = field(default_factory=utcnow_iso)
    completed_at: str = field(default_factory=utcnow_iso)

    @property
    def ok(self) -> bool:
        """Return ``True`` when the step completed successfully."""
        return self.state is TaskState.COMPLETED

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "step_id": self.step_id,
            "state": self.state.value,
            "tool_id": self.tool_id,
            "execution_id": self.execution_id,
            "duration_ms": self.duration_ms,
            "output": self.output,
            "error": self.error,
            "failure_class": self.failure_class.value,
            "evidence_count": self.evidence_count,
            "findings_count": self.findings_count,
            "deduplicated": self.deduplicated,
            "fallback": self.fallback.__dict__ if self.fallback else None,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass(slots=True)
class MissionRunResult:
    """The aggregate outcome of running a mission plan.

    Attributes:
        mission_id: owning mission.
        plan_id: the executed plan.
        outcomes: per-step outcomes keyed by step id.
        completed: step ids that completed successfully.
        failed: step ids that failed.
        blocked: step ids that were blocked by gates.
        deduplicated: step ids that reused cached executions.
        gaps: canonical mission gaps (blocked/failed steps).

    """

    mission_id: str = ""
    plan_id: str = ""
    outcomes: dict[str, StepOutcome] = field(default_factory=dict)
    completed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    deduplicated: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    @property
    def all_completed(self) -> bool:
        """Return ``True`` when every step completed (no failures/blocked)."""
        return not self.failed and not self.blocked

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "outcomes": {step_id: outcome.to_dict() for step_id, outcome in self.outcomes.items()},
            "completed": list(self.completed),
            "failed": list(self.failed),
            "blocked": list(self.blocked),
            "deduplicated": list(self.deduplicated),
            "gaps": list(self.gaps),
        }


class MissionExecutor:
    """Executes a mission plan through the Tool Integration SDK.

    Usage::

        executor = MissionExecutor(engine=engine, tip=tip)
        result = executor.run(mission_id="m1", plan=plan, scope=scope)
        result.all_completed  # True when every step succeeded

    The executor records scope and safety decisions, tool selections,
    deduplication and failures so the orchestration engine can persist them.
    """

    def __init__(
        self,
        engine: ExecutionEngine | None = None,
        tip: Any | None = None,
        selector: MissionToolSelector | None = None,
        guard: MissionScopeGuard | None = None,
        safety: MissionSafetyEnforcer | None = None,
        rate_limiter: RateLimiter | None = None,
        retry: RetryEngine | None = None,
        fallback: FallbackEngine | None = None,
        deduplicator: ExecutionDeduplicator | None = None,
        *,
        freshness_window_seconds: int = 0,
    ) -> None:
        self._engine = engine
        self._selector = selector or MissionToolSelector(tip=tip, engine=engine)
        self._guard = guard or MissionScopeGuard()
        self._safety = safety or MissionSafetyEnforcer()
        self._rate_limiter = rate_limiter or RateLimiter()
        self._retry = retry or RetryEngine()
        self._fallback = fallback or FallbackEngine(self._selector)
        self._deduplicator = deduplicator or ExecutionDeduplicator(
            freshness_window_seconds=freshness_window_seconds
        )
        self._decisions: list[dict[str, object]] = []
        self._selections: list[dict[str, object]] = []
        self._failures: list[dict[str, object]] = []
        self._fallbacks: list[dict[str, object]] = []

    # -- public API ----------------------------------------------------------

    def run(
        self,
        *,
        mission_id: str,
        plan: ExecutionPlan,
        tool_outputs: dict[str, dict[str, Any]] | None = None,
        stop_check: Any = None,
    ) -> MissionRunResult:
        """Execute a plan and return the aggregate outcome.

        Args:
            mission_id: owning mission id.
            plan: the plan to execute.
            tool_outputs: pre-normalized outputs keyed by step id (for
                deterministic tests); steps without an entry execute the tool.
            stop_check: callable returning a stop reason string when a stop
                condition triggers (``None`` = never stop).

        """
        self._guard = MissionScopeGuard(plan.scope)
        self._safety = MissionSafetyEnforcer(plan.policies.execution_policy, plan.policies.safety)
        self._rate_limiter = RateLimiter(plan.policies.rate_limit)
        self._retry = RetryEngine(policy=plan.policies.retry)
        self._clear_records()
        self._safety = MissionSafetyEnforcer(plan.policies.execution_policy, plan.policies.safety)

        graph = MissionDependencyGraph(plan)
        result = MissionRunResult(mission_id=mission_id, plan_id=plan.plan_id)
        completed: set[str] = set()
        skipped: set[str] = set()

        while True:
            if stop_check is not None:
                stop = stop_check()
                if stop is not None:
                    result.gaps.append(f"stopped: {stop}")
                    break
            ready = graph.ready(completed, skipped=skipped)
            if not ready:
                break
            for step_id in ready:
                step = graph.step(step_id)
                if step is None:
                    result.failed.append(step_id)
                    result.gaps.append(step_id)
                    continue
                outcome = self._execute_step(
                    plan, step,
                    mission_id=mission_id,
                    tool_outputs=tool_outputs,
                )
                result.outcomes[step_id] = outcome
                if outcome.state is TaskState.COMPLETED:
                    completed.add(step_id)
                    result.completed.append(step_id)
                    if outcome.deduplicated:
                        result.deduplicated.append(step_id)
                elif outcome.state is TaskState.BLOCKED:
                    skipped.add(step_id)
                    result.blocked.append(step_id)
                    result.gaps.append(step_id)
                else:
                    skipped.add(step_id)
                    result.failed.append(step_id)
                    result.gaps.append(step_id)
        return result

    def records(self) -> dict[str, list[dict[str, object]]]:
        """Return the gate records collected during the run.

        Returns:
            A mapping with ``scope``, ``safety``, ``rate_limit``, ``selection``,
            ``fallback`` and ``failure`` record lists.

        """
        return {
            "scope": [d for d in self._decisions if d["kind"] == "scope"],
            "safety": [d for d in self._decisions if d["kind"] == "safety"],
            "rate_limit": [d for d in self._decisions if d["kind"] == "rate_limit"],
            "selection": list(self._selections),
            "fallback": list(self._fallbacks),
            "failure": list(self._failures),
        }

    # -- step execution ------------------------------------------------------

    def _execute_step(
        self,
        plan: ExecutionPlan,
        step: MissionStep,
        *,
        mission_id: str,
        tool_outputs: dict[str, dict[str, Any]] | None,
    ) -> StepOutcome:
        started = utcnow_iso()

        # 1) Scope guard before every task.
        decision = self._guard.decides(step.target)
        self._record_decision("scope", step, decision, mission_id, plan.plan_id)
        if not decision.allowed:
            return StepOutcome(
                step_id=step.step_id,
                state=TaskState.BLOCKED,
                error=f"scope blocked: {decision.reason}",
                failure_class=FailureClass.SCOPE_FAILURE,
                started_at=started,
            )

        # 2) Safety gate before every task.
        safety = self._safety.decides(
            action=f"{step.action} {step.capability}".strip(),
            safety_class=step.safety_class,
            parameters=step.parameters,
        )
        self._record_decision("safety", step, safety, mission_id, plan.plan_id)
        if not safety.allowed:
            return StepOutcome(
                step_id=step.step_id,
                state=TaskState.BLOCKED,
                error=f"safety blocked: {safety.reason}",
                failure_class=FailureClass.SAFETY_FAILURE,
                started_at=started,
            )

        # 3) Rate limit before every task.
        rate = self._rate_limiter.allows(
            mission_id=mission_id,
            target=step.target,
            domain=normalize_domain(step.target),
            ip=_ip_of(step.target),
            tool_id=step.tool_id,
        )
        self._record_decision("rate_limit", step, rate, mission_id, plan.plan_id)
        if not rate.allowed:
            return StepOutcome(
                step_id=step.step_id,
                state=TaskState.BLOCKED,
                error=f"rate limited: {rate.reason}",
                failure_class=FailureClass.RATE_LIMIT,
                started_at=started,
            )

        # 4) Pre-normalized output shortcut (deterministic path).
        if tool_outputs is not None and step.step_id in tool_outputs:
            output = tool_outputs[step.step_id]
            return StepOutcome(
                step_id=step.step_id,
                state=TaskState.COMPLETED,
                tool_id=step.tool_id,
                output=output,
                evidence_count=_count_records(output, "evidence"),
                findings_count=_count_records(output, "findings"),
                started_at=started,
                completed_at=utcnow_iso(),
            )

        # 5) Select a tool (primary, then fallback on failure/unavailability).
        selection = self._select_tool(step, mission_id, plan)
        if selection is None:
            return StepOutcome(
                step_id=step.step_id,
                state=TaskState.FAILED,
                error=f"no tool available for capability '{step.capability}'",
                failure_class=FailureClass.TOOL_CRASH,
                started_at=started,
            )
        tool_id = selection
        self._selections.append(
            {
                "step_id": step.step_id,
                "tool_id": tool_id,
                "capability": step.capability,
                "mission_id": mission_id,
                "plan_id": plan.plan_id,
            }
        )

        # 6) Deduplicate identical executions within the freshness window.
        if self._engine is not None:
            input_hash = execution_hash(tool_id=tool_id, target=step.target, parameters=step.parameters)
            cached = self._deduplicator.lookup(input_hash)
            if cached is not None:
                return StepOutcome(
                    step_id=step.step_id,
                    state=TaskState.COMPLETED,
                    tool_id=tool_id,
                    execution_id=cached.execution_id,
                    deduplicated=True,
                    output=cached.result_summary,
                    started_at=started,
                    completed_at=utcnow_iso(),
                )

        # 7) Execute with retry/fallback loop.
        outcome = self._execute_with_retry(step, tool_id, mission_id, plan, started)
        if outcome.ok and outcome.execution_id and self._engine is not None:
            self._deduplicator.record(
                ExecutionRecord(
                    execution_id=outcome.execution_id,
                    input_hash=execution_hash(tool_id=tool_id, target=step.target, parameters=step.parameters),
                    tool_id=tool_id,
                    target=step.target,
                    result_summary=outcome.output or {},
                )
            )
        return outcome

    def _execute_with_retry(
        self,
        step: MissionStep,
        tool_id: str,
        mission_id: str,
        plan: ExecutionPlan,
        started: str,
    ) -> StepOutcome:
        attempt = 0
        while True:
            outcome = self._attempt(step, tool_id, mission_id, plan, started)
            if outcome.ok or not self._retry.should_retry(_report_of(outcome)):
                return outcome
            attempt += 1
            # Fall back to an alternative tool after retries are exhausted.
            if attempt >= plan.policies.retry.retries():
                fallback_decision = self._fallback.select_fallback(
                    step_id=step.step_id,
                    primary=tool_id,
                    need=_need_of(step),
                    mission_type=_mission_type_of(plan),
                    policy=plan.policies.tool,
                )
                if fallback_decision.fallback_tool:
                    self._fallbacks.append(
                        {
                            "step_id": step.step_id,
                            "primary_tool": tool_id,
                            "fallback_tool": fallback_decision.fallback_tool,
                            "reason": fallback_decision.reason,
                        }
                    )
                    tool_id = fallback_decision.fallback_tool
                    continue
                return outcome
            self._failures.append(
                {
                    "step_id": step.step_id,
                    "tool_id": tool_id,
                    "error": outcome.error,
                    "failure_class": outcome.failure_class.value,
                    "retry": attempt,
                }
            )

    def _attempt(
        self,
        step: MissionStep,
        tool_id: str,
        mission_id: str,
        plan: ExecutionPlan,
        started: str,
    ) -> StepOutcome:
        if self._engine is None:
            return StepOutcome(
                step_id=step.step_id,
                state=TaskState.FAILED,
                error="execution engine unavailable",
                tool_id=tool_id,
                started_at=started,
                completed_at=utcnow_iso(),
            )
        context = self._build_context(step, tool_id, mission_id, plan)
        try:
            pipeline = self._engine.execute(context)
        except Exception as exc:  # noqa: BLE001 - surfaced as a classified failure
            report = self._retry.report(error=str(exc))
            return _outcome_from_report(step, tool_id, report, started)
        result = pipeline.result
        report = self._retry.report(
            status=result.status,
            failure_kind=result.failure_kind,
            error=result.error,
        )
        if not result.status.is_success:
            return _outcome_from_report(step, tool_id, report, started, execution_id=result.execution_id)
        output = result.output.json if isinstance(result.output.json, dict) else {}
        return StepOutcome(
            step_id=step.step_id,
            state=TaskState.COMPLETED,
            tool_id=tool_id,
            execution_id=result.execution_id,
            duration_ms=max(0, result.duration_ms),
            output=output,
            evidence_count=_count_records(output, "evidence"),
            findings_count=_count_records(output, "findings"),
            started_at=started,
            completed_at=utcnow_iso(),
        )

    def _build_context(self, step: MissionStep, tool_id: str, mission_id: str, plan: ExecutionPlan) -> ExecutionContext:
        parameters = dict(step.parameters)
        parameters.setdefault("target", step.target)
        permissions = _permissions_for(step.safety_class)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=step.target)
            .with_mission(mission_id)
            .with_target_type(step.target_type)
            .with_profile(plan.policies.execution_policy.value)
            .with_correlation_id(generate_id())
            .with_permissions(permissions)
            .with_timeout(step.timeout_seconds)
            .with_parameters(parameters)
            .build()
        )

    # -- tool selection ------------------------------------------------------

    def _select_tool(self, step: MissionStep, mission_id: str, plan: ExecutionPlan) -> str | None:
        if step.tool_id:
            return step.tool_id
        if not step.capability:
            return None
        need = _need_of(step)
        try:
            result = self._selector.select_primary(need, mission_type=_mission_type_of(plan), policy=plan.policies.tool)
            return result.tool_id
        except Exception:  # noqa: BLE001 - no candidate means no tool
            return None

    # -- record keeping ------------------------------------------------------

    def _record_decision(self, kind: str, step: MissionStep, decision: Any, mission_id: str, plan_id: str) -> None:
        detail = decision.to_dict() if hasattr(decision, "to_dict") else {"allowed": bool(decision)}
        self._decisions.append(
            {
                "kind": kind,
                "step_id": step.step_id,
                "mission_id": mission_id,
                "plan_id": plan_id,
                "target": step.target,
                "allowed": bool(getattr(decision, "allowed", True)),
                "reason": str(getattr(decision, "reason", "")),
                "detail": detail,
            }
        )

    def _clear_records(self) -> None:
        self._decisions = []
        self._selections = []
        self._failures = []
        self._fallbacks = []


# -- module helpers -----------------------------------------------------------


def _report_of(outcome: StepOutcome) -> FailureReport:
    return FailureReport(
        failure_class=outcome.failure_class,
        error=outcome.error,
        retryable=outcome.failure_class.retryable,
    )


def _outcome_from_report(
    step: MissionStep,
    tool_id: str,
    report: FailureReport,
    started: str,
    *,
    execution_id: str = "",
) -> StepOutcome:
    state = TaskState.BLOCKED if report.failure_class in (
        FailureClass.SCOPE_FAILURE,
        FailureClass.SAFETY_FAILURE,
    ) else TaskState.FAILED
    return StepOutcome(
        step_id=step.step_id,
        state=state,
        tool_id=tool_id,
        execution_id=execution_id,
        error=report.error or f"{report.failure_class.value} failure",
        failure_class=report.failure_class,
        started_at=started,
        completed_at=utcnow_iso(),
    )


def _need_of(step: MissionStep) -> Any:
    from hunterx.domain.orchestration.selection import CapabilityNeed

    return CapabilityNeed(
        capability=step.capability,
        target_type=step.target_type,
        safety_class=step.safety_class,
    )


def _mission_type_of(plan: ExecutionPlan) -> MissionType:
    from hunterx.domain.orchestration.enums import MissionType

    objective = (plan.objective or "").lower()
    if "api" in objective:
        return MissionType.API_PENTEST
    if "cloud" in objective:
        return MissionType.CLOUD_ASSESSMENT
    if "bug" in objective or "bounty" in objective:
        return MissionType.BUG_BOUNTY
    return MissionType.VULNERABILITY_ASSESSMENT


def _count_records(output: dict[str, Any] | None, kind: str) -> int:
    if not isinstance(output, dict):
        return 0
    value = output.get(kind)
    if isinstance(value, list):
        return len(value)
    return 0


def _permissions_for(safety_class: str) -> tuple[str, ...]:
    return {
        "passive": ("none",),
        "read_only": ("network",),
        "benign_marker": ("network",),
        "controlled": ("network",),
    }.get(safety_class, ("none",))


def _ip_of(target: str) -> str:
    import ipaddress

    value = target.strip()
    if "://" in value:
        from urllib.parse import urlparse

        value = urlparse(value).netloc or value
    value = value.split("/", 1)[0].split(":", 1)[0].strip("[]")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return ""
