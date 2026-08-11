# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Offensive Tool Orchestration — Target Intelligence Database entities.

System-of-record entities for the Wave 14 offensive tool orchestration
capability: execution plans, phases and steps, tool selections, execution
dependencies, execution checkpoints, policy decisions, replanning events,
coverage metrics, mission quality scores, mission failures and per-step task
history. Every orchestration fact that matters is persisted here — never only
in memory.

Security boundary: these tables store orchestration metadata, canonical
targets, tool selections and redacted evidence references only — never exploit
payloads, never credentials, never raw out-of-scope request material.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class MissionPlanRecord(TidbEntity):
    """A persisted execution plan for a mission.

    Attributes:
        plan_id: stable plan identifier.
        mission_id: owning mission.
        plan_version: plan version (incremented on replanning).
        objective: mission objective the plan fulfils.
        state: plan lifecycle state.
        scope: JSON-safe scope snapshot.
        policies: JSON-safe policy envelope snapshot.

    """

    plan_id: str
    mission_id: str = ""
    plan_version: int = 1
    objective: str = ""
    state: str = "planned"
    scope: dict[str, object] = field(default_factory=dict)
    policies: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class MissionPhaseRecord(TidbEntity):
    """A persisted mission phase.

    Attributes:
        phase_id: identifier unique within the plan.
        plan_id: owning plan.
        kind: canonical phase kind.
        name: human-readable phase name.
        order: position within the plan.
        parallel: whether the phase steps may run concurrently.
        optional: whether the planner may skip the phase.
        state: phase state.
        depends_on: ids of phases that must finish first.

    """

    phase_id: str
    plan_id: str = ""
    kind: str = "scope"
    name: str = ""
    order: int = 0
    parallel: bool = False
    optional: bool = False
    state: str = "pending"
    depends_on: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MissionStepRecord(TidbEntity):
    """A persisted mission step.

    Attributes:
        step_id: stable step identifier.
        plan_id: owning plan.
        phase_id: owning phase.
        action: logical action or tool id.
        capability: capability required for the step.
        tool_id: selected tool id (empty until selected).
        target / target_type: the assessed target.
        parameters: step parameters snapshot.
        depends_on: ids of steps that must finish first.
        condition: condition expression (empty = unconditional).
        state: step state.
        timeout_seconds: execution timeout.
        retryable: whether the step may be retried.
        safety_class: safety class of the step.
        evidence_requirements / success_criteria: canonical expectations.
        fallback_tools: ordered fallback tool ids.
        execution_id: last execution id for the step.
        started_at / completed_at: timestamps.
        duration_ms: last execution duration.
        error: last error message.

    """

    step_id: str
    plan_id: str = ""
    phase_id: str = ""
    action: str = ""
    capability: str = ""
    tool_id: str = ""
    target: str = ""
    target_type: str = ""
    parameters: dict[str, object] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    condition: str = ""
    state: str = "pending"
    timeout_seconds: float = 60.0
    retryable: bool = True
    safety_class: str = "passive"
    evidence_requirements: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)
    fallback_tools: list[str] = field(default_factory=list)
    execution_id: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class ExecutionDependency(TidbEntity):
    """A persisted execution dependency between steps.

    Attributes:
        dependency_id: stable record identifier.
        plan_id: owning plan.
        source_step_id: the step that must finish first.
        target_step_id: the step that depends on the source.
        kind: dependency kind (``finish-to-start``).

    """

    dependency_id: str
    plan_id: str = ""
    source_step_id: str = ""
    target_step_id: str = ""
    kind: str = "finish-to-start"


@dataclass(slots=True)
class ExecutionCheckpoint(TidbEntity):
    """A persisted mission checkpoint.

    Attributes:
        checkpoint_id: stable checkpoint identifier.
        plan_id: owning plan.
        mission_id: owning mission.
        checkpoint_version: checkpoint version.
        plan_version: plan version at checkpoint time.
        label: human-readable checkpoint label.
        state: JSON-safe mission/plan state snapshot.
        completed_steps: ids of steps completed at checkpoint time.

    """

    checkpoint_id: str
    plan_id: str = ""
    mission_id: str = ""
    checkpoint_version: int = 1
    plan_version: int = 1
    label: str = ""
    state: dict[str, object] = field(default_factory=dict)
    completed_steps: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExecutionPolicyDecision(TidbEntity):
    """A persisted gate decision before a task executes.

    Attributes:
        decision_id: stable record identifier.
        mission_id / plan_id / step_id: scoping identifiers.
        target: the target the decision concerned.
        kind: gate kind (``scope``, ``safety``, ``rate_limit``, ``tool``).
        allowed: whether the task was permitted.
        reason: human-readable reason.
        detail: structured detail map.

    """

    decision_id: str
    mission_id: str = ""
    plan_id: str = ""
    step_id: str = ""
    target: str = ""
    kind: str = "scope"
    allowed: bool = False
    reason: str = ""
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ToolSelectionRecord(TidbEntity):
    """A persisted tool selection for a step.

    Attributes:
        selection_id: stable record identifier.
        mission_id / plan_id / step_id: scoping identifiers.
        capability: capability the selection satisfies.
        tool_id: selected tool.
        alternative_tools: ordered fallback chain.
        score: selection score in ``[0, 1]``.
        reasons: selection rationale.
        fallback_of: primary tool this selection substitutes for.

    """

    selection_id: str
    mission_id: str = ""
    plan_id: str = ""
    step_id: str = ""
    capability: str = ""
    tool_id: str = ""
    alternative_tools: list[str] = field(default_factory=list)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    fallback_of: str = ""


@dataclass(slots=True)
class ToolFallback(TidbEntity):
    """A persisted tool fallback event.

    Attributes:
        fallback_id: stable record identifier.
        mission_id / plan_id / step_id: scoping identifiers.
        primary_tool: the tool that failed or was unavailable.
        fallback_tool: the tool substituted in.
        reason: fallback rationale.

    """

    fallback_id: str
    mission_id: str = ""
    plan_id: str = ""
    step_id: str = ""
    primary_tool: str = ""
    fallback_tool: str = ""
    reason: str = ""


@dataclass(slots=True)
class MissionReplan(TidbEntity):
    """A persisted mission replanning event.

    Attributes:
        replan_id: stable record identifier.
        mission_id / plan_id: scoping identifiers.
        reason: replanning rationale.
        previous_version: plan version before replanning.
        new_version: plan version after replanning.
        added_steps: steps added by the replan.
        removed_steps: steps removed by the replan.
        blocked_assets: assets blocked by the replan (out of scope).

    """

    replan_id: str
    mission_id: str = ""
    plan_id: str = ""
    reason: str = ""
    previous_version: int = 1
    new_version: int = 1
    added_steps: list[str] = field(default_factory=list)
    removed_steps: list[str] = field(default_factory=list)
    blocked_assets: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MissionCoverage(TidbEntity):
    """A persisted coverage metric.

    Attributes:
        coverage_id: stable record identifier.
        mission_id / plan_id: scoping identifiers.
        kind: coverage kind (``asset``, ``port``, ``technology``, ...).
        observed: number of attack-surface items observed.
        expected: number of items expected to be covered.
        covered: number of items covered.
        fraction: computed coverage fraction in ``[0, 1]``.

    """

    coverage_id: str
    mission_id: str = ""
    plan_id: str = ""
    kind: str = "asset"
    observed: int = 0
    expected: int = 0
    covered: int = 0
    fraction: float = 0.0


@dataclass(slots=True)
class MissionQuality(TidbEntity):
    """A persisted mission quality score.

    Attributes:
        quality_id: stable record identifier.
        mission_id / plan_id: scoping identifiers.
        score: overall mission quality in ``[0, 1]``.
        factors: JSON-safe factor breakdown.
        explainability: JSON-safe explanation.

    """

    quality_id: str
    mission_id: str = ""
    plan_id: str = ""
    score: float = 0.0
    factors: dict[str, object] = field(default_factory=dict)
    explainability: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class MissionFailure(TidbEntity):
    """A persisted classified mission/task failure.

    Attributes:
        failure_id: stable record identifier.
        mission_id / plan_id / step_id: scoping identifiers.
        execution_id: last execution id for the failed step.
        tool_id: tool that failed.
        target: the assessed target.
        failure_class: canonical failure classification.
        management: failure-management strategy applied.
        error: error message.
        retries: retries performed.

    """

    failure_id: str
    mission_id: str = ""
    plan_id: str = ""
    step_id: str = ""
    execution_id: str = ""
    tool_id: str = ""
    target: str = ""
    failure_class: str = "permanent"
    management: str = "blocked"
    error: str = ""
    retries: int = 0


@dataclass(slots=True)
class MissionTaskHistory(TidbEntity):
    """A persisted per-step task history entry.

    Attributes:
        history_id: stable record identifier.
        mission_id / plan_id / step_id: scoping identifiers.
        execution_id: execution id for this attempt.
        tool_id: tool executed.
        target: the assessed target.
        state: terminal task state.
        started_at / completed_at: timestamps.
        duration_ms: execution duration.
        error: error message on failure.

    """

    history_id: str
    mission_id: str = ""
    plan_id: str = ""
    step_id: str = ""
    execution_id: str = ""
    tool_id: str = ""
    target: str = ""
    state: str = "completed"
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int = 0
    error: str = ""
