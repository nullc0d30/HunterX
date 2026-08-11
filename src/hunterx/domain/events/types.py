# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Domain events raised by engine and application layers.

These are convenience constructors for the canonical event types defined by
the platform. Publishing a typed event keeps payload schemas consistent across
producers.
"""

from __future__ import annotations

from enum import Enum

from hunterx.domain.events import DomainEvent


class EventType(Enum):
    """Canonical event types emitted by the execution pipeline."""

    EXECUTION_STARTED = "execution.started"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_FAILED = "execution.failed"
    EXECUTION_TIMED_OUT = "execution.timed_out"
    EXECUTION_RETRIED = "execution.retried"
    OUTPUT_COLLECTED = "output.collected"
    NORMALIZATION_COMPLETE = "normalization.complete"
    DATABASE_UPDATED = "database.updated"
    TOOL_EXECUTED = "tool.executed"
    TOOL_EXECUTION_STARTED = "tool.execution.started"
    TOOL_EXECUTION_COMPLETED = "tool.execution.completed"
    TOOL_EXECUTION_FAILED = "tool.execution.failed"
    TOOL_OUTPUT_RECEIVED = "tool.output.received"
    TOOL_OUTPUT_PARSED = "tool.output.parsed"
    TOOL_OUTPUT_NORMALIZED = "tool.output.normalized"
    TOOL_EVIDENCE_EXTRACTED = "tool.evidence.extracted"
    TOOL_OBSERVATION_CREATED = "tool.observation.created"
    TOOL_RESULT_CONTRADICTION = "tool.result.contradiction"
    TOOL_HEALTH_FAILED = "tool.health.failed"
    TOOL_VERSION_DETECTED = "tool.version.detected"
    TOOL_RECOMMENDATION_CREATED = "tool.recommendation.created"


class MissionStartedEvent(DomainEvent):
    """Emitted when a mission transitions to RUNNING."""

    def __init__(self, mission_id: str, *, source: str = "mission.engine") -> None:
        super().__init__(
            event_type="mission.started",
            payload={"mission_id": mission_id},
            source=source,
        )


class MissionCompletedEvent(DomainEvent):
    """Emitted when a mission finishes successfully."""

    def __init__(self, mission_id: str, *, source: str = "mission.engine") -> None:
        super().__init__(
            event_type="mission.completed",
            payload={"mission_id": mission_id},
            source=source,
        )


class MissionFailedEvent(DomainEvent):
    """Emitted when a mission fails."""

    def __init__(self, mission_id: str, error: str, *, source: str = "mission.engine") -> None:
        super().__init__(
            event_type="mission.failed",
            payload={"mission_id": mission_id, "error": error},
            source=source,
        )


class MissionScopingStartedEvent(DomainEvent):
    """Emitted when mission scope resolution begins."""

    def __init__(self, mission_id: str, *, mission_type: str = "", source: str = "orchestration") -> None:
        super().__init__(
            event_type="mission.scoping.started",
            payload={"mission_id": mission_id, "mission_type": mission_type},
            source=source,
            mission_id=mission_id,
        )


class MissionScopingCompletedEvent(DomainEvent):
    """Emitted when mission scope resolution completes."""

    def __init__(
        self,
        mission_id: str,
        *,
        roots: list[str] | None = None,
        excludes: list[str] | None = None,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.scoping.completed",
            payload={
                "mission_id": mission_id,
                "roots": roots or [],
                "excludes": excludes or [],
            },
            source=source,
            mission_id=mission_id,
        )


class MissionPlanningStartedEvent(DomainEvent):
    """Emitted when mission planning begins."""

    def __init__(self, mission_id: str, *, objective: str = "", source: str = "orchestration") -> None:
        super().__init__(
            event_type="mission.planning.started",
            payload={"mission_id": mission_id, "objective": objective},
            source=source,
            mission_id=mission_id,
        )


class MissionPlanCreatedEvent(DomainEvent):
    """Emitted when an execution plan is created."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        phases: int = 0,
        steps: int = 0,
        version: int = 1,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.plan.created",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "phases": phases,
                "steps": steps,
                "version": version,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionPhaseStartedEvent(DomainEvent):
    """Emitted when a mission phase begins."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        phase_id: str,
        *,
        phase_kind: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.phase.started",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "phase_id": phase_id,
                "phase_kind": phase_kind,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionPhaseCompletedEvent(DomainEvent):
    """Emitted when a mission phase completes."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        phase_id: str,
        *,
        steps_completed: int = 0,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.phase.completed",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "phase_id": phase_id,
                "steps_completed": steps_completed,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionStepStartedEvent(DomainEvent):
    """Emitted when a mission step begins."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        *,
        phase_id: str = "",
        capability: str = "",
        target: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.step.started",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "phase_id": phase_id,
                "capability": capability,
                "target": target,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionStepCompletedEvent(DomainEvent):
    """Emitted when a mission step completes."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        *,
        tool_id: str = "",
        execution_id: str = "",
        duration_ms: int = 0,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.step.completed",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool_id": tool_id,
                "execution_id": execution_id,
                "duration_ms": duration_ms,
            },
            source=source,
            mission_id=mission_id,
            execution_id=execution_id or None,
        )


class MissionStepFailedEvent(DomainEvent):
    """Emitted when a mission step fails."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        error: str,
        *,
        tool_id: str = "",
        failure_class: str = "permanent",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.step.failed",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool_id": tool_id,
                "error": error,
                "failure_class": failure_class,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionStepBlockedEvent(DomainEvent):
    """Emitted when a mission step is blocked by a gate decision."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        *,
        kind: str = "scope",
        reason: str = "",
        target: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.step.blocked",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "kind": kind,
                "reason": reason,
                "target": target,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionToolSelectedEvent(DomainEvent):
    """Emitted when a tool is selected for a step."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        tool_id: str,
        *,
        capability: str = "",
        score: float = 0.0,
        fallback_of: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.tool.selected",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool_id": tool_id,
                "capability": capability,
                "score": score,
                "fallback_of": fallback_of,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionToolStartedEvent(DomainEvent):
    """Emitted when a selected tool begins executing."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        tool_id: str,
        *,
        execution_id: str = "",
        target: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.tool.started",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool_id": tool_id,
                "execution_id": execution_id,
                "target": target,
            },
            source=source,
            mission_id=mission_id,
            execution_id=execution_id or None,
        )


class MissionToolCompletedEvent(DomainEvent):
    """Emitted when a selected tool completes executing."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        tool_id: str,
        *,
        execution_id: str = "",
        duration_ms: int = 0,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.tool.completed",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool_id": tool_id,
                "execution_id": execution_id,
                "duration_ms": duration_ms,
            },
            source=source,
            mission_id=mission_id,
            execution_id=execution_id or None,
        )


class MissionToolFailedEvent(DomainEvent):
    """Emitted when a selected tool fails."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        tool_id: str,
        error: str,
        *,
        execution_id: str = "",
        failure_class: str = "permanent",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.tool.failed",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool_id": tool_id,
                "error": error,
                "execution_id": execution_id,
                "failure_class": failure_class,
            },
            source=source,
            mission_id=mission_id,
            execution_id=execution_id or None,
        )


class MissionToolFallbackEvent(DomainEvent):
    """Emitted when a step falls back to an alternative tool."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        primary_tool: str,
        fallback_tool: str,
        *,
        reason: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.tool.fallback",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "primary_tool": primary_tool,
                "fallback_tool": fallback_tool,
                "reason": reason,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionResultCreatedEvent(DomainEvent):
    """Emitted when a canonical step result is produced."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        step_id: str,
        *,
        tool_id: str = "",
        execution_id: str = "",
        findings: int = 0,
        evidence: int = 0,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.result.created",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool_id": tool_id,
                "execution_id": execution_id,
                "findings": findings,
                "evidence": evidence,
            },
            source=source,
            mission_id=mission_id,
            execution_id=execution_id or None,
        )


class MissionIntelligenceUpdatedEvent(DomainEvent):
    """Emitted when mission intelligence is updated from a step result."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        step_id: str = "",
        updates: dict[str, object] | None = None,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.intelligence.updated",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "updates": updates or {},
            },
            source=source,
            mission_id=mission_id,
        )


class MissionReplanningStartedEvent(DomainEvent):
    """Emitted when mission replanning begins."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        reason: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.replanning.started",
            payload={"mission_id": mission_id, "plan_id": plan_id, "reason": reason},
            source=source,
            mission_id=mission_id,
        )


class MissionReplannedEvent(DomainEvent):
    """Emitted when the mission plan is regenerated."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        previous_version: int = 1,
        new_version: int = 1,
        added_steps: list[str] | None = None,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.replanned",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "previous_version": previous_version,
                "new_version": new_version,
                "added_steps": added_steps or [],
            },
            source=source,
            mission_id=mission_id,
        )


class MissionCheckpointCreatedEvent(DomainEvent):
    """Emitted when a mission checkpoint is persisted."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        checkpoint_id: str,
        *,
        label: str = "",
        completed_steps: list[str] | None = None,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.checkpoint.created",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "checkpoint_id": checkpoint_id,
                "label": label,
                "completed_steps": completed_steps or [],
            },
            source=source,
            mission_id=mission_id,
        )


class MissionResumedEvent(DomainEvent):
    """Emitted when a mission resumes from a checkpoint."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        checkpoint_id: str = "",
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.resumed",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "checkpoint_id": checkpoint_id,
            },
            source=source,
            mission_id=mission_id,
        )


class MissionBlockedEvent(DomainEvent):
    """Emitted when a mission becomes blocked."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        reason: str,
        *,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.blocked",
            payload={"mission_id": mission_id, "plan_id": plan_id, "reason": reason},
            source=source,
            mission_id=mission_id,
        )


class MissionPartialEvent(DomainEvent):
    """Emitted when a mission completes partially with explicit gaps."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        gaps: list[str] | None = None,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.partial",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "gaps": gaps or [],
            },
            source=source,
            mission_id=mission_id,
        )


class MissionQualityComputedEvent(DomainEvent):
    """Emitted when the mission quality score is computed."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        score: float = 0.0,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.quality.computed",
            payload={"mission_id": mission_id, "plan_id": plan_id, "score": score},
            source=source,
            mission_id=mission_id,
        )


class MissionCoverageComputedEvent(DomainEvent):
    """Emitted when the mission coverage metrics are computed."""

    def __init__(
        self,
        mission_id: str,
        plan_id: str,
        *,
        coverage: dict[str, object] | None = None,
        source: str = "orchestration",
    ) -> None:
        super().__init__(
            event_type="mission.coverage.computed",
            payload={
                "mission_id": mission_id,
                "plan_id": plan_id,
                "coverage": coverage or {},
            },
            source=source,
            mission_id=mission_id,
        )


class FindingCreatedEvent(DomainEvent):
    """Emitted when a new finding is accepted into the store."""

    def __init__(self, finding_id: str, mission_id: str, *, source: str = "finding.engine") -> None:
        super().__init__(
            event_type="finding.created",
            payload={"finding_id": finding_id, "mission_id": mission_id},
            source=source,
        )


class ToolExecutedEvent(DomainEvent):
    """Emitted when a tool completes an execution."""

    def __init__(
        self,
        tool: str,
        mission_id: str | None,
        *,
        succeeded: bool,
        duration_ms: int,
        source: str = "tool.executor",
    ) -> None:
        super().__init__(
            event_type="tool.executed",
            payload={
                "tool": tool,
                "mission_id": mission_id,
                "succeeded": succeeded,
                "duration_ms": duration_ms,
            },
            source=source,
        )


class ToolExecutionStartedEvent(DomainEvent):
    """Emitted when a tool execution begins (toolchain namespace)."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        mission_id: str = "",
        target_id: str = "",
        scope_id: str = "",
        *,
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_EXECUTION_STARTED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "scope_id": scope_id,
            },
            source=source,
        )


class ToolExecutionCompletedEvent(DomainEvent):
    """Emitted when a tool execution completes (toolchain namespace)."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        *,
        exit_code: int | None = None,
        semantics: str = "unknown",
        duration_ms: int = 0,
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_EXECUTION_COMPLETED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "exit_code": exit_code,
                "semantics": semantics,
                "duration_ms": duration_ms,
            },
            source=source,
        )


class ToolExecutionFailedEvent(DomainEvent):
    """Emitted when a tool execution fails (toolchain namespace)."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        *,
        failure_kind: str = "error",
        message: str = "",
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_EXECUTION_FAILED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "failure_kind": failure_kind,
                "message": message,
            },
            source=source,
        )


class ToolOutputReceivedEvent(DomainEvent):
    """Emitted when raw tool output is captured."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        *,
        formats: list[str] | None = None,
        size_bytes: int = 0,
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_OUTPUT_RECEIVED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "formats": formats or [],
                "size_bytes": size_bytes,
            },
            source=source,
        )


class ToolOutputParsedEvent(DomainEvent):
    """Emitted when tool output is parsed into structured records."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        *,
        parser_id: str = "",
        records: int = 0,
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_OUTPUT_PARSED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "parser_id": parser_id,
                "records": records,
            },
            source=source,
        )


class ToolOutputNormalizedEvent(DomainEvent):
    """Emitted when parsed records are normalized into canonical observations."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        *,
        normalizer_id: str = "",
        observations: int = 0,
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_OUTPUT_NORMALIZED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "normalizer_id": normalizer_id,
                "observations": observations,
            },
            source=source,
        )


class ToolEvidenceExtractedEvent(DomainEvent):
    """Emitted when evidence is extracted from a tool result."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        evidence_id: str,
        *,
        evidence_class: str = "candidate",
        evidence_type: str = "",
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_EVIDENCE_EXTRACTED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "evidence_id": evidence_id,
                "evidence_class": evidence_class,
                "evidence_type": evidence_type,
            },
            source=source,
        )


class ToolObservationCreatedEvent(DomainEvent):
    """Emitted when a canonical observation is created from tool output."""

    def __init__(
        self,
        execution_id: str,
        tool_id: str,
        observation_id: str,
        *,
        observation_kind: str = "other",
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_OBSERVATION_CREATED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "observation_id": observation_id,
                "observation_kind": observation_kind,
            },
            source=source,
        )


class ToolResultContradictionEvent(DomainEvent):
    """Emitted when tools produce contradictory evidence."""

    def __init__(
        self,
        correlation_key: str,
        target: str,
        *,
        tools: list[str] | None = None,
        vulnerability_class: str = "",
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_RESULT_CONTRADICTION.value,
            payload={
                "correlation_key": correlation_key,
                "target": target,
                "tools": tools or [],
                "vulnerability_class": vulnerability_class,
            },
            source=source,
        )


class ToolHealthFailedEvent(DomainEvent):
    """Emitted when a tool health check fails."""

    def __init__(
        self,
        tool_id: str,
        *,
        status: str = "unavailable",
        reason: str = "",
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_HEALTH_FAILED.value,
            payload={"tool_id": tool_id, "status": status, "reason": reason},
            source=source,
        )


class ToolVersionDetectedEvent(DomainEvent):
    """Emitted when a tool version is detected or updated."""

    def __init__(
        self,
        tool_id: str,
        version: str,
        *,
        compatible: bool = True,
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_VERSION_DETECTED.value,
            payload={"tool_id": tool_id, "version": version, "compatible": compatible},
            source=source,
        )


class ToolRecommendationCreatedEvent(DomainEvent):
    """Emitted when a tool recommendation is produced."""

    def __init__(
        self,
        capability: str,
        tool_id: str,
        *,
        kind: str = "best",
        score: float = 0.0,
        reason: str = "",
        source: str = "toolchain",
    ) -> None:
        super().__init__(
            event_type=EventType.TOOL_RECOMMENDATION_CREATED.value,
            payload={
                "capability": capability,
                "tool_id": tool_id,
                "kind": kind,
                "score": score,
                "reason": reason,
            },
            source=source,
        )


class ReconStartedEvent(DomainEvent):
    """Emitted when a reconnaissance run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "recon.service",
    ) -> None:
        super().__init__(
            event_type="recon.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class ReconToolCompletedEvent(DomainEvent):
    """Emitted when a single recon tool execution finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        tool_id: str,
        status: str,
        *,
        records: int = 0,
        duration_ms: int = 0,
        error: str = "",
        source: str = "recon.service",
    ) -> None:
        super().__init__(
            event_type="recon.tool_completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "tool_id": tool_id,
                "status": status,
                "records": records,
                "duration_ms": duration_ms,
                "error": error,
            },
            source=source,
        )


class ReconCorrelatedEvent(DomainEvent):
    """Emitted after discovery records are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_records: int,
        correlated_records: int,
        distinct_assets: int,
        source: str = "recon.service",
    ) -> None:
        super().__init__(
            event_type="recon.correlated",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_records": raw_records,
                "correlated_records": correlated_records,
                "distinct_assets": distinct_assets,
            },
            source=source,
        )


class ReconPersistedEvent(DomainEvent):
    """Emitted when correlated records are persisted to the TIDB."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        persisted: int,
        source: str = "recon.service",
    ) -> None:
        super().__init__(
            event_type="recon.persisted",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "persisted": persisted,
            },
            source=source,
        )


class ReconCompletedEvent(DomainEvent):
    """Emitted when a reconnaissance run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        records: int,
        distinct_assets: int,
        source: str = "recon.service",
    ) -> None:
        super().__init__(
            event_type="recon.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "records": records,
                "distinct_assets": distinct_assets,
            },
            source=source,
        )


class ReconFailedEvent(DomainEvent):
    """Emitted when a reconnaissance run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        error: str,
        *,
        source: str = "recon.service",
    ) -> None:
        super().__init__(
            event_type="recon.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "error": error,
            },
            source=source,
        )


class DnsIntelligenceStartedEvent(DomainEvent):
    """Emitted when a DNS intelligence run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.intelligence.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class DnsPhaseStartedEvent(DomainEvent):
    """Emitted when a DNS pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class DnsResolutionStartedEvent(DomainEvent):
    """Emitted when a DNS resolution begins."""

    def __init__(
        self,
        correlation_id: str,
        name: str,
        *,
        record_types: list[str] | None = None,
        mission_id: str = "",
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.resolution.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "name": name,
                "record_types": record_types or [],
            },
            source=source,
        )


class DnsResolutionCompletedEvent(DomainEvent):
    """Emitted when a DNS resolution completes."""

    def __init__(
        self,
        correlation_id: str,
        name: str,
        status: str,
        *,
        records: int = 0,
        duration_ms: int = 0,
        mission_id: str = "",
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.resolution.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "name": name,
                "status": status,
                "records": records,
                "duration_ms": duration_ms,
            },
            source=source,
        )


class DnsResolutionFailedEvent(DomainEvent):
    """Emitted when a DNS resolution fails."""

    def __init__(
        self,
        correlation_id: str,
        name: str,
        error: str,
        *,
        mission_id: str = "",
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.resolution.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "name": name,
                "error": error,
            },
            source=source,
        )


class DnsRecordDiscoveredEvent(DomainEvent):
    """Emitted when a DNS record is discovered."""

    def __init__(
        self,
        correlation_id: str,
        name: str,
        record_type: str,
        value: str,
        *,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.record.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "name": name,
                "record_type": record_type,
                "value": value,
                "tool_id": tool_id,
            },
            source=source,
        )


class DnsConflictDetectedEvent(DomainEvent):
    """Emitted when a DNS conflict is detected."""

    def __init__(
        self,
        correlation_id: str,
        name: str,
        record_type: str,
        values: list[str],
        *,
        selected: str = "",
        mission_id: str = "",
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.conflict.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "name": name,
                "record_type": record_type,
                "values": values,
                "selected": selected,
            },
            source=source,
        )


class DnsChangeDetectedEvent(DomainEvent):
    """Emitted when a DNS change is detected."""

    def __init__(
        self,
        correlation_id: str,
        name: str,
        record_type: str,
        change_type: str,
        *,
        old_value: str = "",
        new_value: str = "",
        mission_id: str = "",
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "name": name,
                "record_type": record_type,
                "change_type": change_type,
                "old_value": old_value,
                "new_value": new_value,
            },
            source=source,
        )


class DnsCorrelationCompletedEvent(DomainEvent):
    """Emitted when DNS records are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_records: int,
        correlated_records: int,
        conflicts: int,
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_records": raw_records,
                "correlated_records": correlated_records,
                "conflicts": conflicts,
            },
            source=source,
        )


class DnsIntelligenceCompletedEvent(DomainEvent):
    """Emitted when a DNS intelligence run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        records: int,
        distinct: int,
        source: str = "dns.service",
    ) -> None:
        super().__init__(
            event_type="dns.intelligence.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "records": records,
                "distinct": distinct,
            },
            source=source,
        )


class LiveDiscoveryStartedEvent(DomainEvent):
    """Emitted when a live host & service discovery run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.discovery.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class LivePhaseStartedEvent(DomainEvent):
    """Emitted when a live discovery pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class LiveToolFailedEvent(DomainEvent):
    """Emitted when a live discovery tool execution fails."""

    def __init__(
        self,
        correlation_id: str,
        target: str,
        error: str,
        *,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.tool.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "tool_id": tool_id,
                "error": error,
            },
            source=source,
        )


class LiveObservationDiscoveredEvent(DomainEvent):
    """Emitted when a live discovery observation is captured."""

    def __init__(
        self,
        correlation_id: str,
        kind: str,
        key: str,
        *,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.host.discovered" if kind == "host" else f"host.{kind}.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "kind": kind,
                "key": key,
                "tool_id": tool_id,
            },
            source=source,
        )


class LiveConflictDetectedEvent(DomainEvent):
    """Emitted when a live discovery conflict is detected."""

    def __init__(
        self,
        correlation_id: str,
        kind: str,
        key: str,
        values: list[str],
        *,
        selected: str = "",
        mission_id: str = "",
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.conflict.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "kind": kind,
                "key": key,
                "values": values,
                "selected": selected,
            },
            source=source,
        )


class LiveChangeDetectedEvent(DomainEvent):
    """Emitted when a live state change is detected."""

    def __init__(
        self,
        correlation_id: str,
        kind: str,
        key: str,
        change_type: str,
        *,
        old_value: str = "",
        new_value: str = "",
        mission_id: str = "",
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "kind": kind,
                "key": key,
                "change_type": change_type,
                "old_value": old_value,
                "new_value": new_value,
            },
            source=source,
        )


class LiveCorrelationCompletedEvent(DomainEvent):
    """Emitted when live discovery observations are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_observations: int,
        correlated_observations: int,
        conflicts: int,
        hosts: int,
        ports: int,
        services: int,
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_observations": raw_observations,
                "correlated_observations": correlated_observations,
                "conflicts": conflicts,
                "hosts": hosts,
                "ports": ports,
                "services": services,
            },
            source=source,
        )


class LiveDiscoveryCompletedEvent(DomainEvent):
    """Emitted when a live host & service discovery run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        hosts: int,
        ports: int,
        services: int,
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.discovery.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "hosts": hosts,
                "ports": ports,
                "services": services,
            },
            source=source,
        )


class LiveDiscoveryFailedEvent(DomainEvent):
    """Emitted when a live host & service discovery run fails."""

    def __init__(
        self,
        correlation_id: str,
        target: str,
        error: str,
        *,
        mission_id: str = "",
        source: str = "livehost.service",
    ) -> None:
        super().__init__(
            event_type="host.discovery.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class PluginLoadedEvent(DomainEvent):
    """Emitted when a plugin is successfully loaded."""

    def __init__(self, plugin: str, version: str, *, source: str = "plugin.manager") -> None:
        super().__init__(
            event_type="plugin.loaded",
            payload={"plugin": plugin, "version": version},
            source=source,
        )


class ExecutionStartedEvent(DomainEvent):
    """Emitted when a tool execution begins."""

    def __init__(
        self, execution_id: str, tool_id: str, context_id: str | None = None, *, source: str = "tool.sdk"
    ) -> None:
        super().__init__(
            event_type=EventType.EXECUTION_STARTED.value,
            payload={"execution_id": execution_id, "tool_id": tool_id, "context_id": context_id},
            source=source,
        )


class ExecutionCompletedEvent(DomainEvent):
    """Emitted when a tool execution completes successfully."""

    def __init__(self, execution_id: str, tool_id: str, summary: str = "", *, source: str = "tool.sdk") -> None:
        super().__init__(
            event_type=EventType.EXECUTION_COMPLETED.value,
            payload={"execution_id": execution_id, "tool_id": tool_id, "summary": summary},
            source=source,
        )


class ExecutionFailedEvent(DomainEvent):
    """Emitted when a tool execution fails."""

    def __init__(
        self, execution_id: str, tool_id: str, failure_kind: str, message: str, *, source: str = "tool.sdk"
    ) -> None:
        super().__init__(
            event_type=EventType.EXECUTION_FAILED.value,
            payload={
                "execution_id": execution_id,
                "tool_id": tool_id,
                "failure_kind": failure_kind,
                "message": message,
            },
            source=source,
        )


class ExecutionTimedOutEvent(DomainEvent):
    """Emitted when a tool execution exceeds its deadline."""

    def __init__(self, execution_id: str, tool_id: str, timeout_seconds: float, *, source: str = "tool.sdk") -> None:
        super().__init__(
            event_type=EventType.EXECUTION_TIMED_OUT.value,
            payload={"execution_id": execution_id, "tool_id": tool_id, "timeout_seconds": timeout_seconds},
            source=source,
        )


class ExecutionRetriedEvent(DomainEvent):
    """Emitted when a failed execution is retried."""

    def __init__(self, execution_id: str, tool_id: str, attempt: int, reason: str, *, source: str = "tool.sdk") -> None:
        super().__init__(
            event_type=EventType.EXECUTION_RETRIED.value,
            payload={"execution_id": execution_id, "tool_id": tool_id, "attempt": attempt, "reason": reason},
            source=source,
        )


class OutputCollectedEvent(DomainEvent):
    """Emitted when tool output is captured."""

    def __init__(
        self, execution_id: str, tool_id: str, formats: list[str], size_bytes: int, *, source: str = "tool.sdk"
    ) -> None:
        super().__init__(
            event_type=EventType.OUTPUT_COLLECTED.value,
            payload={"execution_id": execution_id, "tool_id": tool_id, "formats": formats, "size_bytes": size_bytes},
            source=source,
        )


class NormalizationCompleteEvent(DomainEvent):
    """Emitted when tool output has been normalized to findings."""

    def __init__(self, execution_id: str, tool_id: str, findings: int, *, source: str = "tool.sdk") -> None:
        super().__init__(
            event_type=EventType.NORMALIZATION_COMPLETE.value,
            payload={"execution_id": execution_id, "tool_id": tool_id, "findings": findings},
            source=source,
        )


class DatabaseUpdatedEvent(DomainEvent):
    """Emitted when execution results are stored in the database."""

    def __init__(self, execution_id: str, tool_id: str, stored_ids: list[str], *, source: str = "tool.sdk") -> None:
        super().__init__(
            event_type=EventType.DATABASE_UPDATED.value,
            payload={"execution_id": execution_id, "tool_id": tool_id, "stored_ids": stored_ids},
            source=source,
        )


class TopologyBuildStartedEvent(DomainEvent):
    """Emitted when a topology build run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "full",
        tools: list[str] | None = None,
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.build.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class TopologyRelationshipDiscoveredEvent(DomainEvent):
    """Emitted when a new topology relationship is discovered."""

    def __init__(
        self,
        correlation_id: str,
        key: str,
        rel_type: str,
        source: str,
        target: str,
        *,
        mission_id: str = "",
        source_label: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.relationship.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "key": key,
                "rel_type": rel_type,
                "source": source,
                "target": target,
            },
            source=source_label,
        )


class TopologyRelationshipUpdatedEvent(DomainEvent):
    """Emitted when an existing topology relationship changes."""

    def __init__(
        self,
        correlation_id: str,
        key: str,
        rel_type: str,
        source: str,
        target: str,
        *,
        mission_id: str = "",
        source_label: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.relationship.updated",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "key": key,
                "rel_type": rel_type,
                "source": source,
                "target": target,
            },
            source=source_label,
        )


class TopologyRelationshipRemovedEvent(DomainEvent):
    """Emitted when a topology relationship is removed."""

    def __init__(
        self,
        correlation_id: str,
        key: str,
        rel_type: str,
        source: str,
        target: str,
        *,
        mission_id: str = "",
        source_label: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.relationship.removed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "key": key,
                "rel_type": rel_type,
                "source": source,
                "target": target,
            },
            source=source_label,
        )


class TopologyEntityCorrelatedEvent(DomainEvent):
    """Emitted when topology entities are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        entities: int,
        relationships: int,
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.entity.correlated",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "entities": entities,
                "relationships": relationships,
            },
            source=source,
        )


class TopologyConflictDetectedEvent(DomainEvent):
    """Emitted when a topology relationship conflict is detected."""

    def __init__(
        self,
        correlation_id: str,
        key: str,
        conflict_type: str,
        values: list[str],
        *,
        selected: str = "",
        mission_id: str = "",
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.conflict.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "key": key,
                "conflict_type": conflict_type,
                "values": values,
                "selected": selected,
            },
            source=source,
        )


class TopologyClusterCreatedEvent(DomainEvent):
    """Emitted when a shared-infrastructure cluster is created."""

    def __init__(
        self,
        correlation_id: str,
        cluster_type: str,
        name: str,
        members: list[str],
        *,
        mission_id: str = "",
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.cluster.created",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "cluster_type": cluster_type,
                "name": name,
                "members": members,
            },
            source=source,
        )


class TopologyAnalysisStartedEvent(DomainEvent):
    """Emitted when topology analysis begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.analysis.started",
            payload={"mission_id": mission_id, "correlation_id": correlation_id, "target": target},
            source=source,
        )


class TopologyAnalysisCompletedEvent(DomainEvent):
    """Emitted when topology analysis completes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        node_count: int,
        relationship_count: int,
        cluster_count: int,
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.analysis.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "node_count": node_count,
                "relationship_count": relationship_count,
                "cluster_count": cluster_count,
            },
            source=source,
        )


class TopologyBuildCompletedEvent(DomainEvent):
    """Emitted when a topology build run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        entities_processed: int,
        relationships_processed: int,
        new_relationships: int,
        updated_relationships: int,
        removed_relationships: int,
        conflicts: int,
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.build.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "entities_processed": entities_processed,
                "relationships_processed": relationships_processed,
                "new_relationships": new_relationships,
                "updated_relationships": updated_relationships,
                "removed_relationships": removed_relationships,
                "conflicts": conflicts,
            },
            source=source,
        )


class TopologyBuildFailedEvent(DomainEvent):
    """Emitted when a topology build run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "topology.service",
    ) -> None:
        super().__init__(
            event_type="topology.build.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class TechnologyFingerprintingStartedEvent(DomainEvent):
    """Emitted when a technology fingerprinting run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.fingerprinting.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class TechnologyPhaseStartedEvent(DomainEvent):
    """Emitted when a fingerprinting pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class TechnologyDetectedEvent(DomainEvent):
    """Emitted when a technology is detected on an asset."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        *,
        category: str = "other",
        version: str = "",
        tool_id: str = "",
        mission_id: str = "",
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "category": category,
                "version": version,
                "tool_id": tool_id,
            },
            source=source,
        )


class TechnologyUpdatedEvent(DomainEvent):
    """Emitted when an existing technology observation is updated."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        *,
        category: str = "other",
        version: str = "",
        tool_id: str = "",
        mission_id: str = "",
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.updated",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "category": category,
                "version": version,
                "tool_id": tool_id,
            },
            source=source,
        )


class TechnologyVersionDetectedEvent(DomainEvent):
    """Emitted when an evidence-backed version is detected for a technology."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        version: str,
        *,
        confidence: str = "unknown",
        mission_id: str = "",
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.version.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "version": version,
                "confidence": confidence,
            },
            source=source,
        )


class TechnologyVersionChangedEvent(DomainEvent):
    """Emitted when a technology version changes between missions."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        *,
        old_version: str = "",
        new_version: str = "",
        mission_id: str = "",
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.version.changed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "old_version": old_version,
                "new_version": new_version,
            },
            source=source,
        )


class TechnologyConflictEvent(DomainEvent):
    """Emitted when conflicting technology evidence is detected."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        values: list[str],
        *,
        selected: str = "",
        conflict_type: str = "version",
        mission_id: str = "",
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.conflict",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "values": values,
                "selected": selected,
                "conflict_type": conflict_type,
            },
            source=source,
        )


class TechnologyRemovedEvent(DomainEvent):
    """Emitted when a technology is no longer observed on an asset."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        *,
        previous: str = "",
        mission_id: str = "",
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.removed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "previous": previous,
            },
            source=source,
        )


class TechnologyFingerprintingCompletedEvent(DomainEvent):
    """Emitted when a technology fingerprinting run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        technologies: int,
        distinct: int,
        versions: int,
        conflicts: int,
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.fingerprinting.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "technologies": technologies,
                "distinct": distinct,
                "versions": versions,
                "conflicts": conflicts,
            },
            source=source,
        )


class TechnologyFingerprintingFailedEvent(DomainEvent):
    """Emitted when a technology fingerprinting run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "technology.service",
    ) -> None:
        super().__init__(
            event_type="technology.fingerprinting.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class CrawlStartedEvent(DomainEvent):
    """Emitted when a web crawl run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "active",
        tools: list[str] | None = None,
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class CrawlPhaseStartedEvent(DomainEvent):
    """Emitted when a crawl pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class CrawlUrlDiscoveredEvent(DomainEvent):
    """Emitted when a URL observation is discovered."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        *,
        status_code: int | None = None,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.url.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "status_code": status_code,
                "tool_id": tool_id,
            },
            source=source,
        )


class CrawlEndpointDiscoveredEvent(DomainEvent):
    """Emitted when an API endpoint is discovered."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        method: str,
        *,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.endpoint.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "method": method,
                "tool_id": tool_id,
            },
            source=source,
        )


class CrawlWebSocketDiscoveredEvent(DomainEvent):
    """Emitted when a WebSocket endpoint is discovered."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        *,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.websocket.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "tool_id": tool_id,
            },
            source=source,
        )


class CrawlGraphQLDiscoveredEvent(DomainEvent):
    """Emitted when a GraphQL endpoint is discovered."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        *,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.graphql.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "tool_id": tool_id,
            },
            source=source,
        )


class CrawlRedirectDiscoveredEvent(DomainEvent):
    """Emitted when an HTTP redirect is discovered."""

    def __init__(
        self,
        correlation_id: str,
        source_url: str,
        destination_url: str,
        *,
        status_code: int = 301,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.redirect.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "source_url": source_url,
                "destination_url": destination_url,
                "status_code": status_code,
                "tool_id": tool_id,
            },
            source=source,
        )


class CrawlAuthBoundaryDiscoveredEvent(DomainEvent):
    """Emitted when an authentication boundary is discovered."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        scheme: str,
        *,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.auth_boundary.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "scheme": scheme,
                "tool_id": tool_id,
            },
            source=source,
        )


class CrawlChangeDetectedEvent(DomainEvent):
    """Emitted when a web-surface change is detected between runs."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        change_type: str,
        *,
        previous: str = "",
        current: str = "",
        tool_id: str = "",
        mission_id: str = "",
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "change_type": change_type,
                "previous": previous,
                "current": current,
                "tool_id": tool_id,
            },
            source=source,
        )


class CrawlCorrelationCompletedEvent(DomainEvent):
    """Emitted when crawl observations are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_observations: int,
        correlated_observations: int,
        urls: int,
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_observations": raw_observations,
                "correlated_observations": correlated_observations,
                "urls": urls,
            },
            source=source,
        )


class CrawlCompletedEvent(DomainEvent):
    """Emitted when a web crawl run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        urls: int,
        distinct: int,
        endpoints: int,
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "urls": urls,
                "distinct": distinct,
                "endpoints": endpoints,
            },
            source=source,
        )


class CrawlFailedEvent(DomainEvent):
    """Emitted when a web crawl run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "crawl.service",
    ) -> None:
        super().__init__(
            event_type="crawl.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class JavaScriptAnalysisStartedEvent(DomainEvent):
    """Emitted when a JavaScript intelligence run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "active",
        tools: list[str] | None = None,
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.analysis.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class JavaScriptPhaseStartedEvent(DomainEvent):
    """Emitted when a JavaScript analysis pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class JavaScriptAssetAnalysedEvent(DomainEvent):
    """Emitted when one script asset is analysed."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        *,
        findings: int = 0,
        secrets: int = 0,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.asset.analysed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "findings": findings,
                "secrets": secrets,
                "tool_id": tool_id,
            },
            source=source,
        )


class JavaScriptSecretDiscoveredEvent(DomainEvent):
    """Emitted when a potential secret indicator is discovered client-side."""

    def __init__(
        self,
        correlation_id: str,
        url: str,
        classification: str,
        *,
        tier: str = "low",
        tool_id: str = "",
        mission_id: str = "",
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.secret.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "url": url,
                "classification": classification,
                "tier": tier,
                "tool_id": tool_id,
            },
            source=source,
        )


class JavaScriptChangeDetectedEvent(DomainEvent):
    """Emitted when a client-side surface change is detected between runs."""

    def __init__(
        self,
        correlation_id: str,
        subject: str,
        change_type: str,
        *,
        previous: str = "",
        current: str = "",
        tool_id: str = "",
        mission_id: str = "",
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject": subject,
                "change_type": change_type,
                "previous": previous,
                "current": current,
                "tool_id": tool_id,
            },
            source=source,
        )


class JavaScriptCorrelationCompletedEvent(DomainEvent):
    """Emitted when JavaScript intelligence observations are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_observations: int,
        correlated_observations: int,
        assets: int,
        secrets: int = 0,
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_observations": raw_observations,
                "correlated_observations": correlated_observations,
                "assets": assets,
                "secrets": secrets,
            },
            source=source,
        )


class JavaScriptAnalysisCompletedEvent(DomainEvent):
    """Emitted when a JavaScript intelligence run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        assets: int,
        findings: int,
        secrets: int = 0,
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.analysis.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "assets": assets,
                "findings": findings,
                "secrets": secrets,
            },
            source=source,
        )


class JavaScriptAnalysisFailedEvent(DomainEvent):
    """Emitted when a JavaScript intelligence run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "javascript.service",
    ) -> None:
        super().__init__(
            event_type="javascript.analysis.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class ApiIntelligenceStartedEvent(DomainEvent):
    """Emitted when an API intelligence run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.intelligence.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class ApiPhaseStartedEvent(DomainEvent):
    """Emitted when an API intelligence pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class ApiHostDiscoveredEvent(DomainEvent):
    """Emitted when an API host/origin is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        api_kinds: list[str] | None = None,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.host.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "api_kinds": api_kinds or [],
                "tool_id": tool_id,
            },
            source=source,
        )


class ApiSpecDiscoveredEvent(DomainEvent):
    """Emitted when an API specification document is located."""

    def __init__(
        self,
        correlation_id: str,
        source_url: str,
        spec_type: str,
        *,
        version: str = "",
        operations: int = 0,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.spec.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "source_url": source_url,
                "spec_type": spec_type,
                "version": version,
                "operations": operations,
                "tool_id": tool_id,
            },
            source=source,
        )


class ApiDiscoveredEvent(DomainEvent):
    """Emitted when a canonical API is discovered on a host."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        api_name: str,
        *,
        api_version: str = "",
        documented: bool = False,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.api.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "api_name": api_name,
                "api_version": api_version,
                "documented": documented,
                "tool_id": tool_id,
            },
            source=source,
        )


class ApiEndpointDiscoveredEvent(DomainEvent):
    """Emitted when an API endpoint operation is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        method: str,
        path: str,
        *,
        documented: bool = False,
        tool_id: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.endpoint.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "method": method,
                "path": path,
                "documented": documented,
                "tool_id": tool_id,
            },
            source=source,
        )


class ApiVersionDiscoveredEvent(DomainEvent):
    """Emitted when an API version is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        api_name: str,
        version: str,
        *,
        documented: bool = False,
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.version.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "api_name": api_name,
                "version": version,
                "documented": documented,
            },
            source=source,
        )


class ApiAuthDiscoveredEvent(DomainEvent):
    """Emitted when an authentication scheme is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        scheme_type: str,
        *,
        documented: bool = False,
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.auth.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "scheme_type": scheme_type,
                "documented": documented,
            },
            source=source,
        )


class ApiAuthorizationDiscoveredEvent(DomainEvent):
    """Emitted when an authorization model is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        model_type: str,
        *,
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.authorization.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "model_type": model_type,
            },
            source=source,
        )


class ApiRateLimitDiscoveredEvent(DomainEvent):
    """Emitted when a rate-limit indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        style: str,
        *,
        headers: list[str] | None = None,
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.rate_limit.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "style": style,
                "headers": headers or [],
            },
            source=source,
        )


class ApiPaginationDiscoveredEvent(DomainEvent):
    """Emitted when a pagination style is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        style: str,
        *,
        endpoint: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.pagination.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "style": style,
                "endpoint": endpoint,
            },
            source=source,
        )


class ApiFilterDiscoveredEvent(DomainEvent):
    """Emitted when a filter capability is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        filter_param: str,
        *,
        endpoint: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.filter.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "filter_param": filter_param,
                "endpoint": endpoint,
            },
            source=source,
        )


class ApiUndocumentedDetectedEvent(DomainEvent):
    """Emitted when an undocumented API surface is detected."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        endpoints: int = 0,
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.undocumented.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "endpoints": endpoints,
            },
            source=source,
        )


class ApiHistoricalDiscoveredEvent(DomainEvent):
    """Emitted when a historical API surface is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        api_name: str = "",
        version: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.historical.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "api_name": api_name,
                "version": version,
            },
            source=source,
        )


class ApiChangeDetectedEvent(DomainEvent):
    """Emitted when an API surface change is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject: str,
        change_type: str,
        *,
        previous: str = "",
        current: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject": subject,
                "change_type": change_type,
                "previous": previous,
                "current": current,
            },
            source=source,
        )


class ApiConflictDetectedEvent(DomainEvent):
    """Emitted when conflicting API intelligence is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject: str,
        conflict_type: str,
        values: list[str],
        *,
        selected: str = "",
        mission_id: str = "",
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.conflict.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject": subject,
                "conflict_type": conflict_type,
                "values": values,
                "selected": selected,
            },
            source=source,
        )


class ApiCorrelationCompletedEvent(DomainEvent):
    """Emitted when API observations are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_observations: int,
        correlated_observations: int,
        conflicts: int,
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_observations": raw_observations,
                "correlated_observations": correlated_observations,
                "conflicts": conflicts,
            },
            source=source,
        )


class ApiIntelligenceCompletedEvent(DomainEvent):
    """Emitted when an API intelligence run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        hosts: int,
        apis: int,
        operations: int,
        documented: int,
        undocumented: int,
        changes: int,
        conflicts: int,
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.intelligence.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "hosts": hosts,
                "apis": apis,
                "operations": operations,
                "documented": documented,
                "undocumented": undocumented,
                "changes": changes,
                "conflicts": conflicts,
            },
            source=source,
        )


class ApiIntelligenceFailedEvent(DomainEvent):
    """Emitted when an API intelligence run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "api.service",
    ) -> None:
        super().__init__(
            event_type="api.intelligence.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class AuthDiscoveryStartedEvent(DomainEvent):
    """Emitted when an authentication intelligence run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.discovery.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class AuthPhaseStartedEvent(DomainEvent):
    """Emitted when an authentication intelligence pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class AuthLoginSurfaceDiscoveredEvent(DomainEvent):
    """Emitted when an authentication surface is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        surface_kind: str,
        *,
        url: str = "",
        access_state: str = "",
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.login_surface.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "url": url,
                "surface_kind": surface_kind,
                "access_state": access_state,
                "confidence": confidence,
            },
            source=source,
        )


class AuthEndpointDiscoveredEvent(DomainEvent):
    """Emitted when an authentication endpoint is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        kind: str,
        *,
        url: str = "",
        method: str = "GET",
        documented: bool = False,
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.endpoint.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "kind": kind,
                "url": url,
                "method": method,
                "documented": documented,
                "confidence": confidence,
            },
            source=source,
        )


class AuthIdentityProviderDiscoveredEvent(DomainEvent):
    """Emitted when an identity provider is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        provider_kind: str,
        *,
        issuer: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.identity_provider.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "provider_kind": provider_kind,
                "issuer": issuer,
                "confidence": confidence,
            },
            source=source,
        )


class AuthOAuthDiscoveredEvent(DomainEvent):
    """Emitted when an OAuth configuration is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        token_endpoint: str = "",
        authorization_endpoint: str = "",
        issuer: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.oauth.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "token_endpoint": token_endpoint,
                "authorization_endpoint": authorization_endpoint,
                "issuer": issuer,
                "confidence": confidence,
            },
            source=source,
        )


class AuthOIDCDiscoveredEvent(DomainEvent):
    """Emitted when an OIDC configuration is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        issuer: str = "",
        discovery_url: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.oidc.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "issuer": issuer,
                "discovery_url": discovery_url,
                "confidence": confidence,
            },
            source=source,
        )


class AuthSAMLDiscoveredEvent(DomainEvent):
    """Emitted when a SAML indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        entity_id: str = "",
        sso_url: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.saml.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "entity_id": entity_id,
                "sso_url": sso_url,
                "confidence": confidence,
            },
            source=source,
        )


class AuthMFADiscoveredEvent(DomainEvent):
    """Emitted when an MFA mechanism is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        kind: str,
        *,
        endpoint: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.mfa.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "kind": kind,
                "endpoint": endpoint,
                "confidence": confidence,
            },
            source=source,
        )


class AuthSessionCookieDiscoveredEvent(DomainEvent):
    """Emitted when a session cookie is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        secure: bool = False,
        httponly: bool = False,
        samesite: str = "",
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.session_cookie.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "confidence": confidence,
            },
            source=source,
        )


class AuthTokenStorageDiscoveredEvent(DomainEvent):
    """Emitted when a token storage indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        storage_type: str,
        *,
        token_category: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.token_storage.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "storage_type": storage_type,
                "token_category": token_category,
                "confidence": confidence,
            },
            source=source,
        )


class AuthCSRFDiscoveredEvent(DomainEvent):
    """Emitted when a CSRF mechanism is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        kind: str,
        *,
        cookie_name: str = "",
        header_name: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.csrf.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "kind": kind,
                "cookie_name": cookie_name,
                "header_name": header_name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthCORSDiscoveredEvent(DomainEvent):
    """Emitted when a CORS configuration is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        allow_origin: str = "",
        allow_credentials: bool = False,
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.cors.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "allow_origin": allow_origin,
                "allow_credentials": allow_credentials,
                "confidence": confidence,
            },
            source=source,
        )


class AuthRoleDiscoveredEvent(DomainEvent):
    """Emitted when a role indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float = 0.3,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.role.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthPermissionDiscoveredEvent(DomainEvent):
    """Emitted when a permission indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float = 0.3,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.permission.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthTenantDiscoveredEvent(DomainEvent):
    """Emitted when a tenant indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        tenant_type: str = "unknown",
        confidence: float = 0.3,
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.tenant.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "tenant_type": tenant_type,
                "confidence": confidence,
            },
            source=source,
        )


class AuthChangeDetectedEvent(DomainEvent):
    """Emitted when an authentication change is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject_type: str,
        subject: str,
        change_type: str,
        *,
        previous: str = "",
        current: str = "",
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject_type": subject_type,
                "subject": subject,
                "change_type": change_type,
                "previous": previous,
                "current": current,
            },
            source=source,
        )


class AuthConflictDetectedEvent(DomainEvent):
    """Emitted when conflicting authentication intelligence is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject: str,
        conflict_type: str,
        *,
        selected: str = "",
        mission_id: str = "",
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.conflict.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject": subject,
                "conflict_type": conflict_type,
                "selected": selected,
            },
            source=source,
        )


class AuthCorrelationCompletedEvent(DomainEvent):
    """Emitted when authentication observations are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_observations: int,
        correlated_observations: int,
        conflicts: int,
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_observations": raw_observations,
                "correlated_observations": correlated_observations,
                "conflicts": conflicts,
            },
            source=source,
        )


class AuthDiscoveryCompletedEvent(DomainEvent):
    """Emitted when an authentication intelligence run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        surfaces: int,
        endpoints: int,
        identity_providers: int,
        changes: int,
        conflicts: int,
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.discovery.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "surfaces": surfaces,
                "endpoints": endpoints,
                "identity_providers": identity_providers,
                "changes": changes,
                "conflicts": conflicts,
            },
            source=source,
        )


class AuthDiscoveryFailedEvent(DomainEvent):
    """Emitted when an authentication intelligence run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "auth.service",
    ) -> None:
        super().__init__(
            event_type="auth.discovery.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class AuthorizationDiscoveryStartedEvent(DomainEvent):
    """Emitted when an authorization intelligence run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.discovery.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class AuthorizationPhaseStartedEvent(DomainEvent):
    """Emitted when an authorization intelligence pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class AuthorizationSubjectDiscoveredEvent(DomainEvent):
    """Emitted when an authorization subject is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        subject_kind: str = "unknown",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.subject.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "subject_kind": subject_kind,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationRoleDiscoveredEvent(DomainEvent):
    """Emitted when a role is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float = 0.3,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.role.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationPermissionDiscoveredEvent(DomainEvent):
    """Emitted when a permission is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float = 0.3,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.permission.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationScopeDiscoveredEvent(DomainEvent):
    """Emitted when a scope is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float = 0.3,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.scope.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationPolicyDiscoveredEvent(DomainEvent):
    """Emitted when a policy model is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        name: str = "",
        model_kind: str = "unknown",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.policy.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "model_kind": model_kind,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationResourceDiscoveredEvent(DomainEvent):
    """Emitted when an authorization resource is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        resource_kind: str = "unknown",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.resource.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "resource_kind": resource_kind,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationActionDiscoveredEvent(DomainEvent):
    """Emitted when an authorization action is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        resource: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.action.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "resource": resource,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationOwnershipDiscoveredEvent(DomainEvent):
    """Emitted when an ownership indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.ownership.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationTenantDiscoveredEvent(DomainEvent):
    """Emitted when a tenant authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        tenant_kind: str = "unknown",
        confidence: float = 0.3,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.tenant.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "tenant_kind": tenant_kind,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationAdminSurfaceDiscoveredEvent(DomainEvent):
    """Emitted when an administrative surface is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        url: str = "",
        surface_kind: str = "unknown",
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.admin_surface.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "url": url,
                "surface_kind": surface_kind,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationFunctionLevelDiscoveredEvent(DomainEvent):
    """Emitted when a function-level authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        function: str = "",
        endpoint: str = "",
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.function_level.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "function": function,
                "endpoint": endpoint,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationObjectLevelDiscoveredEvent(DomainEvent):
    """Emitted when an object-level authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        resource: str = "",
        endpoint: str = "",
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.object_level.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "resource": resource,
                "endpoint": endpoint,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationFieldLevelDiscoveredEvent(DomainEvent):
    """Emitted when a field-level authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        field_name: str = "",
        resource: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.field_level.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "field": field_name,
                "resource": resource,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationFrontendDiscoveredEvent(DomainEvent):
    """Emitted when a frontend authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        check_type: str = "unknown",
        target: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.frontend.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "check_type": check_type,
                "target": target,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationBackendDiscoveredEvent(DomainEvent):
    """Emitted when a backend authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        mechanism: str = "unknown",
        name: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.backend.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "mechanism": mechanism,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationApiCorrelationDiscoveredEvent(DomainEvent):
    """Emitted when an API authorization correlation is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        endpoint: str = "",
        method: str = "GET",
        authentication: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.api_correlation.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "endpoint": endpoint,
                "method": method,
                "authentication": authentication,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationGraphQLDiscoveredEvent(DomainEvent):
    """Emitted when a GraphQL authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        subject: str = "field",
        name: str = "",
        directive: str = "",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.graphql.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "subject": subject,
                "name": name,
                "directive": directive,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationWebSocketDiscoveredEvent(DomainEvent):
    """Emitted when a WebSocket authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        *,
        endpoint: str = "",
        mechanism: str = "unknown",
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.websocket.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "endpoint": endpoint,
                "mechanism": mechanism,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationServiceDiscoveredEvent(DomainEvent):
    """Emitted when a service-to-service authorization indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float = 0.4,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.service.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationDecisionDiscoveredEvent(DomainEvent):
    """Emitted when an authorization decision indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        decision: str,
        *,
        endpoint: str = "",
        confidence: float = 0.5,
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.decision.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "decision": decision,
                "endpoint": endpoint,
                "confidence": confidence,
            },
            source=source,
        )


class AuthorizationChangeDetectedEvent(DomainEvent):
    """Emitted when an authorization change is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject_type: str,
        subject: str,
        change_type: str,
        *,
        previous: str = "",
        current: str = "",
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject_type": subject_type,
                "subject": subject,
                "change_type": change_type,
                "previous": previous,
                "current": current,
            },
            source=source,
        )


class AuthorizationConflictDetectedEvent(DomainEvent):
    """Emitted when conflicting authorization intelligence is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject: str,
        conflict_type: str,
        *,
        selected: str = "",
        mission_id: str = "",
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.conflict.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject": subject,
                "conflict_type": conflict_type,
                "selected": selected,
            },
            source=source,
        )


class AuthorizationCorrelationCompletedEvent(DomainEvent):
    """Emitted when authorization observations are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_observations: int,
        correlated_observations: int,
        conflicts: int,
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_observations": raw_observations,
                "correlated_observations": correlated_observations,
                "conflicts": conflicts,
            },
            source=source,
        )


class AuthorizationDiscoveryCompletedEvent(DomainEvent):
    """Emitted when an authorization intelligence run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        resources: int,
        roles: int,
        permissions: int,
        admin_surfaces: int,
        changes: int,
        conflicts: int,
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.discovery.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "resources": resources,
                "roles": roles,
                "permissions": permissions,
                "admin_surfaces": admin_surfaces,
                "changes": changes,
                "conflicts": conflicts,
            },
            source=source,
        )


class AuthorizationDiscoveryFailedEvent(DomainEvent):
    """Emitted when an authorization intelligence run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "authorization.service",
    ) -> None:
        super().__init__(
            event_type="authorization.discovery.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


# ---------------------------------------------------------------------------
# Cloud & SaaS intelligence events (Sprint 017 / Wave 11)
# ---------------------------------------------------------------------------


class CloudIntelligenceStartedEvent(DomainEvent):
    """Emitted when a cloud & SaaS intelligence run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        *,
        mode: str = "hybrid",
        tools: list[str] | None = None,
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.intelligence.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "mode": mode,
                "tools": tools or [],
            },
            source=source,
        )


class CloudPhaseStartedEvent(DomainEvent):
    """Emitted when a cloud intelligence pipeline phase begins."""

    def __init__(
        self,
        correlation_id: str,
        phase: str,
        *,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.phase.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "phase": phase,
            },
            source=source,
        )


class CloudProviderDiscoveredEvent(DomainEvent):
    """Emitted when a cloud provider is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.provider.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "confidence": confidence,
            },
            source=source,
        )


class CloudAccountDiscoveredEvent(DomainEvent):
    """Emitted when a cloud account/subscription/project indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        kind: str = "account",
        value: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.account.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "kind": kind,
                "value": value,
                "confidence": confidence,
            },
            source=source,
        )


class CloudRegionDiscoveredEvent(DomainEvent):
    """Emitted when a cloud region is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        region: str,
        *,
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.region.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "region": region,
                "confidence": confidence,
            },
            source=source,
        )


class CloudResourceDiscoveredEvent(DomainEvent):
    """Emitted when a cloud resource is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        resource_kind: str = "unknown",
        identifier: str = "",
        service: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.resource.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "resource_kind": resource_kind,
                "identifier": identifier,
                "service": service,
                "confidence": confidence,
            },
            source=source,
        )


class CloudServiceDiscoveredEvent(DomainEvent):
    """Emitted when a cloud service is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        service: str,
        *,
        category: str = "unknown",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.service.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "service": service,
                "category": category,
                "confidence": confidence,
            },
            source=source,
        )


class CloudEndpointDiscoveredEvent(DomainEvent):
    """Emitted when a cloud endpoint is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        endpoint: str,
        provider: str,
        *,
        service: str = "",
        plane: str = "unknown",
        exposure: str = "unknown",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.endpoint.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "endpoint": endpoint,
                "provider": provider,
                "service": service,
                "plane": plane,
                "exposure": exposure,
                "confidence": confidence,
            },
            source=source,
        )


class CloudStorageDiscoveredEvent(DomainEvent):
    """Emitted when a cloud storage indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        storage_kind: str = "object",
        identifier: str = "",
        public: str = "unknown",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.storage.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "storage_kind": storage_kind,
                "identifier": identifier,
                "public": public,
                "confidence": confidence,
            },
            source=source,
        )


class CloudComputeDiscoveredEvent(DomainEvent):
    """Emitted when a cloud compute indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        compute_kind: str = "instance",
        identifier: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.compute.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "compute_kind": compute_kind,
                "identifier": identifier,
                "confidence": confidence,
            },
            source=source,
        )


class CloudContainerDiscoveredEvent(DomainEvent):
    """Emitted when a container indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        container_kind: str = "registry",
        identifier: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.container.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "container_kind": container_kind,
                "identifier": identifier,
                "confidence": confidence,
            },
            source=source,
        )


class CloudKubernetesDiscoveredEvent(DomainEvent):
    """Emitted when a Kubernetes indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        cluster: str = "",
        kind: str = "unknown",
        name: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.kubernetes.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "cluster": cluster,
                "kind": kind,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class CloudServerlessDiscoveredEvent(DomainEvent):
    """Emitted when a serverless indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        identifier: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.serverless.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "identifier": identifier,
                "confidence": confidence,
            },
            source=source,
        )


class CloudDatabaseDiscoveredEvent(DomainEvent):
    """Emitted when a cloud database indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        database_kind: str = "managed",
        identifier: str = "",
        technology: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.database.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "database_kind": database_kind,
                "identifier": identifier,
                "technology": technology,
                "confidence": confidence,
            },
            source=source,
        )


class CloudGatewayDiscoveredEvent(DomainEvent):
    """Emitted when an API gateway is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        gateway_kind: str = "gateway",
        identifier: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.gateway.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "gateway_kind": gateway_kind,
                "identifier": identifier,
                "confidence": confidence,
            },
            source=source,
        )


class CloudCdnDiscoveredEvent(DomainEvent):
    """Emitted when a CDN is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        identifier: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.cdn.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "identifier": identifier,
                "confidence": confidence,
            },
            source=source,
        )


class CloudLoadBalancerDiscoveredEvent(DomainEvent):
    """Emitted when a load balancer is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        identifier: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.load_balancer.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "identifier": identifier,
                "confidence": confidence,
            },
            source=source,
        )


class CloudIdentityDiscoveredEvent(DomainEvent):
    """Emitted when a cloud identity indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        identity_kind: str = "unknown",
        name: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.identity.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "identity_kind": identity_kind,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class CloudIamDiscoveredEvent(DomainEvent):
    """Emitted when a cloud IAM indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        *,
        kind: str = "role",
        name: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.iam.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "kind": kind,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class CloudEnvironmentDiscoveredEvent(DomainEvent):
    """Emitted when a cloud environment indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        provider: str,
        environment: str,
        *,
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.environment.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "provider": provider,
                "environment": environment,
                "confidence": confidence,
            },
            source=source,
        )


class CloudSaasDiscoveredEvent(DomainEvent):
    """Emitted when a SaaS provider is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.saas.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "confidence": confidence,
            },
            source=source,
        )


class CloudSaasIntegrationDiscoveredEvent(DomainEvent):
    """Emitted when a SaaS integration is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        saas_provider: str,
        *,
        integration_type: str = "unknown",
        name: str = "",
        endpoint: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.saas_integration.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "saas_provider": saas_provider,
                "integration_type": integration_type,
                "name": name,
                "endpoint": endpoint,
                "confidence": confidence,
            },
            source=source,
        )


class CloudWebhookDiscoveredEvent(DomainEvent):
    """Emitted when a webhook is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        endpoint: str,
        *,
        direction: str = "unknown",
        provider: str = "",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.webhook.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "endpoint": endpoint,
                "direction": direction,
                "provider": provider,
                "confidence": confidence,
            },
            source=source,
        )


class CloudDependencyDiscoveredEvent(DomainEvent):
    """Emitted when a cloud/third-party dependency is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        name: str,
        *,
        provider: str = "",
        kind: str = "unknown",
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.dependency.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "name": name,
                "provider": provider,
                "kind": kind,
                "confidence": confidence,
            },
            source=source,
        )


class CloudExposureDiscoveredEvent(DomainEvent):
    """Emitted when a cloud exposure indicator is discovered."""

    def __init__(
        self,
        correlation_id: str,
        origin: str,
        kind: str,
        subject: str,
        *,
        confidence: float,
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.exposure.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "origin": origin,
                "kind": kind,
                "subject": subject,
                "confidence": confidence,
            },
            source=source,
        )


class CloudChangeDetectedEvent(DomainEvent):
    """Emitted when a cloud architecture change is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject_type: str,
        subject: str,
        change_type: str,
        *,
        previous: str = "",
        current: str = "",
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.change.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject_type": subject_type,
                "subject": subject,
                "change_type": change_type,
                "previous": previous,
                "current": current,
            },
            source=source,
        )


class CloudConflictDetectedEvent(DomainEvent):
    """Emitted when conflicting cloud intelligence is detected."""

    def __init__(
        self,
        correlation_id: str,
        subject: str,
        conflict_type: str,
        *,
        selected: str = "",
        mission_id: str = "",
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.conflict.detected",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "subject": subject,
                "conflict_type": conflict_type,
                "selected": selected,
            },
            source=source,
        )


class CloudCorrelationCompletedEvent(DomainEvent):
    """Emitted when cloud observations are correlated."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        raw_observations: int,
        correlated_observations: int,
        conflicts: int,
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.correlation.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "raw_observations": raw_observations,
                "correlated_observations": correlated_observations,
                "conflicts": conflicts,
            },
            source=source,
        )


class CloudIntelligenceCompletedEvent(DomainEvent):
    """Emitted when a cloud intelligence run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        providers: int,
        accounts: int,
        regions: int,
        resources: int,
        services: int,
        endpoints: int,
        environments: int,
        identities: int,
        saas_providers: int,
        saas_integrations: int,
        webhooks: int,
        changes: int,
        conflicts: int,
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.intelligence.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "providers": providers,
                "accounts": accounts,
                "regions": regions,
                "resources": resources,
                "services": services,
                "endpoints": endpoints,
                "environments": environments,
                "identities": identities,
                "saas_providers": saas_providers,
                "saas_integrations": saas_integrations,
                "webhooks": webhooks,
                "changes": changes,
                "conflicts": conflicts,
            },
            source=source,
        )


class CloudIntelligenceFailedEvent(DomainEvent):
    """Emitted when a cloud intelligence run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "cloud.service",
    ) -> None:
        super().__init__(
            event_type="cloud.intelligence.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class VulnerabilityKnowledgeRefreshStartedEvent(DomainEvent):
    """Emitted when a vulnerability knowledge refresh run begins."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        sources: list[str] | None = None,
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.knowledge.refresh.started",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "sources": sources or [],
            },
            source=source,
        )


class VulnerabilityKnowledgeSourceUpdatedEvent(DomainEvent):
    """Emitted when a knowledge source is refreshed."""

    def __init__(
        self,
        correlation_id: str,
        source_name: str,
        *,
        records: int = 0,
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.knowledge.source.updated",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "source": source_name,
                "records": records,
            },
            source=source,
        )


class VulnerabilityCveDiscoveredEvent(DomainEvent):
    """Emitted when a canonical CVE is discovered/refreshed."""

    def __init__(
        self,
        correlation_id: str,
        cve_id: str,
        *,
        source_name: str = "",
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.cve.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "cve_id": cve_id,
                "source": source_name,
            },
            source=source,
        )


class VulnerabilityCweDiscoveredEvent(DomainEvent):
    """Emitted when a canonical CWE is discovered/refreshed."""

    def __init__(
        self,
        correlation_id: str,
        cwe_id: str,
        *,
        source_name: str = "",
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.cwe.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "cwe_id": cwe_id,
                "source": source_name,
            },
            source=source,
        )


class VulnerabilityCpeDiscoveredEvent(DomainEvent):
    """Emitted when a canonical CPE is discovered."""

    def __init__(
        self,
        correlation_id: str,
        cpe: str,
        *,
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.cpe.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "cpe": cpe,
            },
            source=source,
        )


class VulnerabilityAdvisoryDiscoveredEvent(DomainEvent):
    """Emitted when a vendor advisory is discovered/refreshed."""

    def __init__(
        self,
        correlation_id: str,
        advisory_id: str,
        *,
        vendor: str = "",
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.advisory.discovered",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "advisory_id": advisory_id,
                "vendor": vendor,
            },
            source=source,
        )


class VulnerabilityMatchCreatedEvent(DomainEvent):
    """Emitted when a technology→vulnerability match is created."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        cve_id: str,
        *,
        state: str = "possible_match",
        confidence: float = 0.0,
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.match.created",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "cve_id": cve_id,
                "state": state,
                "confidence": confidence,
            },
            source=source,
        )


class VulnerabilityMatchRemovedEvent(DomainEvent):
    """Emitted when a technology→vulnerability match is removed."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        cve_id: str,
        *,
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.match.removed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "cve_id": cve_id,
            },
            source=source,
        )


class VulnerabilityVersionMatchChangedEvent(DomainEvent):
    """Emitted when a match's version evidence changes between missions."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        technology: str,
        cve_id: str,
        *,
        old_version: str = "",
        new_version: str = "",
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.version_match.changed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "technology": technology,
                "cve_id": cve_id,
                "old_version": old_version,
                "new_version": new_version,
            },
            source=source,
        )


class VulnerabilityKevStatusChangedEvent(DomainEvent):
    """Emitted when a CVE's KEV membership changes."""

    def __init__(
        self,
        correlation_id: str,
        cve_id: str,
        *,
        in_kev: bool = False,
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.kev.changed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "cve_id": cve_id,
                "in_kev": in_kev,
            },
            source=source,
        )


class VulnerabilityEpssChangedEvent(DomainEvent):
    """Emitted when a CVE's EPSS score changes."""

    def __init__(
        self,
        correlation_id: str,
        cve_id: str,
        *,
        old_epss: float = 0.0,
        new_epss: float = 0.0,
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.epss.changed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "cve_id": cve_id,
                "old_epss": old_epss,
                "new_epss": new_epss,
            },
            source=source,
        )


class VulnerabilityExploitabilityIndicatorChangedEvent(DomainEvent):
    """Emitted when a CVE's exploitability indicator changes."""

    def __init__(
        self,
        correlation_id: str,
        cve_id: str,
        *,
        availability: str = "unknown",
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.exploitability.changed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "cve_id": cve_id,
                "availability": availability,
            },
            source=source,
        )


class VulnerabilityRiskAssessmentCreatedEvent(DomainEvent):
    """Emitted when a risk assessment is created."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        cve_id: str,
        *,
        score: float = 0.0,
        priority: str = "unknown",
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.risk.created",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "cve_id": cve_id,
                "score": score,
                "priority": priority,
            },
            source=source,
        )


class VulnerabilityRiskAssessmentChangedEvent(DomainEvent):
    """Emitted when a risk assessment changes."""

    def __init__(
        self,
        correlation_id: str,
        asset: str,
        cve_id: str,
        *,
        old_score: float = 0.0,
        new_score: float = 0.0,
        mission_id: str = "",
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.risk.changed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "asset": asset,
                "cve_id": cve_id,
                "old_score": old_score,
                "new_score": new_score,
            },
            source=source,
        )


class VulnerabilityIntelligenceCompletedEvent(DomainEvent):
    """Emitted when a vulnerability intelligence run finishes."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        *,
        target: str,
        matches: int,
        relevant: int,
        risks: int,
        changes: int,
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.intelligence.completed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "matches": matches,
                "relevant": relevant,
                "risks": risks,
                "changes": changes,
            },
            source=source,
        )


class VulnerabilityIntelligenceFailedEvent(DomainEvent):
    """Emitted when a vulnerability intelligence run fails."""

    def __init__(
        self,
        mission_id: str,
        correlation_id: str,
        target: str,
        error: str,
        *,
        source: str = "vulnerability.service",
    ) -> None:
        super().__init__(
            event_type="vulnerability.intelligence.failed",
            payload={
                "mission_id": mission_id,
                "correlation_id": correlation_id,
                "target": target,
                "error": error,
            },
            source=source,
        )


class VulnerabilityHypothesisCreatedEvent(DomainEvent):
    """Emitted when a vulnerability hypothesis is created."""

    def __init__(
        self,
        hypothesis_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        class_name: str = "known_vulnerable_software",
        confidence: float = 0.0,
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.hypothesis.created",
            payload={
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "class": class_name,
                "confidence": confidence,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityValidationPlannedEvent(DomainEvent):
    """Emitted when a validation plan is created for a hypothesis."""

    def __init__(
        self,
        plan_id: str,
        hypothesis_id: str,
        *,
        mission_id: str = "",
        strategy: str = "version_validation",
        steps: int = 0,
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.validation.planned",
            payload={
                "plan_id": plan_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "strategy": strategy,
                "steps": steps,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityValidationStartedEvent(DomainEvent):
    """Emitted when a validation execution starts."""

    def __init__(
        self,
        validation_id: str,
        hypothesis_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        plan_id: str = "",
        tool_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.validation.started",
            payload={
                "validation_id": validation_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "plan_id": plan_id,
                "tool_id": tool_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityValidationStepStartedEvent(DomainEvent):
    """Emitted when a validation step starts."""

    def __init__(
        self,
        validation_id: str,
        step_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        action: str = "",
        tool_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.validation.step.started",
            payload={
                "validation_id": validation_id,
                "step_id": step_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "action": action,
                "tool_id": tool_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityValidationStepCompletedEvent(DomainEvent):
    """Emitted when a validation step completes."""

    def __init__(
        self,
        validation_id: str,
        step_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        action: str = "",
        observations: int = 0,
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.validation.step.completed",
            payload={
                "validation_id": validation_id,
                "step_id": step_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "action": action,
                "observations": observations,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityValidationBlockedEvent(DomainEvent):
    """Emitted when a validation action is blocked by scope/safety policy."""

    def __init__(
        self,
        validation_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        reason: str = "scope_blocked",
        kind: str = "scope",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.validation.blocked",
            payload={
                "validation_id": validation_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "reason": reason,
                "kind": kind,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityValidationFailedEvent(DomainEvent):
    """Emitted when a validation execution fails."""

    def __init__(
        self,
        validation_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        error: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.validation.failed",
            payload={
                "validation_id": validation_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "error": error,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityEvidenceCreatedEvent(DomainEvent):
    """Emitted when validation evidence is created."""

    def __init__(
        self,
        evidence_id: str,
        validation_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        tool_id: str = "",
        comparison: str = "no_comparison",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.evidence.created",
            payload={
                "evidence_id": evidence_id,
                "validation_id": validation_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "asset_id": asset_id,
                "tool_id": tool_id,
                "comparison": comparison,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityVerdictCreatedEvent(DomainEvent):
    """Emitted when a validation verdict is produced."""

    def __init__(
        self,
        verdict_id: str,
        validation_id: str,
        hypothesis_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        result: str = "inconclusive",
        confidence: float = 0.0,
        evidence_ids: list[str] | None = None,
        rule_ids: list[str] | None = None,
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.verdict.created",
            payload={
                "verdict_id": verdict_id,
                "validation_id": validation_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "result": result,
                "confidence": confidence,
                "evidence_ids": evidence_ids or [],
                "rule_ids": rule_ids or [],
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityConfirmedEvent(DomainEvent):
    """Emitted when a vulnerability hypothesis is confirmed."""

    def __init__(
        self,
        hypothesis_id: str,
        verdict_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        confidence: float = 0.0,
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.confirmed",
            payload={
                "hypothesis_id": hypothesis_id,
                "verdict_id": verdict_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "confidence": confidence,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityFalsePositiveEvent(DomainEvent):
    """Emitted when a vulnerability hypothesis is refuted as a false positive."""

    def __init__(
        self,
        hypothesis_id: str,
        verdict_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.false_positive",
            payload={
                "hypothesis_id": hypothesis_id,
                "verdict_id": verdict_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityInconclusiveEvent(DomainEvent):
    """Emitted when a vulnerability hypothesis is left inconclusive."""

    def __init__(
        self,
        hypothesis_id: str,
        verdict_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.inconclusive",
            payload={
                "hypothesis_id": hypothesis_id,
                "verdict_id": verdict_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityResolvedEvent(DomainEvent):
    """Emitted when a confirmed vulnerability is resolved."""

    def __init__(
        self,
        hypothesis_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.resolved",
            payload={
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityReopenedEvent(DomainEvent):
    """Emitted when a resolved vulnerability is reopened."""

    def __init__(
        self,
        hypothesis_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.reopened",
            payload={
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityValidationCompletedEvent(DomainEvent):
    """Emitted when a validation execution completes."""

    def __init__(
        self,
        validation_id: str,
        hypothesis_id: str,
        *,
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        result: str = "inconclusive",
        confidence: float = 0.0,
        evidence: int = 0,
        duration_ms: int = 0,
        correlation_id: str | None = None,
        source: str = "vulnerability.validation",
    ) -> None:
        super().__init__(
            event_type="vulnerability.validation.completed",
            payload={
                "validation_id": validation_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "result": result,
                "confidence": confidence,
                "evidence": evidence,
                "duration_ms": duration_ms,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )

class VulnerabilityProofCreatedEvent(DomainEvent):
    """Emitted when a vulnerability proof candidate is created."""

    def __init__(
        self,
        proof_id: str,
        *,
        finding_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        proof_type: str = "behavioral_proof",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.created",
            payload={
                "proof_id": proof_id,
                "finding_id": finding_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "proof_type": proof_type,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofPlannedEvent(DomainEvent):
    """Emitted when a proof plan is created for a proof."""

    def __init__(
        self,
        proof_plan_id: str,
        proof_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        steps: int = 0,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.planned",
            payload={
                "proof_plan_id": proof_plan_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "steps": steps,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStartedEvent(DomainEvent):
    """Emitted when a proof execution starts."""

    def __init__(
        self,
        execution_id: str,
        proof_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        plan_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.started",
            payload={
                "execution_id": execution_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "plan_id": plan_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStepStartedEvent(DomainEvent):
    """Emitted when a proof step starts."""

    def __init__(
        self,
        execution_id: str,
        step_id: str,
        *,
        proof_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        action: str = "",
        tool_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.step.started",
            payload={
                "execution_id": execution_id,
                "step_id": step_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "action": action,
                "tool_id": tool_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStepCompletedEvent(DomainEvent):
    """Emitted when a proof step completes."""

    def __init__(
        self,
        execution_id: str,
        step_id: str,
        *,
        proof_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        action: str = "",
        observations: int = 0,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.step.completed",
            payload={
                "execution_id": execution_id,
                "step_id": step_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "action": action,
                "observations": observations,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofGeneratedEvent(DomainEvent):
    """Emitted when a proof PoC is generated."""

    def __init__(
        self,
        poc_id: str,
        proof_id: str,
        *,
        finding_id: str = "",
        format: str = "request_response",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.generated",
            payload={
                "poc_id": poc_id,
                "proof_id": proof_id,
                "finding_id": finding_id,
                "format": format,
            },
            correlation_id=correlation_id,
            source=source,
        )


class VulnerabilityProofExecutedEvent(DomainEvent):
    """Emitted when a proof execution completes."""

    def __init__(
        self,
        execution_id: str,
        proof_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        observations: int = 0,
        duration_ms: int = 0,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.executed",
            payload={
                "execution_id": execution_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "observations": observations,
                "duration_ms": duration_ms,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofReplayStartedEvent(DomainEvent):
    """Emitted when a proof replay starts."""

    def __init__(
        self,
        replay_id: str,
        proof_id: str,
        *,
        poc_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.replay.started",
            payload={
                "replay_id": replay_id,
                "proof_id": proof_id,
                "poc_id": poc_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofReplayCompletedEvent(DomainEvent):
    """Emitted when a proof replay completes."""

    def __init__(
        self,
        replay_id: str,
        proof_id: str,
        *,
        poc_id: str = "",
        result: str = "not_run",
        verdict: str = "inconclusive",
        reproducible: bool = False,
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.replay.completed",
            payload={
                "replay_id": replay_id,
                "proof_id": proof_id,
                "poc_id": poc_id,
                "result": result,
                "verdict": verdict,
                "reproducible": reproducible,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofValidatedEvent(DomainEvent):
    """Emitted when a proof is validated."""

    def __init__(
        self,
        proof_id: str,
        *,
        finding_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        confidence: float = 0.0,
        reproducibility: str = "not_assessed",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.validated",
            payload={
                "proof_id": proof_id,
                "finding_id": finding_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "confidence": confidence,
                "reproducibility": reproducibility,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofFailedEvent(DomainEvent):
    """Emitted when a proof fails."""

    def __init__(
        self,
        proof_id: str,
        *,
        finding_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        reason: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.failed",
            payload={
                "proof_id": proof_id,
                "finding_id": finding_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "reason": reason,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofBlockedEvent(DomainEvent):
    """Emitted when a proof action is blocked by scope/safety/proof policy."""

    def __init__(
        self,
        proof_id: str,
        *,
        finding_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        reason: str = "scope_blocked",
        kind: str = "scope",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.blocked",
            payload={
                "proof_id": proof_id,
                "finding_id": finding_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "reason": reason,
                "kind": kind,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofInconclusiveEvent(DomainEvent):
    """Emitted when a proof is left inconclusive."""

    def __init__(
        self,
        proof_id: str,
        *,
        finding_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        reason: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.inconclusive",
            payload={
                "proof_id": proof_id,
                "finding_id": finding_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "reason": reason,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofInvalidatedEvent(DomainEvent):
    """Emitted when a proof is invalidated."""

    def __init__(
        self,
        proof_id: str,
        *,
        finding_id: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        reason: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="proof.invalidated",
            payload={
                "proof_id": proof_id,
                "finding_id": finding_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "reason": reason,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityPocCreatedEvent(DomainEvent):
    """Emitted when a PoC artifact is created (or versioned)."""

    def __init__(
        self,
        poc_id: str,
        *,
        proof_id: str = "",
        finding_id: str = "",
        format: str = "request_response",
        version: str = "1.0.0",
        parent_version: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="poc.created",
            payload={
                "poc_id": poc_id,
                "proof_id": proof_id,
                "finding_id": finding_id,
                "format": format,
                "version": version,
                "parent_version": parent_version,
            },
            correlation_id=correlation_id,
            source=source,
        )


class VulnerabilityPocValidatedEvent(DomainEvent):
    """Emitted when a PoC is validated through replay."""

    def __init__(
        self,
        poc_id: str,
        *,
        proof_id: str = "",
        version: str = "1.0.0",
        reproducible: bool = False,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="poc.validated",
            payload={
                "poc_id": poc_id,
                "proof_id": proof_id,
                "version": version,
                "reproducible": reproducible,
            },
            correlation_id=correlation_id,
            source=source,
        )


class VulnerabilityImpactAssessedEvent(DomainEvent):
    """Emitted when an impact assessment is produced."""

    def __init__(
        self,
        impact_id: str,
        proof_id: str,
        *,
        finding_id: str = "",
        impact_type: str = "confidentiality",
        impact_level: str = "none",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="impact.assessed",
            payload={
                "impact_id": impact_id,
                "proof_id": proof_id,
                "finding_id": finding_id,
                "impact_type": impact_type,
                "impact_level": impact_level,
            },
            correlation_id=correlation_id,
            source=source,
        )


class VulnerabilityConfidenceCalculatedEvent(DomainEvent):
    """Emitted when a confidence assessment is calculated."""

    def __init__(
        self,
        confidence_id: str,
        proof_id: str,
        *,
        finding_id: str = "",
        confidence: float = 0.0,
        state: str = "low",
        policy_id: str = "confidence-policy/1.0.0",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="confidence.calculated",
            payload={
                "confidence_id": confidence_id,
                "proof_id": proof_id,
                "finding_id": finding_id,
                "confidence": confidence,
                "state": state,
                "policy_id": policy_id,
            },
            correlation_id=correlation_id,
            source=source,
        )


class VulnerabilityFindingProvenEvent(DomainEvent):
    """Emitted when a finding becomes PROVEN."""

    def __init__(
        self,
        finding_id: str,
        proof_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        confidence: float = 0.0,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="finding.proven",
            payload={
                "finding_id": finding_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "confidence": confidence,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityFindingConfirmedEvent(DomainEvent):
    """Emitted when a finding becomes CONFIRMED."""

    def __init__(
        self,
        finding_id: str,
        proof_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        confidence: float = 0.0,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="finding.confirmed",
            payload={
                "finding_id": finding_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "confidence": confidence,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityFindingReportReadyEvent(DomainEvent):
    """Emitted when a finding becomes REPORT_READY."""

    def __init__(
        self,
        finding_id: str,
        proof_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        asset_id: str = "",
        vulnerability_id: str = "",
        reportable: bool = True,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof",
    ) -> None:
        super().__init__(
            event_type="finding.report_ready",
            payload={
                "finding_id": finding_id,
                "proof_id": proof_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "asset_id": asset_id,
                "vulnerability_id": vulnerability_id,
                "reportable": reportable,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStrategySelectedEvent(DomainEvent):
    """Emitted when a proof strategy is selected for a vulnerability candidate."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        *,
        vulnerability_class: str = "unknown_behavior",
        strategy_version: str = "1.0.0",
        hypothesis_id: str = "",
        mission_id: str = "",
        target_id: str = "",
        risk_level: str = "low",
        executability: str = "executable",
        reasoning: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.strategy.selected",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "strategy_version": strategy_version,
                "vulnerability_class": vulnerability_class,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "target_id": target_id,
                "risk_level": risk_level,
                "executability": executability,
                "reasoning": reasoning,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStrategyBlockedEvent(DomainEvent):
    """Emitted when no usable strategy can be selected for a candidate."""

    def __init__(
        self,
        proof_id: str,
        *,
        vulnerability_class: str = "unknown_behavior",
        hypothesis_id: str = "",
        mission_id: str = "",
        reason: str = "",
        blocked_strategies: list[str] | None = None,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.strategy.blocked",
            payload={
                "proof_id": proof_id,
                "vulnerability_class": vulnerability_class,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "reason": reason,
                "blocked_strategies": blocked_strategies or [],
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStrategyMissingEvidenceEvent(DomainEvent):
    """Emitted when a strategy needs evidence that is not yet available."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        *,
        missing_evidence: list[str] | None = None,
        hypothesis_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.strategy.missing_evidence",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "missing_evidence": missing_evidence or [],
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofValidationStartedEvent(DomainEvent):
    """Emitted when a proof validation begins."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        *,
        hypothesis_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.validation.started",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofValidationCompletedEvent(DomainEvent):
    """Emitted when a proof validation completes with a verdict."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        verdict: str,
        *,
        score: float = 0.0,
        proof_quality_level: str = "p0_candidate",
        hypothesis_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.validation.completed",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "verdict": verdict,
                "score": score,
                "proof_quality_level": proof_quality_level,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofValidationFailedEvent(DomainEvent):
    """Emitted when a proof validation fails (invalid/unsafe/blocked)."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        verdict: str,
        *,
        reason: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.validation.failed",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "verdict": verdict,
                "reason": reason,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofValidationInconclusiveEvent(DomainEvent):
    """Emitted when a proof validation is inconclusive."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        *,
        reason: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.validation.inconclusive",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "reason": reason,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofValidationContradictedEvent(DomainEvent):
    """Emitted when a proof validation finds contradictory evidence."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        *,
        contradictory_evidence: list[str] | None = None,
        hypothesis_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.validation.contradicted",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "contradictory_evidence": contradictory_evidence or [],
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofManualRequiredEvent(DomainEvent):
    """Emitted when automation cannot safely establish proof."""

    def __init__(
        self,
        proof_id: str,
        strategy_id: str,
        instruction_id: str,
        *,
        objective: str = "",
        hypothesis_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.manual_required",
            payload={
                "proof_id": proof_id,
                "strategy_id": strategy_id,
                "instruction_id": instruction_id,
                "objective": objective,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStrategyCandidateCreatedEvent(DomainEvent):
    """Emitted when a novel strategy candidate is proposed."""

    def __init__(
        self,
        candidate_id: str,
        *,
        vulnerability_class: str = "unknown_behavior",
        hypothesis_id: str = "",
        mission_id: str = "",
        review_required: bool = True,
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.strategy.candidate_created",
            payload={
                "candidate_id": candidate_id,
                "vulnerability_class": vulnerability_class,
                "hypothesis_id": hypothesis_id,
                "mission_id": mission_id,
                "review_required": review_required,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStrategyCandidateApprovedEvent(DomainEvent):
    """Emitted when a strategy candidate is approved."""

    def __init__(
        self,
        candidate_id: str,
        strategy_id: str,
        *,
        vulnerability_class: str = "unknown_behavior",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.strategy.approved",
            payload={
                "candidate_id": candidate_id,
                "strategy_id": strategy_id,
                "vulnerability_class": vulnerability_class,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class VulnerabilityProofStrategyCandidateRejectedEvent(DomainEvent):
    """Emitted when a strategy candidate is rejected."""

    def __init__(
        self,
        candidate_id: str,
        *,
        reason: str = "",
        vulnerability_class: str = "unknown_behavior",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "vulnerability.proof.strategy",
    ) -> None:
        super().__init__(
            event_type="proof.strategy.rejected",
            payload={
                "candidate_id": candidate_id,
                "reason": reason,
                "vulnerability_class": vulnerability_class,
                "mission_id": mission_id,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class _FindingOrchestrationEvent(DomainEvent):
    """Base for Sprint 028 finding lifecycle events.

    Every orchestration event carries the scoping and provenance fields the
    finding lifecycle requires: ``mission_id``, ``target_id``, ``finding_id``,
    ``asset_id``, ``correlation_id`` and ``provenance`` in addition to the
    envelope timestamp.
    """

    _event_type = "finding.updated"

    def __init__(
        self,
        event_type: str,
        *,
        finding_id: str,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
        **extra: object,
    ) -> None:
        payload: dict[str, object] = {
            "finding_id": finding_id,
            "target_id": target_id,
            "mission_id": mission_id,
            "asset_id": asset_id,
            "provenance": provenance,
        }
        payload.update(extra)
        super().__init__(
            event_type=event_type,
            payload=payload,
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class FindingOrchestrationCreatedEvent(_FindingOrchestrationEvent):
    """Emitted when an orchestrated finding is created (CANDIDATE)."""

    def __init__(
        self,
        finding_id: str,
        *,
        vulnerability_class: str = "unknown_behavior",
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.created",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            vulnerability_class=vulnerability_class,
        )


class FindingSupportedEvent(_FindingOrchestrationEvent):
    """Emitted when a finding gains hypothesis-supporting evidence."""

    def __init__(
        self,
        finding_id: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.supported",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
        )


class FindingValidationStartedEvent(_FindingOrchestrationEvent):
    """Emitted when finding validation starts."""

    def __init__(
        self,
        finding_id: str,
        validation_id: str,
        *,
        strategy_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.validation.started",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            validation_id=validation_id,
            strategy_id=strategy_id,
        )


class FindingValidationCompletedEvent(_FindingOrchestrationEvent):
    """Emitted when finding validation completes with a verdict."""

    def __init__(
        self,
        finding_id: str,
        validation_id: str,
        verdict: str,
        *,
        status: str = "completed",
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.validation.completed",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            validation_id=validation_id,
            verdict=verdict,
            status=status,
        )


class FindingEvidenceAddedEvent(_FindingOrchestrationEvent):
    """Emitted when evidence is added to a finding."""

    def __init__(
        self,
        finding_id: str,
        evidence_id: str,
        evidence_kind: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.evidence.added",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            evidence_id=evidence_id,
            evidence_kind=evidence_kind,
        )


class FindingEvidenceConflictEvent(_FindingOrchestrationEvent):
    """Emitted when contradictory evidence is detected."""

    def __init__(
        self,
        finding_id: str,
        conflict_id: str,
        conflict_kind: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.evidence.conflict",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            conflict_id=conflict_id,
            conflict_kind=conflict_kind,
        )


class FindingProofRequiredEvent(_FindingOrchestrationEvent):
    """Emitted when a validated finding requires proof."""

    def __init__(
        self,
        finding_id: str,
        *,
        proof_strategy_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.proof.required",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            proof_strategy_id=proof_strategy_id,
        )


class FindingProofStartedEvent(_FindingOrchestrationEvent):
    """Emitted when proof generation/execution starts."""

    def __init__(
        self,
        finding_id: str,
        poc_id: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.proof.started",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            poc_id=poc_id,
        )


class FindingProofReplayedEvent(_FindingOrchestrationEvent):
    """Emitted when a PoC is replayed under controlled conditions."""

    def __init__(
        self,
        finding_id: str,
        replay_id: str,
        verdict: str,
        *,
        poc_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.proof.replayed",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            replay_id=replay_id,
            verdict=verdict,
            poc_id=poc_id,
        )


class FindingProofValidatedEvent(_FindingOrchestrationEvent):
    """Emitted when a proof is validated (PoC reached PROOF_VALIDATED)."""

    def __init__(
        self,
        finding_id: str,
        poc_id: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.proof.validated",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            poc_id=poc_id,
        )


class FindingImpactAssessedEvent(_FindingOrchestrationEvent):
    """Emitted when an evidence-backed impact assessment is produced."""

    def __init__(
        self,
        finding_id: str,
        assessment_id: str,
        *,
        dimensions: tuple[str, ...] = (),
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.impact.assessed",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            assessment_id=assessment_id,
            dimensions=list(dimensions),
        )


class FindingConfidenceUpdatedEvent(_FindingOrchestrationEvent):
    """Emitted when the evidence-driven confidence is updated."""

    def __init__(
        self,
        finding_id: str,
        assessment_id: str,
        score: float,
        level: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.confidence.updated",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            assessment_id=assessment_id,
            score=score,
            level=level,
        )


class FindingDuplicateDetectedEvent(_FindingOrchestrationEvent):
    """Emitted when a finding is correlated as a duplicate."""

    def __init__(
        self,
        finding_id: str,
        matched_finding_id: str,
        relation: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.duplicate.detected",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            matched_finding_id=matched_finding_id,
            relation=relation,
        )


class FindingDisprovedEvent(_FindingOrchestrationEvent):
    """Emitted when a finding is disproved by contradictory evidence."""

    def __init__(
        self,
        finding_id: str,
        reason: str,
        *,
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.disproved",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            reason=reason,
        )


class FindingReportReadyEvent(_FindingOrchestrationEvent):
    """Emitted when a finding becomes REPORT_READY."""

    def __init__(
        self,
        finding_id: str,
        *,
        checklist_id: str = "",
        package_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        asset_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "vulnerability.finding",
    ) -> None:
        super().__init__(
            "finding.report_ready",
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            checklist_id=checklist_id,
            package_id=package_id,
        )


class _ReportEvent(DomainEvent):
    """Base for Sprint 029 professional reporting events.

    Every report event carries the scoping and provenance fields the report
    lifecycle requires: ``mission_id``, ``target_id``, ``finding_id``,
    ``report_id``, ``correlation_id`` and ``provenance`` in addition to the
    envelope timestamp.
    """

    def __init__(
        self,
        event_type: str,
        *,
        report_id: str,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
        **extra: object,
    ) -> None:
        payload: dict[str, object] = {
            "report_id": report_id,
            "finding_id": finding_id,
            "target_id": target_id,
            "mission_id": mission_id,
            "provenance": provenance,
        }
        payload.update(extra)
        super().__init__(
            event_type=event_type,
            payload=payload,
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class ReportCreatedEvent(_ReportEvent):
    """Emitted when a professional report is created."""

    def __init__(
        self,
        report_id: str,
        *,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        template: str = "pentest",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.created",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            template=template,
        )


class ReportUpdatedEvent(_ReportEvent):
    """Emitted when a professional report transitions state."""

    def __init__(
        self,
        report_id: str,
        *,
        from_state: str = "",
        to_state: str = "",
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.updated",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            from_state=from_state,
            to_state=to_state,
        )


class ReportQaStartedEvent(_ReportEvent):
    """Emitted when report QA begins."""

    def __init__(
        self,
        report_id: str,
        *,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.qa.started",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
        )


class ReportQaPassedEvent(_ReportEvent):
    """Emitted when report QA passes."""

    def __init__(
        self,
        report_id: str,
        *,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.qa.passed",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
        )


class ReportQaFailedEvent(_ReportEvent):
    """Emitted when report QA finds blocking defects."""

    def __init__(
        self,
        report_id: str,
        *,
        reasons: tuple[str, ...] = (),
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.qa.failed",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            reasons=list(reasons),
        )


class ReportGeneratedEvent(_ReportEvent):
    """Emitted when a report version is generated."""

    def __init__(
        self,
        report_id: str,
        *,
        version: int = 1,
        content_hash: str = "",
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.generated",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            version=version,
            content_hash=content_hash,
        )


class ReportExportedEvent(_ReportEvent):
    """Emitted when a report is exported."""

    def __init__(
        self,
        report_id: str,
        *,
        fmt: str = "markdown",
        version: int = 1,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.exported",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            format=fmt,
            version=version,
        )


class ReportSubmissionReadyEvent(_ReportEvent):
    """Emitted when a report becomes READY_FOR_SUBMISSION."""

    def __init__(
        self,
        report_id: str,
        *,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.submission_ready",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
        )


class ReportRetestStartedEvent(_ReportEvent):
    """Emitted when a report retest begins."""

    def __init__(
        self,
        report_id: str,
        *,
        retest_plan_id: str = "",
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.retest.started",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            retest_plan_id=retest_plan_id,
        )


class ReportRetestCompletedEvent(_ReportEvent):
    """Emitted when a report retest completes."""

    def __init__(
        self,
        report_id: str,
        *,
        retest_state: str = "completed",
        fix_verified: bool = False,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.retest.completed",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
            retest_state=retest_state,
            fix_verified=fix_verified,
        )


class ReportClosedEvent(_ReportEvent):
    """Emitted when a report is closed."""

    def __init__(
        self,
        report_id: str,
        *,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.closed",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
        )


class ReportReopenedEvent(_ReportEvent):
    """Emitted when a report is reopened."""

    def __init__(
        self,
        report_id: str,
        *,
        finding_id: str = "",
        target_id: str = "",
        mission_id: str = "",
        correlation_id: str | None = None,
        provenance: str = "",
        source: str = "reporting.service",
    ) -> None:
        super().__init__(
            "report.reopened",
            report_id=report_id,
            finding_id=finding_id,
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            provenance=provenance,
            source=source,
        )


class _TargetMemoryEvent(DomainEvent):
    """Base for Sprint 030 target memory events.

    Every target-memory event carries the scoping fields the historical layer
    requires: ``target_id``, ``mission_id`` and ``snapshot_id``/``diff_id`` in
    addition to the envelope timestamp.
    """

    def __init__(
        self,
        event_type: str,
        *,
        target_id: str,
        mission_id: str = "",
        snapshot_id: str = "",
        diff_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
        **extra: object,
    ) -> None:
        payload: dict[str, object] = {
            "target_id": target_id,
            "mission_id": mission_id,
            "snapshot_id": snapshot_id,
            "diff_id": diff_id,
        }
        payload.update(extra)
        super().__init__(
            event_type=event_type,
            payload=payload,
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class TargetMemoryUpdatedEvent(_TargetMemoryEvent):
    """Emitted when target memory observations are recorded."""

    def __init__(
        self,
        target_id: str,
        *,
        mission_id: str = "",
        observation_count: int = 0,
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "target.memory.updated",
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            source=source,
            observation_count=observation_count,
        )


class TargetSnapshotCreatedEvent(_TargetMemoryEvent):
    """Emitted when a reproducible target snapshot is created."""

    def __init__(
        self,
        target_id: str,
        snapshot_id: str,
        *,
        mission_id: str = "",
        state_hash: str = "",
        observation_count: int = 0,
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "target.snapshot.created",
            target_id=target_id,
            mission_id=mission_id,
            snapshot_id=snapshot_id,
            correlation_id=correlation_id,
            source=source,
            state_hash=state_hash,
            observation_count=observation_count,
        )


class TargetDiffCreatedEvent(_TargetMemoryEvent):
    """Emitted when a deterministic snapshot diff is created."""

    def __init__(
        self,
        target_id: str,
        diff_id: str,
        *,
        snapshot_a_id: str = "",
        snapshot_b_id: str = "",
        change_count: int = 0,
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "target.diff.created",
            target_id=target_id,
            diff_id=diff_id,
            correlation_id=correlation_id,
            source=source,
            snapshot_a_id=snapshot_a_id,
            snapshot_b_id=snapshot_b_id,
            change_count=change_count,
        )


class TargetChangeDetectedEvent(_TargetMemoryEvent):
    """Emitted when a significant target change is detected."""

    def __init__(
        self,
        target_id: str,
        *,
        key: str = "",
        kind: str = "",
        significance: str = "low",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "target.change.detected",
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            source=source,
            key=key,
            kind=kind,
            significance=significance,
        )


class TargetObservationStaleEvent(_TargetMemoryEvent):
    """Emitted when a target observation became stale."""

    def __init__(
        self,
        target_id: str,
        *,
        observation_key: str = "",
        freshness: str = "stale",
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "target.observation.stale",
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            source=source,
            observation_key=observation_key,
            freshness=freshness,
        )


class TargetRevalidationRequiredEvent(_TargetMemoryEvent):
    """Emitted when target observations require revalidation."""

    def __init__(
        self,
        target_id: str,
        *,
        plan_id: str = "",
        item_count: int = 0,
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "target.revalidation.required",
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            source=source,
            plan_id=plan_id,
            item_count=item_count,
        )


class CoverageUpdatedEvent(_TargetMemoryEvent):
    """Emitted when target coverage memory was updated."""

    def __init__(
        self,
        target_id: str,
        *,
        coverage_count: int = 0,
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "coverage.updated",
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            source=source,
            coverage_count=coverage_count,
        )


class CoverageGapDetectedEvent(_TargetMemoryEvent):
    """Emitted when a coverage gap is detected."""

    def __init__(
        self,
        target_id: str,
        *,
        campaign_id: str = "",
        gap_count: int = 0,
        mission_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "coverage.gap.detected",
            target_id=target_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            source=source,
            campaign_id=campaign_id,
            gap_count=gap_count,
        )


class _CampaignEvent(DomainEvent):
    """Base for Sprint 030 campaign events."""

    def __init__(
        self,
        event_type: str,
        *,
        campaign_id: str,
        name: str = "",
        status: str = "",
        mission_count: int = 0,
        correlation_id: str | None = None,
        source: str = "target_memory.service",
        **extra: object,
    ) -> None:
        payload: dict[str, object] = {
            "campaign_id": campaign_id,
            "name": name,
            "status": status,
            "mission_count": mission_count,
        }
        payload.update(extra)
        super().__init__(event_type=event_type, payload=payload, correlation_id=correlation_id, source=source)


class CampaignCreatedEvent(_CampaignEvent):
    """Emitted when a campaign is created."""

    def __init__(
        self,
        campaign_id: str,
        *,
        name: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "campaign.created",
            campaign_id=campaign_id,
            name=name,
            correlation_id=correlation_id,
            source=source,
        )


class CampaignUpdatedEvent(_CampaignEvent):
    """Emitted when a campaign is updated."""

    def __init__(
        self,
        campaign_id: str,
        *,
        status: str = "",
        mission_count: int = 0,
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "campaign.updated",
            campaign_id=campaign_id,
            status=status,
            mission_count=mission_count,
            correlation_id=correlation_id,
            source=source,
        )


class CampaignCompletedEvent(_CampaignEvent):
    """Emitted when a campaign is completed."""

    def __init__(
        self,
        campaign_id: str,
        *,
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "campaign.completed",
            campaign_id=campaign_id,
            correlation_id=correlation_id,
            source=source,
        )


class _HypothesisMemoryEvent(DomainEvent):
    """Base for Sprint 030 hypothesis memory events."""

    def __init__(
        self,
        event_type: str,
        *,
        target_id: str,
        mission_id: str = "",
        hypothesis_id: str = "",
        outcome: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            event_type=event_type,
            payload={
                "target_id": target_id,
                "mission_id": mission_id,
                "hypothesis_id": hypothesis_id,
                "outcome": outcome,
            },
            correlation_id=correlation_id,
            mission_id=mission_id,
            source=source,
        )


class HypothesisRecordedEvent(_HypothesisMemoryEvent):
    """Emitted when a hypothesis memory record is recorded."""

    def __init__(
        self,
        target_id: str,
        *,
        mission_id: str = "",
        hypothesis_id: str = "",
        outcome: str = "inconclusive",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "hypothesis.recorded",
            target_id=target_id,
            mission_id=mission_id,
            hypothesis_id=hypothesis_id,
            outcome=outcome,
            correlation_id=correlation_id,
            source=source,
        )


class HypothesisFailedEvent(_HypothesisMemoryEvent):
    """Emitted when a hypothesis failed validation."""

    def __init__(
        self,
        target_id: str,
        *,
        mission_id: str = "",
        hypothesis_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "hypothesis.failed",
            target_id=target_id,
            mission_id=mission_id,
            hypothesis_id=hypothesis_id,
            outcome="failed",
            correlation_id=correlation_id,
            source=source,
        )


class HypothesisSucceededEvent(_HypothesisMemoryEvent):
    """Emitted when a hypothesis was validated/proven."""

    def __init__(
        self,
        target_id: str,
        *,
        mission_id: str = "",
        hypothesis_id: str = "",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "hypothesis.succeeded",
            target_id=target_id,
            mission_id=mission_id,
            hypothesis_id=hypothesis_id,
            outcome="succeeded",
            correlation_id=correlation_id,
            source=source,
        )


class RiskChangedEvent(DomainEvent):
    """Emitted when target risk changed."""

    def __init__(
        self,
        target_id: str,
        *,
        campaign_id: str = "",
        risk_level: str = "low",
        previous_risk_level: str | None = None,
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "risk.changed",
            payload={
                "target_id": target_id,
                "campaign_id": campaign_id,
                "risk_level": risk_level,
                "previous_risk_level": previous_risk_level,
            },
            correlation_id=correlation_id,
            source=source,
        )


class FindingRecurredEvent(DomainEvent):
    """Emitted when a previously remediated finding recurs."""

    def __init__(
        self,
        target_id: str,
        *,
        original_finding_id: str = "",
        new_finding_id: str = "",
        kind: str = "new_location",
        correlation_id: str | None = None,
        source: str = "target_memory.service",
    ) -> None:
        super().__init__(
            "finding.recurred",
            payload={
                "target_id": target_id,
                "original_finding_id": original_finding_id,
                "new_finding_id": new_finding_id,
                "kind": kind,
            },
            correlation_id=correlation_id,
            source=source,
        )
