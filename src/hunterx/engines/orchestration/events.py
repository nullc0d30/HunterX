# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission orchestration event emitter.

Publishes the canonical mission orchestration events (``mission.*``) through an
``EventBusPort``. Every emitter method is a no-op when no event bus is wired so
the orchestration engine stays usable without observability.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.events.types import (
    MissionBlockedEvent,
    MissionCheckpointCreatedEvent,
    MissionCoverageComputedEvent,
    MissionIntelligenceUpdatedEvent,
    MissionPartialEvent,
    MissionPhaseCompletedEvent,
    MissionPhaseStartedEvent,
    MissionPlanCreatedEvent,
    MissionPlanningStartedEvent,
    MissionQualityComputedEvent,
    MissionReplannedEvent,
    MissionReplanningStartedEvent,
    MissionResultCreatedEvent,
    MissionResumedEvent,
    MissionScopingCompletedEvent,
    MissionScopingStartedEvent,
    MissionStepBlockedEvent,
    MissionStepCompletedEvent,
    MissionStepFailedEvent,
    MissionStepStartedEvent,
    MissionToolCompletedEvent,
    MissionToolFailedEvent,
    MissionToolFallbackEvent,
    MissionToolSelectedEvent,
    MissionToolStartedEvent,
)
from hunterx.domain.ports.messaging import EventBusPort


class MissionEventEmitter:
    """Publishes canonical mission orchestration events."""

    def __init__(self, event_bus: EventBusPort | None = None) -> None:
        self._event_bus = event_bus

    def scoping_started(self, mission_id: str, *, mission_type: str = "") -> None:
        """Publish ``mission.scoping.started``."""
        self._publish(MissionScopingStartedEvent(mission_id, mission_type=mission_type))

    def scoping_completed(self, mission_id: str, *, roots: list[str] | None = None, excludes: list[str] | None = None) -> None:
        """Publish ``mission.scoping.completed``."""
        self._publish(MissionScopingCompletedEvent(mission_id, roots=roots, excludes=excludes))

    def planning_started(self, mission_id: str, *, objective: str = "") -> None:
        """Publish ``mission.planning.started``."""
        self._publish(MissionPlanningStartedEvent(mission_id, objective=objective))

    def plan_created(self, mission_id: str, plan_id: str, *, phases: int = 0, steps: int = 0, version: int = 1) -> None:
        """Publish ``mission.plan.created``."""
        self._publish(MissionPlanCreatedEvent(mission_id, plan_id, phases=phases, steps=steps, version=version))

    def phase_started(self, mission_id: str, plan_id: str, phase_id: str, *, phase_kind: str = "") -> None:
        """Publish ``mission.phase.started``."""
        self._publish(MissionPhaseStartedEvent(mission_id, plan_id, phase_id, phase_kind=phase_kind))

    def phase_completed(self, mission_id: str, plan_id: str, phase_id: str, *, steps_completed: int = 0) -> None:
        """Publish ``mission.phase.completed``."""
        self._publish(MissionPhaseCompletedEvent(mission_id, plan_id, phase_id, steps_completed=steps_completed))

    def step_started(self, mission_id: str, plan_id: str, step_id: str, *, phase_id: str = "", capability: str = "", target: str = "") -> None:
        """Publish ``mission.step.started``."""
        self._publish(MissionStepStartedEvent(mission_id, plan_id, step_id, phase_id=phase_id, capability=capability, target=target))

    def step_completed(self, mission_id: str, plan_id: str, step_id: str, *, tool_id: str = "", execution_id: str = "", duration_ms: int = 0) -> None:
        """Publish ``mission.step.completed``."""
        self._publish(MissionStepCompletedEvent(mission_id, plan_id, step_id, tool_id=tool_id, execution_id=execution_id, duration_ms=duration_ms))

    def step_failed(self, mission_id: str, plan_id: str, step_id: str, error: str, *, tool_id: str = "", failure_class: str = "permanent") -> None:
        """Publish ``mission.step.failed``."""
        self._publish(MissionStepFailedEvent(mission_id, plan_id, step_id, error, tool_id=tool_id, failure_class=failure_class))

    def step_blocked(self, mission_id: str, plan_id: str, step_id: str, *, kind: str = "scope", reason: str = "", target: str = "") -> None:
        """Publish ``mission.step.blocked``."""
        self._publish(MissionStepBlockedEvent(mission_id, plan_id, step_id, kind=kind, reason=reason, target=target))

    def tool_selected(self, mission_id: str, plan_id: str, step_id: str, tool_id: str, *, capability: str = "", score: float = 0.0, fallback_of: str = "") -> None:
        """Publish ``mission.tool.selected``."""
        self._publish(MissionToolSelectedEvent(mission_id, plan_id, step_id, tool_id, capability=capability, score=score, fallback_of=fallback_of))

    def tool_started(self, mission_id: str, plan_id: str, step_id: str, tool_id: str, *, execution_id: str = "", target: str = "") -> None:
        """Publish ``mission.tool.started``."""
        self._publish(MissionToolStartedEvent(mission_id, plan_id, step_id, tool_id, execution_id=execution_id, target=target))

    def tool_completed(self, mission_id: str, plan_id: str, step_id: str, tool_id: str, *, execution_id: str = "", duration_ms: int = 0) -> None:
        """Publish ``mission.tool.completed``."""
        self._publish(MissionToolCompletedEvent(mission_id, plan_id, step_id, tool_id, execution_id=execution_id, duration_ms=duration_ms))

    def tool_failed(self, mission_id: str, plan_id: str, step_id: str, tool_id: str, error: str, *, execution_id: str = "", failure_class: str = "permanent") -> None:
        """Publish ``mission.tool.failed``."""
        self._publish(MissionToolFailedEvent(mission_id, plan_id, step_id, tool_id, error, execution_id=execution_id, failure_class=failure_class))

    def tool_fallback(self, mission_id: str, plan_id: str, step_id: str, primary_tool: str, fallback_tool: str, *, reason: str = "") -> None:
        """Publish ``mission.tool.fallback``."""
        self._publish(MissionToolFallbackEvent(mission_id, plan_id, step_id, primary_tool, fallback_tool, reason=reason))

    def result_created(self, mission_id: str, plan_id: str, step_id: str, *, tool_id: str = "", execution_id: str = "", findings: int = 0, evidence: int = 0) -> None:
        """Publish ``mission.result.created``."""
        self._publish(MissionResultCreatedEvent(mission_id, plan_id, step_id, tool_id=tool_id, execution_id=execution_id, findings=findings, evidence=evidence))

    def intelligence_updated(self, mission_id: str, plan_id: str, *, step_id: str = "", updates: dict[str, object] | None = None) -> None:
        """Publish ``mission.intelligence.updated``."""
        self._publish(MissionIntelligenceUpdatedEvent(mission_id, plan_id, step_id=step_id, updates=updates))

    def replanning_started(self, mission_id: str, plan_id: str, *, reason: str = "") -> None:
        """Publish ``mission.replanning.started``."""
        self._publish(MissionReplanningStartedEvent(mission_id, plan_id, reason=reason))

    def replanned(self, mission_id: str, plan_id: str, *, previous_version: int = 1, new_version: int = 1, added_steps: list[str] | None = None) -> None:
        """Publish ``mission.replanned``."""
        self._publish(MissionReplannedEvent(mission_id, plan_id, previous_version=previous_version, new_version=new_version, added_steps=added_steps))

    def checkpoint_created(self, mission_id: str, plan_id: str, checkpoint_id: str, *, label: str = "", completed_steps: list[str] | None = None) -> None:
        """Publish ``mission.checkpoint.created``."""
        self._publish(MissionCheckpointCreatedEvent(mission_id, plan_id, checkpoint_id, label=label, completed_steps=completed_steps))

    def resumed(self, mission_id: str, plan_id: str, *, checkpoint_id: str = "") -> None:
        """Publish ``mission.resumed``."""
        self._publish(MissionResumedEvent(mission_id, plan_id, checkpoint_id=checkpoint_id))

    def blocked(self, mission_id: str, plan_id: str, reason: str) -> None:
        """Publish ``mission.blocked``."""
        self._publish(MissionBlockedEvent(mission_id, plan_id, reason))

    def partial(self, mission_id: str, plan_id: str, *, gaps: list[str] | None = None) -> None:
        """Publish ``mission.partial``."""
        self._publish(MissionPartialEvent(mission_id, plan_id, gaps=gaps))

    def quality_computed(self, mission_id: str, plan_id: str, *, score: float = 0.0) -> None:
        """Publish ``mission.quality.computed``."""
        self._publish(MissionQualityComputedEvent(mission_id, plan_id, score=score))

    def coverage_computed(self, mission_id: str, plan_id: str, *, coverage: dict[str, object] | None = None) -> None:
        """Publish ``mission.coverage.computed``."""
        self._publish(MissionCoverageComputedEvent(mission_id, plan_id, coverage=coverage))

    def _publish(self, event: Any) -> None:
        """Publish ``event`` when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)
