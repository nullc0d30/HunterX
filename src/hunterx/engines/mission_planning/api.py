# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission Planning API.

The facade every internal subsystem uses to interact with the mission planning
engine: create, update, validate, plan, status, cancel, history, execution
graphs and checkpoints. Composes the engine, profile engine and planner behind
one surface, mirroring the pattern of ``ToolIntelligenceAPI``.
"""

from __future__ import annotations

from hunterx.domain.exceptions import (
    MissionProfileNotFoundError,
    MissionTemplateNotFoundError,
)
from hunterx.domain.mission_planning import (
    Checkpoint,
    ExecutionGraph,
    MissionPlan,
    MissionProfile,
    MissionRequest,
    MissionTemplate,
    MissionTimelineEntry,
)
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)
from hunterx.engines.mission_planning.config import ConfigurationResolver
from hunterx.engines.mission_planning.engine import MissionPlanningEngine
from hunterx.engines.mission_planning.planner import MissionPlanner
from hunterx.engines.mission_planning.profiles import MissionProfileEngine
from hunterx.shared.result import Result, Success


class MissionPlanningAPI:
    """Internal API for the mission planning subsystem.

    Constructed with repositories (in-memory in tests/embedded use) and
    optional collaborators. Profile/template registration is available for
    declarative mission definition; the lifecycle methods match the engine.
    """

    def __init__(
        self,
        *,
        plans: MissionPlanRepository,
        profiles: MissionProfileRepository | None = None,
        templates: MissionTemplateRepository | None = None,
        checkpoints: CheckpointRepository | None = None,
        timeline: MissionTimelineRepository | None = None,
        event_bus: EventBusPort | None = None,
        profile_engine: MissionProfileEngine | None = None,
        planner: MissionPlanner | None = None,
        resolver: ConfigurationResolver | None = None,
    ) -> None:
        self.profiles = profile_engine or MissionProfileEngine(profiles=profiles, templates=templates)
        self.planner = planner or MissionPlanner(resolver or ConfigurationResolver())
        self.engine = MissionPlanningEngine(
            plans=plans,
            profiles=profiles,
            templates=templates,
            checkpoints=checkpoints,
            timeline_repository=timeline,
            event_bus=event_bus,
            profile_engine=self.profiles,
            planner=self.planner,
            resolver=resolver,
        )

    # -- profile / template catalog ---------------------------------------

    def register_profile(self, profile: MissionProfile) -> MissionProfile:
        """Register a mission profile."""
        return self.profiles.register_profile(profile)

    def register_template(self, template: MissionTemplate) -> MissionTemplate:
        """Register a mission template."""
        return self.profiles.register_template(template)

    def resolve_profile(self, profile_id: str) -> MissionProfile:
        """Return the fully merged profile for ``profile_id``."""
        return self.profiles.resolve_profile(profile_id)

    def list_profiles(self) -> list[MissionProfile]:
        """List registered mission profiles."""
        return self.profiles.list_profiles()

    def list_templates(self) -> list[MissionTemplate]:
        """List registered mission templates."""
        return self.profiles.list_templates()

    # -- validation --------------------------------------------------------

    def validate(self, request: MissionRequest) -> list[str]:
        """Return validation errors for a request (empty when valid)."""
        errors: list[str] = []
        try:
            profile = self.profiles.resolve_profile(request.profile_id)
        except MissionProfileNotFoundError as exc:
            return [str(exc)]
        if request.template_id is not None:
            try:
                self.profiles.resolve_template(request.template_id)
            except MissionTemplateNotFoundError as exc:
                errors.append(str(exc))
        if not request.targets:
            errors.append("mission must declare at least one target.")
        if not request.name:
            errors.append("mission name must not be empty.")
        plan = MissionPlan(
            mission_id="",
            profile_id=request.profile_id,
            template_id=request.template_id,
            mission_type=request.mission_type,
            name=request.name or "unnamed",
            targets=request.targets,
            variables=request.variables,
            config=request.config,
            priority=request.priority,
        )
        errors.extend(self.planner.validate(plan, profile))
        return errors

    # -- lifecycle ---------------------------------------------------------

    def create_mission(self, request: MissionRequest) -> Result[MissionPlan, Exception]:
        """Validate, create and enqueue a mission plan."""
        return self.engine.create_mission(request)

    def update_mission(
        self,
        plan_id: str,
        *,
        name: str | None = None,
        targets: tuple[str, ...] | None = None,
        variables: dict[str, object] | None = None,
        config: dict[str, object] | None = None,
        priority: str | None = None,
    ) -> Result[MissionPlan, Exception]:
        """Update editable fields of a mission that has not been executed."""
        return self.engine.update_mission(
            plan_id,
            name=name,
            targets=targets,
            variables=variables,
            config=config,
            priority=priority,
        )

    def plan_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Expand a queued mission into a ready plan."""
        return self.engine.plan_mission(plan_id)

    def start_mission(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Begin executing a ready plan."""
        return self.engine.start_mission(plan_id)

    def status(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Return the current plan for ``plan_id``."""
        return self.engine.status(plan_id)

    def cancel(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Cancel a mission from any active state."""
        return self.engine.cancel_mission(plan_id)

    def fail(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Fail a mission from any active state."""
        return self.engine.fail_mission(plan_id)

    def complete(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Mark an executing mission completed."""
        return self.engine.complete_mission(plan_id)

    def archive(self, plan_id: str) -> Result[MissionPlan, Exception]:
        """Archive a terminal mission."""
        return self.engine.archive_mission(plan_id)

    def history(self, mission_id: str) -> Result[list[MissionTimelineEntry], Exception]:
        """Return a mission's timeline entries."""
        return Success(self.engine.history(mission_id))

    def list_missions(self, *, limit: int = 100, offset: int = 0) -> list[MissionPlan]:
        """List persisted mission plans."""
        return self.engine.list_plans(limit=limit, offset=offset)

    # -- execution graph ---------------------------------------------------

    def graph(self, plan_id: str) -> Result[ExecutionGraph, Exception]:
        """Build the execution graph (DAG) for a planned mission."""
        return self.engine.build_graph(plan_id)

    # -- checkpoints -------------------------------------------------------

    def checkpoint_create(
        self,
        plan_id: str,
        label: str,
        *,
        rerun_from: str | None = None,
    ) -> Result[Checkpoint, Exception]:
        """Snapshot a plan into a checkpoint."""
        return self.engine.checkpoint_create(plan_id, label, rerun_from=rerun_from)

    def checkpoint_list(self, plan_id: str) -> list[Checkpoint]:
        """Return checkpoints for a plan."""
        return self.engine.checkpoint_list(plan_id)

    def checkpoint_restore(self, checkpoint_id: str) -> Result[MissionPlan, Exception]:
        """Restore a plan from a checkpoint (supports partial rerun)."""
        return self.engine.checkpoint_restore(checkpoint_id)

    # -- convenience -------------------------------------------------------

    @staticmethod
    def summary(plan: MissionPlan) -> dict[str, object]:
        """Return a JSON-safe status summary for a plan."""
        return {
            "plan_id": plan.plan_id,
            "mission_id": plan.mission_id,
            "name": plan.name,
            "status": plan.status.value,
            "progress": plan.progress,
            "total_steps": plan.total_steps,
            "completed_steps": plan.completed_steps,
            "phases": len(plan.phases),
            "estimated_duration_seconds": plan.estimated_duration_seconds,
            "approval_level": plan.approval_level.value,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
            "started_at": plan.started_at,
            "completed_at": plan.completed_at,
        }
