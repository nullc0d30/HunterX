# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission planner.

Expands a mission plan into an ordered, dependency-aware set of phases and
steps. Handles required/optional phase selection, dependency closure and
ordering, per-target step expansion, duration estimation, approval
requirements and expected outputs. The planner never executes anything — it
produces the plan the execution graph is later built from.
"""

from __future__ import annotations

from hunterx.domain.exceptions import MissionPlanValidationError
from hunterx.domain.mission_planning import (
    MissionPhase,
    MissionPhaseState,
    MissionPlan,
    MissionProfile,
    MissionRequest,
    MissionTemplate,
    PlannedPhase,
    PlanStep,
)
from hunterx.engines.mission_planning.config import ConfigurationResolver
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


def _find_phase(phases: tuple[MissionPhase, ...], phase_id: str) -> MissionPhase | None:
    """Return the phase with ``phase_id``, or ``None``."""
    return next((phase for phase in phases if phase.phase_id == phase_id), None)


class MissionPlanner:
    """Build mission plans from a profile, request and optional template."""

    def __init__(self, resolver: ConfigurationResolver | None = None) -> None:
        self._resolver = resolver or ConfigurationResolver()

    # -- validation --------------------------------------------------------

    def validate(
        self,
        plan: MissionPlan,
        profile: MissionProfile,
    ) -> list[str]:
        """Return validation errors (empty when the request is valid)."""
        errors: list[str] = []
        if not profile.supports(plan.mission_type):
            errors.append(
                f"profile '{profile.profile_id}' does not support mission type '{plan.mission_type.value}'."
            )
        requested = plan.config.get("tools")
        if isinstance(requested, list):
            excluded = profile.allowed_tools.get("exclude")
            if excluded and any(tool in excluded for tool in requested):
                errors.append(
                    f"requested tools {requested} violate the profile's exclusion list {excluded}."
                )
            included = profile.allowed_tools.get("include")
            if included and any(tool not in included for tool in requested):
                errors.append(
                    f"requested tools {requested} are outside the profile's allowed set {included}."
                )
        return errors

    # -- plan expansion ----------------------------------------------------

    def expand(
        self,
        plan: MissionPlan,
        profile: MissionProfile,
        template: MissionTemplate | None = None,
    ) -> MissionPlan:
        """Fill ``plan`` with phases, steps, estimates and resolved config.

        The plan is mutated in place and returned. Raises
        :class:`MissionPlanValidationError` when the request fails profile
        validation.
        """
        errors = self.validate(plan, profile)
        if errors:
            raise MissionPlanValidationError(
                "mission request failed profile validation: " + "; ".join(errors),
                errors=errors,
            )
        effective_phases = (
            template.phases_override
            if template is not None and template.phases_override
            else profile.phases
        )
        selected = self._select_phases(effective_phases, plan.config)
        ordered = self._order_phases(selected)
        request = MissionRequest(
            profile_id=plan.profile_id,
            mission_type=plan.mission_type,
            name=plan.name,
            targets=plan.targets,
            template_id=plan.template_id,
            variables=plan.variables,
            config=plan.config,
            priority=plan.priority,
        )
        resolved_config = self._resolver.resolve(profile, request, template)
        variable_sources: dict[str, object] = {}
        if template is not None:
            variable_sources.update(template.variables)
        variable_sources.update(request.variables)
        resolved_variables = self._resolver.render_mapping(variable_sources)
        selected_ids = {phase.phase_id for phase in ordered}
        planned = [
            self._build_phase(plan, phase, resolved_config, selected_ids)
            for phase in ordered
        ]
        plan.phases = tuple(planned)
        plan.config = resolved_config
        plan.variables = resolved_variables
        plan.estimated_duration_seconds = sum(phase.estimated_duration_seconds for phase in planned)
        plan.approval_level = profile.approval_level
        plan.updated_at = utcnow_iso()
        return plan
    # -- phase selection ---------------------------------------------------

    def _select_phases(
        self,
        phases: tuple[MissionPhase, ...],
        config: dict[str, object],
    ) -> list[MissionPhase]:
        """Return phases to include, with dependencies closed transitively."""
        selected: set[str] = set()
        for phase in phases:
            if self._include_phase(phase, config):
                selected.add(phase.phase_id)
        changed = True
        while changed:
            changed = False
            for phase in phases:
                if phase.phase_id in selected:
                    for dependency in phase.depends_on:
                        dependency_phase = _find_phase(phases, dependency)
                        if (
                            dependency not in selected
                            and dependency_phase is not None
                            and self._include_phase(dependency_phase, config)
                        ):
                            selected.add(dependency)
                            changed = True
        return [phase for phase in phases if phase.phase_id in selected]

    @staticmethod
    def _include_phase(phase: MissionPhase, config: dict[str, object]) -> bool:
        """Decide whether an optional phase is included for this mission."""
        if not phase.optional:
            return True
        phases_cfg = config.get("phases")
        if not isinstance(phases_cfg, dict):
            return True
        disabled = phases_cfg.get("disabled", [])
        enabled = phases_cfg.get("enabled", [])
        if phase.phase_id in disabled:
            return False
        if phase.phase_id in phases_cfg and isinstance(phases_cfg[phase.phase_id], bool):
            return bool(phases_cfg[phase.phase_id])
        if enabled:
            return phase.phase_id in enabled
        return True

    def _order_phases(
        self,
        phases: list[MissionPhase],
    ) -> list[MissionPhase]:
        """Topologically order selected phases honoring ``depends_on``."""
        by_id = {phase.phase_id: phase for phase in phases}
        remaining = {phase.phase_id: set(phase.depends_on) & set(by_id) for phase in phases}
        ordered: list[MissionPhase] = []
        ready = [phase_id for phase_id, deps in remaining.items() if not deps]
        while ready:
            phase_id = ready.pop(0)
            ordered.append(by_id[phase_id])
            for candidate, deps in remaining.items():
                if phase_id in deps:
                    deps.discard(phase_id)
                    if not deps and candidate not in ordered:
                        ready.append(candidate)
        if len(ordered) != len(phases):
            raise MissionPlanValidationError(
                "mission profile contains a phase dependency cycle."
            )
        return ordered

    # -- step / phase construction ----------------------------------------

    def _build_phase(
        self,
        plan: MissionPlan,
        phase: MissionPhase,
        resolved_config: dict[str, object],
        selected_ids: set[str],
    ) -> PlannedPhase:
        """Construct a :class:`PlannedPhase` with per-target steps."""
        steps = self._build_steps(plan, phase, resolved_config)
        return PlannedPhase(
            phase_id=phase.phase_id,
            kind=phase.kind,
            name=phase.name,
            status=MissionPhaseState.PENDING,
            optional=phase.optional,
            depends_on=tuple(dep for dep in phase.depends_on if dep in selected_ids),
            estimated_duration_seconds=phase.estimated_duration_seconds,
            steps=tuple(steps),
            expected_outputs=phase.expected_outputs,
            approval_required=phase.approval_required,
            parallel=phase.parallel,
        )

    def _build_steps(
        self,
        plan: MissionPlan,
        phase: MissionPhase,
        resolved_config: dict[str, object],
    ) -> list[PlanStep]:
        """Expand a phase's actions into per-target, sequentially chained steps."""
        steps: list[PlanStep] = []
        per_step = 0
        if phase.actions:
            per_step = max(0, phase.estimated_duration_seconds // len(phase.actions))
        for target in plan.targets:
            previous: str | None = None
            for action in phase.actions:
                step_id = generate_id()
                steps.append(
                    PlanStep(
                        step_id=step_id,
                        action=action,
                        target=target,
                        parameters=dict(resolved_config),
                        phase_id=phase.phase_id,
                        depends_on=(previous,) if previous is not None else (),
                        estimated_duration_seconds=per_step,
                        approval_required=phase.approval_required,
                    )
                )
                previous = step_id
        return steps

    # -- request reconstruction --------------------------------------------

    @staticmethod
    def request_from_plan(plan: MissionPlan) -> MissionRequest:
        """Reconstruct a :class:`MissionRequest` from a persisted plan."""
        return MissionRequest(
            profile_id=plan.profile_id,
            mission_type=plan.mission_type,
            name=plan.name,
            targets=plan.targets,
            template_id=plan.template_id,
            variables=plan.variables,
            config=plan.config,
            priority=plan.priority,
        )
