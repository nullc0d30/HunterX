# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Checkpoint manager.

Snapshots a :class:`~hunterx.domain.mission_planning.MissionPlan` to a
:class:`~hunterx.domain.mission_planning.Checkpoint` and restores plans from
checkpoints, supporting full recovery and partial rerun. Completed phases and
steps are recorded explicitly so a restored plan can resume from exactly where
execution stopped.
"""

from __future__ import annotations

from hunterx.domain.exceptions import CheckpointNotFoundError
from hunterx.domain.mission_planning import (
    Checkpoint,
    MissionApprovalLevel,
    MissionPhaseKind,
    MissionPhaseState,
    MissionPlan,
    MissionPlanningStatus,
    MissionType,
    PlannedPhase,
    PlanStep,
)
from hunterx.domain.ports.mission_planning import CheckpointRepository
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class CheckpointManager:
    """Create, persist, list and restore mission checkpoints."""

    def __init__(self, repository: CheckpointRepository | None = None) -> None:
        self._repository = repository
        self._store: dict[str, Checkpoint] = {}

    # -- create ------------------------------------------------------------

    def create(
        self,
        plan: MissionPlan,
        label: str,
        *,
        rerun_from: str | None = None,
    ) -> Checkpoint:
        """Snapshot ``plan`` into a new checkpoint.

        ``rerun_from`` names a step id; restoring this checkpoint reruns that
        step and everything after it while keeping earlier work.
        """
        snapshot = self._snapshot(plan)
        checkpoint = Checkpoint(
            checkpoint_id=generate_id(),
            plan_id=plan.plan_id,
            mission_id=plan.mission_id,
            label=label,
            snapshot=snapshot,
            rerun_from=rerun_from,
        )
        self._store[checkpoint.checkpoint_id] = checkpoint
        if self._repository is not None:
            self._repository.save(checkpoint)
        return checkpoint

    def _snapshot(self, plan: MissionPlan) -> dict[str, object]:
        """Serialize a plan into a JSON-safe snapshot."""
        return {
            "plan_id": plan.plan_id,
            "mission_id": plan.mission_id,
            "profile_id": plan.profile_id,
            "template_id": plan.template_id,
            "mission_type": plan.mission_type.value,
            "name": plan.name,
            "status": plan.status.value,
            "targets": list(plan.targets),
            "variables": plan.variables,
            "config": plan.config,
            "priority": plan.priority,
            "approval_level": plan.approval_level.value,
            "progress": plan.progress,
            "estimated_duration_seconds": plan.estimated_duration_seconds,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
            "started_at": plan.started_at,
            "completed_at": plan.completed_at,
            "completed_phases": [p.phase_id for p in plan.phases if p.status is MissionPhaseState.COMPLETED],
            "phases": [
                {
                    "phase_id": phase.phase_id,
                    "kind": phase.kind.value,
                    "name": phase.name,
                    "status": phase.status.value,
                    "optional": phase.optional,
                    "depends_on": list(phase.depends_on),
                    "estimated_duration_seconds": phase.estimated_duration_seconds,
                    "expected_outputs": list(phase.expected_outputs),
                    "approval_required": phase.approval_required,
                    "parallel": phase.parallel,
                    "started_at": phase.started_at,
                    "completed_at": phase.completed_at,
                    "steps": [
                        {
                            "step_id": step.step_id,
                            "action": step.action,
                            "target": step.target,
                            "parameters": step.parameters,
                            "phase_id": step.phase_id,
                            "depends_on": list(step.depends_on),
                            "estimated_duration_seconds": step.estimated_duration_seconds,
                            "approval_required": step.approval_required,
                        }
                        for step in phase.steps
                    ],
                }
                for phase in plan.phases
            ],
        }

    # -- persistence -------------------------------------------------------

    def get(self, checkpoint_id: str) -> Checkpoint:
        """Return a checkpoint, raising :class:`CheckpointNotFoundError`."""
        checkpoint = self._store.get(checkpoint_id)
        if checkpoint is None and self._repository is not None:
            checkpoint = self._repository.get(checkpoint_id)
            if checkpoint is not None:
                self._store[checkpoint_id] = checkpoint
        if checkpoint is None:
            raise CheckpointNotFoundError(checkpoint_id)
        return checkpoint

    def list_for_plan(self, plan_id: str) -> list[Checkpoint]:
        """Return checkpoints for a plan, most recent first."""
        if self._repository is not None and not self._store:
            self._store = {c.checkpoint_id: c for c in self._repository.list_by_plan(plan_id, limit=10_000)}
        checkpoints = [c for c in self._store.values() if c.plan_id == plan_id]
        return sorted(checkpoints, key=lambda c: c.created_at, reverse=True)

    # -- restore -----------------------------------------------------------

    def restore(self, checkpoint: Checkpoint) -> MissionPlan:
        """Rebuild the plan captured by ``checkpoint``.

        Honors ``checkpoint.rerun_from``: steps at or after the named step are
        reset to pending (partial rerun); earlier completed work is preserved.
        """
        snapshot = checkpoint.snapshot
        rerun_from = checkpoint.rerun_from
        completed_phases = set(snapshot.get("completed_phases", []))
        phases = self._restore_phases(snapshot, completed_phases, rerun_from)
        return MissionPlan(
            plan_id=str(snapshot["plan_id"]),
            mission_id=str(snapshot["mission_id"]),
            profile_id=str(snapshot["profile_id"]),
            template_id=snapshot.get("template_id"),
            mission_type=_mission_type(snapshot["mission_type"]),
            name=str(snapshot["name"]),
            status=_status(snapshot["status"]),
            phases=tuple(phases),
            targets=tuple(snapshot.get("targets", [])),
            variables=dict(snapshot.get("variables", {})),
            config=dict(snapshot.get("config", {})),
            priority=str(snapshot.get("priority", "medium")),
            approval_level=_approval(snapshot["approval_level"]),
            progress=float(snapshot.get("progress", 0.0)),
            estimated_duration_seconds=int(snapshot.get("estimated_duration_seconds", 0)),
            created_at=str(snapshot.get("created_at", "")),
            updated_at=str(snapshot.get("updated_at", utcnow_iso())),
            started_at=snapshot.get("started_at"),
            completed_at=snapshot.get("completed_at"),
        )

    def _restore_phases(
        self,
        snapshot: dict[str, object],
        completed_phases: set[str],
        rerun_from: str | None,
    ) -> list[PlannedPhase]:
        rerun_phase: str | None = None
        if rerun_from is not None:
            for raw in snapshot.get("phases", []):
                for step in raw.get("steps", []):
                    if step.get("step_id") == rerun_from:
                        rerun_phase = raw.get("phase_id")
                        break
        phases: list[PlannedPhase] = []
        for raw in snapshot.get("phases", []):
            phase_id = str(raw["phase_id"])
            status = MissionPhaseState.PENDING
            if phase_id in completed_phases and phase_id != rerun_phase:
                status = MissionPhaseState.COMPLETED
            phases.append(
                PlannedPhase(
                    phase_id=phase_id,
                    kind=_phase_kind(raw["kind"]),
                    name=str(raw["name"]),
                    status=status,
                    optional=bool(raw.get("optional", False)),
                    depends_on=tuple(raw.get("depends_on", [])),
                    estimated_duration_seconds=int(raw.get("estimated_duration_seconds", 0)),
                    steps=tuple(self._restore_steps(raw.get("steps", []))),
                    expected_outputs=tuple(raw.get("expected_outputs", [])),
                    approval_required=bool(raw.get("approval_required", False)),
                    parallel=bool(raw.get("parallel", False)),
                    started_at=raw.get("started_at"),
                    completed_at=raw.get("completed_at"),
                )
            )
        return phases

    @staticmethod
    def _restore_steps(raw_steps: list[object]) -> list[PlanStep]:
        return [
            PlanStep(
                step_id=str(step["step_id"]),
                action=str(step["action"]),
                target=str(step["target"]),
                parameters=dict(step.get("parameters", {})),
                phase_id=str(step.get("phase_id", "")),
                depends_on=tuple(step.get("depends_on", [])),
                estimated_duration_seconds=int(step.get("estimated_duration_seconds", 0)),
                approval_required=bool(step.get("approval_required", False)),
            )
            for step in raw_steps
        ]

    def resume(
        self,
        plan: MissionPlan,
        *,
        from_step_id: str,
    ) -> MissionPlan:
        """Return ``plan`` reset for a partial rerun starting at ``from_step_id``.

        Steps at or after ``from_step_id`` (and their phases) are reset to
        pending; phases before it keep their completed state.
        """
        reset_phase: str | None = None
        for phase in plan.phases:
            for step in phase.steps:
                if step.step_id == from_step_id:
                    reset_phase = phase.phase_id
                    break
        phases: list[PlannedPhase] = []
        rerunning = False
        for phase in plan.phases:
            if reset_phase is None:
                new_status = phase.status
            elif rerunning:
                new_status = MissionPhaseState.PENDING
            elif phase.phase_id == reset_phase:
                new_status = MissionPhaseState.PENDING
                rerunning = True
            else:
                new_status = phase.status
            phases.append(
                PlannedPhase(
                    phase_id=phase.phase_id,
                    kind=phase.kind,
                    name=phase.name,
                    status=new_status,
                    optional=phase.optional,
                    depends_on=phase.depends_on,
                    estimated_duration_seconds=phase.estimated_duration_seconds,
                    steps=phase.steps,
                    expected_outputs=phase.expected_outputs,
                    approval_required=phase.approval_required,
                    parallel=phase.parallel,
                    started_at=None if new_status is not MissionPhaseState.COMPLETED else phase.started_at,
                    completed_at=None if new_status is not MissionPhaseState.COMPLETED else phase.completed_at,
                )
            )
        return MissionPlan(
            plan_id=plan.plan_id,
            mission_id=plan.mission_id,
            profile_id=plan.profile_id,
            template_id=plan.template_id,
            mission_type=plan.mission_type,
            name=plan.name,
            status=plan.status,
            phases=tuple(phases),
            targets=plan.targets,
            variables=plan.variables,
            config=plan.config,
            priority=plan.priority,
            approval_level=plan.approval_level,
            progress=plan.progress,
            estimated_duration_seconds=plan.estimated_duration_seconds,
            created_at=plan.created_at,
            updated_at=utcnow_iso(),
            started_at=plan.started_at,
            completed_at=plan.completed_at,
        )


def _mission_type(value: object) -> MissionType:
    return MissionType(str(value))


def _status(value: object) -> MissionPlanningStatus:
    return MissionPlanningStatus(str(value))


def _approval(value: object) -> MissionApprovalLevel:
    return MissionApprovalLevel(str(value))


def _phase_kind(value: object) -> MissionPhaseKind:
    return MissionPhaseKind(str(value))
