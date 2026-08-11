# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the checkpoint manager."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import CheckpointNotFoundError
from hunterx.domain.mission_planning import (
    MissionPhaseState,
    MissionPlan,
    MissionPlanningStatus,
    MissionType,
)
from hunterx.engines.mission_planning.checkpoints import CheckpointManager
from hunterx.engines.mission_planning.planner import MissionPlanner
from tests.framework.mission_planning import (
    InMemoryCheckpointRepository,
    external_pentest_profile,
)


def _planned(*, targets: tuple[str, ...] = ("a.com",)) -> MissionPlan:
    plan = MissionPlan(
        name="M",
        profile_id="external-pentest",
        mission_type=MissionType.EXTERNAL_PENTEST,
        targets=targets,
    )
    return MissionPlanner().expand(plan, external_pentest_profile())


def _advance(plan: MissionPlan, *, completed: tuple[str, ...], status: MissionPlanningStatus) -> MissionPlan:
    """Return a plan with the given phases marked completed and status set."""
    phases = []
    for phase in plan.phases:
        phase_state = (
            MissionPhaseState.COMPLETED
            if phase.phase_id in completed
            else MissionPhaseState.PENDING
        )
        phases.append(
            type(phase)(
                phase_id=phase.phase_id,
                kind=phase.kind,
                name=phase.name,
                status=phase_state,
                optional=phase.optional,
                depends_on=phase.depends_on,
                estimated_duration_seconds=phase.estimated_duration_seconds,
                steps=phase.steps,
                expected_outputs=phase.expected_outputs,
                approval_required=phase.approval_required,
                started_at=phase.started_at,
                completed_at=phase.completed_at,
            )
        )
    return type(plan)(
        plan_id=plan.plan_id,
        mission_id=plan.mission_id,
        profile_id=plan.profile_id,
        template_id=plan.template_id,
        mission_type=plan.mission_type,
        name=plan.name,
        status=status,
        phases=tuple(phases),
        targets=plan.targets,
        variables=plan.variables,
        config=plan.config,
        priority=plan.priority,
        approval_level=plan.approval_level,
        progress=plan.progress,
        estimated_duration_seconds=plan.estimated_duration_seconds,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
        started_at=plan.started_at,
        completed_at=plan.completed_at,
    )


class TestCheckpointManager:
    def test_create_snapshots_state(self) -> None:
        plan = _planned()
        manager = CheckpointManager()
        checkpoint = manager.create(plan, "initial")
        assert checkpoint.plan_id == plan.plan_id
        assert checkpoint.label == "initial"
        assert checkpoint.snapshot["name"] == "M"

    def test_persistence_via_repository(self) -> None:
        repository = InMemoryCheckpointRepository()
        plan = _planned()
        manager = CheckpointManager(repository)
        checkpoint = manager.create(plan, "persisted")
        fetched = manager.get(checkpoint.checkpoint_id)
        assert fetched.checkpoint_id == checkpoint.checkpoint_id
        assert len(manager.list_for_plan(plan.plan_id)) == 1

    def test_unknown_checkpoint_raises(self) -> None:
        manager = CheckpointManager()
        with pytest.raises(CheckpointNotFoundError):
            manager.get("ghost")

    def test_restore_reconstructs_plan(self) -> None:
        plan = _planned()
        manager = CheckpointManager()
        checkpoint = manager.create(plan, "snap")
        restored = manager.restore(checkpoint)
        assert restored.plan_id == plan.plan_id
        assert restored.mission_id == plan.mission_id
        assert restored.targets == plan.targets
        assert len(restored.phases) == len(plan.phases)
        assert restored.status is MissionPlanningStatus.CREATED

    def test_restore_preserves_completed_phases(self) -> None:
        plan = _planned()
        running = _advance(plan, completed=("recon", "enumeration"), status=MissionPlanningStatus.EXECUTING)
        manager = CheckpointManager()
        checkpoint = manager.create(running, "mid-run")
        restored = manager.restore(checkpoint)
        assert restored.phase("recon").status is MissionPhaseState.COMPLETED
        assert restored.phase("enumeration").status is MissionPhaseState.COMPLETED
        assert restored.phase("validation").status is MissionPhaseState.PENDING

    def test_partial_rerun_resets_phase(self) -> None:
        plan = _planned()
        running = _advance(plan, completed=("recon", "enumeration"), status=MissionPlanningStatus.EXECUTING)
        enumeration = running.phase("enumeration")
        assert enumeration is not None
        rerun_step = enumeration.steps[0].step_id
        manager = CheckpointManager()
        checkpoint = manager.create(running, "rerun", rerun_from=rerun_step)
        restored = manager.restore(checkpoint)
        # the rerun phase is reset to pending even though it was completed
        assert restored.phase("enumeration").status is MissionPhaseState.PENDING
        # earlier phases stay completed
        assert restored.phase("recon").status is MissionPhaseState.COMPLETED

    def test_resume_resets_from_step(self) -> None:
        plan = _planned()
        running = _advance(plan, completed=("recon",), status=MissionPlanningStatus.EXECUTING)
        enumeration = running.phase("enumeration")
        assert enumeration is not None
        rerun_step = enumeration.steps[0].step_id
        manager = CheckpointManager()
        resumed = manager.resume(running, from_step_id=rerun_step)
        assert resumed.phase("recon").status is MissionPhaseState.COMPLETED
        assert resumed.phase("enumeration").status is MissionPhaseState.PENDING
        assert resumed.phase("validation").status is MissionPhaseState.PENDING
        assert resumed.phase("reporting").status is MissionPhaseState.PENDING

    def test_checkpoint_rejects_empty_label(self) -> None:
        from hunterx.domain.exceptions import InvalidMissionPlanError

        plan = _planned()
        manager = CheckpointManager()
        with pytest.raises(InvalidMissionPlanError):
            manager.create(plan, "")
