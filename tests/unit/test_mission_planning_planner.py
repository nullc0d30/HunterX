# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the mission planner."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import MissionPlanValidationError
from hunterx.domain.mission_planning import (
    MissionPhaseState,
    MissionPlan,
    MissionTemplate,
    MissionType,
)
from hunterx.engines.mission_planning.planner import MissionPlanner
from tests.framework.mission_planning import external_pentest_profile, web_pentest_profile


def _plan(*, profile_id: str = "external-pentest", mission_type: MissionType = MissionType.EXTERNAL_PENTEST, **kwargs: object) -> MissionPlan:
    base: dict[str, object] = {
        "name": "Mission",
        "profile_id": profile_id,
        "mission_type": mission_type,
        "targets": ("a.com",),
    }
    base.update(kwargs)
    return MissionPlan(**base)  # type: ignore[arg-type]


class TestPlanner:
    def test_expand_orders_phases_by_dependency(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(_plan(), external_pentest_profile())
        assert [phase.phase_id for phase in plan.phases] == [
            "recon",
            "enumeration",
            "validation",
            "reporting",
        ]

    def test_phases_carry_dependencies(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(_plan(), external_pentest_profile())
        enumeration = plan.phase("enumeration")
        assert enumeration is not None
        assert enumeration.depends_on == ("recon",)

    def test_steps_per_target_and_phase(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(_plan(targets=("a.com", "b.com")), external_pentest_profile())
        recon = plan.phase("recon")
        assert recon is not None
        # 2 actions x 2 targets
        assert len(recon.steps) == 4
        assert len({step.target for step in recon.steps}) == 2

    def test_steps_chain_within_phase(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(_plan(targets=("a.com",)), external_pentest_profile())
        recon = plan.phase("recon")
        assert recon is not None
        steps = list(recon.steps)
        assert steps[0].depends_on == ()
        assert steps[1].depends_on == (steps[0].step_id,)

    def test_optional_phase_included_by_default(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(_plan(), external_pentest_profile())
        assert plan.phase("validation") is not None

    def test_optional_phase_disabled_via_config(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(
            _plan(config={"phases": {"disabled": ["validation"]}}),
            external_pentest_profile(),
        )
        assert plan.phase("validation") is None
        # reporting depends on validation, so its dep is dropped
        reporting = plan.phase("reporting")
        assert reporting is not None
        assert reporting.depends_on == ("enumeration",)

    def test_required_phase_dependency_forced_in(self) -> None:
        planner = MissionPlanner()
        # web profile: assess is optional but report depends on it
        plan = planner.expand(
            _plan(profile_id="web-pentest", mission_type=MissionType.WEB_APPLICATION_PENTEST),
            web_pentest_profile(),
        )
        assert plan.phase("assess") is not None

    def test_estimated_duration_is_summed(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(_plan(), external_pentest_profile())
        assert plan.estimated_duration_seconds == 600 + 900 + 300 + 120

    def test_config_and_variables_resolved(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(
            _plan(variables={"prefix": "acme"}, config={"scope": "{{ prefix }}.com"}),
            external_pentest_profile(),
        )
        assert plan.config["scope"] == "acme.com"
        assert plan.variables["prefix"] == "acme"

    def test_template_phase_override(self) -> None:
        from hunterx.domain.mission_planning import MissionPhase, MissionPhaseKind

        planner = MissionPlanner()
        template = MissionTemplate(
            template_id="custom",
            name="Custom",
            profile_id="web-pentest",
            phases_override=(
                MissionPhase(
                    phase_id="custom-only",
                    name="Custom Only",
                    kind=MissionPhaseKind.CLEANUP,
                    estimated_duration_seconds=10,
                    actions=("cleanup.run",),
                ),
            ),
        )
        plan = planner.expand(
            _plan(profile_id="web-pentest", mission_type=MissionType.WEB_APPLICATION_PENTEST),
            web_pentest_profile(),
            template=template,
        )
        assert [phase.phase_id for phase in plan.phases] == ["custom-only"]

    def test_unsupported_mission_type_raises(self) -> None:
        planner = MissionPlanner()
        with pytest.raises(MissionPlanValidationError, match="does not support"):
            planner.expand(
                _plan(mission_type=MissionType.MOBILE_ASSESSMENT),
                external_pentest_profile(),
            )

    def test_excluded_tool_raises(self) -> None:
        planner = MissionPlanner()
        with pytest.raises(MissionPlanValidationError, match="exclusion"):
            planner.expand(
                _plan(config={"tools": ["hydra"]}),
                external_pentest_profile(),
            )

    def test_requested_tool_outside_allowed_raises(self) -> None:
        planner = MissionPlanner()
        with pytest.raises(MissionPlanValidationError, match="outside"):
            planner.expand(
                _plan(config={"tools": ["sqlmap"]}),
                external_pentest_profile(),
            )

    def test_allowed_tool_passes(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(
            _plan(config={"tools": ["nmap", "nuclei"]}),
            external_pentest_profile(),
        )
        assert plan.phase("recon") is not None

    def test_approval_level_from_profile(self) -> None:
        from hunterx.domain.mission_planning import MissionApprovalLevel

        planner = MissionPlanner()
        plan = planner.expand(_plan(), external_pentest_profile())
        assert plan.approval_level is MissionApprovalLevel.OPERATOR

    def test_phase_states_pending_after_expand(self) -> None:
        planner = MissionPlanner()
        plan = planner.expand(_plan(), external_pentest_profile())
        assert all(phase.status is MissionPhaseState.PENDING for phase in plan.phases)

    def test_request_from_plan_round_trip(self) -> None:
        planner = MissionPlanner()
        original = _plan()
        plan = planner.expand(original, external_pentest_profile())
        request = planner.request_from_plan(plan)
        assert request.profile_id == "external-pentest"
        assert request.targets == ("a.com",)
        assert request.mission_type is MissionType.EXTERNAL_PENTEST


class TestPlannerValidation:
    def test_profile_type_mismatch_in_validate(self) -> None:
        planner = MissionPlanner()
        plan = _plan(mission_type=MissionType.MOBILE_ASSESSMENT)
        errors = planner.validate(plan, external_pentest_profile())
        assert errors
        assert any("does not support" in error for error in errors)

    def test_validate_empty_is_clean(self) -> None:
        planner = MissionPlanner()
        errors = planner.validate(_plan(), external_pentest_profile())
        assert errors == []
