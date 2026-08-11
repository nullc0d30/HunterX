# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the mission profile engine and template registration."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import (
    MissionPlanningError,
    MissionProfileNotFoundError,
    MissionTemplateNotFoundError,
)
from hunterx.domain.mission_planning import (
    MissionApprovalLevel,
    MissionPhase,
    MissionPhaseKind,
    MissionProfile,
    MissionTemplate,
)
from hunterx.engines.mission_planning.profiles import MissionProfileEngine, merge_profiles
from tests.framework.mission_planning import (
    InMemoryMissionProfileRepository,
    InMemoryMissionTemplateRepository,
    external_pentest_profile,
    web_pentest_profile,
)


def _profile_engine() -> MissionProfileEngine:
    return MissionProfileEngine(
        profiles=InMemoryMissionProfileRepository(),
        templates=InMemoryMissionTemplateRepository(),
    )


class TestMissionProfileEngine:
    def test_register_and_resolve(self) -> None:
        engine = _profile_engine()
        engine.register_profile(external_pentest_profile())
        resolved = engine.resolve_profile("external-pentest")
        assert resolved.name == "External Penetration Test"
        assert len(resolved.phases) == 4

    def test_unknown_profile_raises(self) -> None:
        engine = _profile_engine()
        with pytest.raises(MissionProfileNotFoundError):
            engine.resolve_profile("ghost")

    def test_inheritance_merges_phases_and_fields(self) -> None:
        engine = _profile_engine()
        engine.register_profile(web_pentest_profile())
        child = MissionProfile(
            profile_id="web-child",
            name="Web Child",
            parent="web-pentest",
            phases=(
                MissionPhase(
                    phase_id="assess",
                    name="Assessment Override",
                    kind=MissionPhaseKind.VULNERABILITY_ASSESSMENT,
                    estimated_duration_seconds=999,
                ),
            ),
            approval_level=MissionApprovalLevel.AUTO,
        )
        engine.register_profile(child)
        resolved = engine.resolve_profile("web-child")
        # child override wins by id
        assess = resolved.phase("assess")
        assert assess is not None
        assert assess.estimated_duration_seconds == 999
        assert assess.name == "Assessment Override"
        # parent-only phases preserved in parent order
        phase_ids = [phase.phase_id for phase in resolved.phases]
        assert phase_ids == ["assess", "crawl", "fingerprint", "report"]
        # non-default child approval wins
        assert resolved.approval_level is MissionApprovalLevel.AUTO

    def test_inherited_default_approval_level(self) -> None:
        engine = _profile_engine()
        base = MissionProfile(
            profile_id="base",
            name="Base",
            approval_level=MissionApprovalLevel.OPERATOR,
            phases=(MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        engine.register_profile(base)
        child = MissionProfile(
            profile_id="child",
            name="Child",
            parent="base",
            phases=(MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        engine.register_profile(child)
        resolved = engine.resolve_profile("child")
        assert resolved.approval_level is MissionApprovalLevel.OPERATOR

    def test_inheritance_cycle_raises(self) -> None:
        engine = _profile_engine()
        a = MissionProfile(
            profile_id="a",
            name="A",
            parent="b",
            phases=(MissionPhase(phase_id="a1", name="A1", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        b = MissionProfile(
            profile_id="b",
            name="B",
            parent="a",
            phases=(MissionPhase(phase_id="b1", name="B1", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        engine.register_profile(a)
        with pytest.raises(MissionPlanningError, match="cycle"):
            engine.register_profile(b)

    def test_unknown_parent_raises_on_resolve(self) -> None:
        engine = _profile_engine()
        child = MissionProfile(
            profile_id="orphan",
            name="Orphan",
            parent="missing-parent",
            phases=(MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        engine.register_profile(child)
        with pytest.raises(MissionProfileNotFoundError):
            engine.resolve_profile("orphan")

    def test_template_registration_and_resolution(self) -> None:
        engine = _profile_engine()
        engine.register_profile(web_pentest_profile())
        template = MissionTemplate(
            template_id="quick-web",
            name="Quick Web",
            profile_id="web-pentest",
            variables={"depth": "fast"},
        )
        engine.register_template(template)
        resolved = engine.resolve_template("quick-web")
        assert resolved.variables == {"depth": "fast"}

    def test_template_unknown_profile_raises(self) -> None:
        engine = _profile_engine()
        template = MissionTemplate(template_id="t", name="T", profile_id="ghost")
        with pytest.raises(MissionProfileNotFoundError):
            engine.register_template(template)

    def test_unknown_template_raises(self) -> None:
        engine = _profile_engine()
        with pytest.raises(MissionTemplateNotFoundError):
            engine.resolve_template("ghost")


class TestMergeProfiles:
    def test_allowed_tools_list_merge(self) -> None:
        parent = MissionProfile(
            profile_id="p",
            name="P",
            allowed_tools={"include": ["nmap", "nuclei"], "exclude": ["hydra"]},
            phases=(MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        child = MissionProfile(
            profile_id="c",
            name="C",
            parent="p",
            allowed_tools={"include": ["masscan"]},
            phases=(MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        merged = merge_profiles(parent, child)
        # child-first union: masscan + parent's nmap/nuclei
        assert merged.allowed_tools["include"] == ["masscan", "nmap", "nuclei"]
        # parent-only key inherited untouched
        assert merged.allowed_tools["exclude"] == ["hydra"]

    def test_dict_deep_merge(self) -> None:
        parent = MissionProfile(
            profile_id="p",
            name="P",
            constraints={"max_scan_duration_h": 24, "max_concurrency": 10},
            phases=(MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        child = MissionProfile(
            profile_id="c",
            name="C",
            parent="p",
            constraints={"max_concurrency": 5},
            phases=(MissionPhase(phase_id="a", name="A", kind=MissionPhaseKind.RECONNAISSANCE),),
        )
        merged = merge_profiles(parent, child)
        assert merged.constraints["max_scan_duration_h"] == 24
        assert merged.constraints["max_concurrency"] == 5
