# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden tests for Adaptive Mission & Attack-Path Planning.

Verifies deterministic behavior and replayability: identical inputs produce
identical planning decisions, plan deltas and attack-path states.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import (
    MissionObjective,
    ReplanTrigger,
)
from hunterx.domain.adaptive_mission_planning.mission import (
    AdaptiveMission,
    DeterministicMissionPlanner,
)
from hunterx.domain.adaptive_mission_planning.replan import ReplanningEngine, ReplanSignal


class TestGoldenReplanning:
    def test_initial_plan_is_deterministic(self) -> None:
        missions = [
            AdaptiveMission(objective=MissionObjective.WEB_SECURITY_ASSESSMENT),
            AdaptiveMission(objective=MissionObjective.WEB_SECURITY_ASSESSMENT),
        ]
        for mission in missions:
            DeterministicMissionPlanner().create_initial_plan(mission)
        first = [action.capability for action in missions[0].graph.actions.values()]
        second = [action.capability for action in missions[1].graph.actions.values()]
        assert first == second

    def test_replan_delta_is_replayable(self) -> None:
        engine = ReplanningEngine()
        mission = AdaptiveMission(objective=MissionObjective.PENTEST_ASSESSMENT)
        DeterministicMissionPlanner().create_initial_plan(mission)
        signal = ReplanSignal(ReplanTrigger.NEW_ASSET_DISCOVERED, asset_key="host:x.example.com", priority=0.9)
        delta_a = engine.build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=1,
            reason="asset",
        )
        mission.graph.apply_delta(delta_a)
        mission.record_version(engine.version_for(delta_a))

        # replay the same signal on a fresh copy
        fresh = AdaptiveMission(objective=MissionObjective.PENTEST_ASSESSMENT)
        DeterministicMissionPlanner().create_initial_plan(fresh)
        delta_b = engine.build_delta(
            mission_id=fresh.mission_id,
            graph=fresh.graph,
            signal=signal,
            current_version=1,
            reason="asset",
        )
        assert [c.kind for c in delta_a.changes] == [c.kind for c in delta_b.changes]
        assert delta_a.plan_version == delta_b.plan_version

    def test_plan_version_history_reconstructs(self) -> None:
        mission = AdaptiveMission(objective=MissionObjective.ATTACK_SURFACE_DISCOVERY)
        DeterministicMissionPlanner().create_initial_plan(mission)
        engine = ReplanningEngine()
        signal = ReplanSignal(ReplanTrigger.NEW_ENDPOINT_DISCOVERED, asset_key="url:http://x.com", priority=0.9)
        delta = engine.build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=mission.plan_version,
            reason="endpoint",
        )
        mission.graph.apply_delta(delta)
        version = engine.version_for(delta)
        assert version.plan_version == 2
        assert version.parent_version == 1
        # the version history is a deterministic record of the delta
        assert set(version.changed_nodes) == {
            change.action_id for change in delta.changes if change.action_id
        }
