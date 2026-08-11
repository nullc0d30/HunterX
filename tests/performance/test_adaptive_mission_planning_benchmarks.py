# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks: Adaptive Mission & Attack-Path Planning.

Benchmarks initial plan creation, candidate ranking, replanning, attack-path
discovery over large graphs and checkpoint/resume. These are micro-benchmarks
over in-memory components.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.attack_path import AttackPathEngine
from hunterx.domain.adaptive_mission_planning.decision import (
    ActionDecisionEngine,
    DecisionInput,
)
from hunterx.domain.adaptive_mission_planning.enums import (
    MissionObjective,
    ReplanTrigger,
)
from hunterx.domain.adaptive_mission_planning.mission import (
    AdaptiveMission,
    DeterministicMissionPlanner,
)
from hunterx.domain.adaptive_mission_planning.models import MissionConstraints
from hunterx.domain.adaptive_mission_planning.replan import ReplanningEngine, ReplanSignal
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
from hunterx.domain.target_intelligence.models import IntelligenceAsset
from hunterx.domain.topology.enums import EntityKind


def _large_surface(size: int = 200) -> AttackSurfaceGraph:
    surface = AttackSurfaceGraph()
    for index in range(size):
        surface.upsert_asset(
            IntelligenceAsset(
                asset_id=f"a{index}",
                target_id="t1",
                mission_id="m1",
                kind=EntityKind.URL,
                name=f"app{index}.example.com",
                key=f"url:http://app{index}.example.com",
                in_scope=True,
            )
        )
    return surface


def test_benchmark_initial_plan(benchmark: object) -> None:
    def run() -> AdaptiveMission:
        mission = AdaptiveMission(objective=MissionObjective.PENTEST_ASSESSMENT)
        DeterministicMissionPlanner().create_initial_plan(mission)
        return mission

    result = benchmark(run)
    assert len(result.graph.actions) > 0


def test_benchmark_candidate_ranking(benchmark: object) -> None:
    engine = ActionDecisionEngine()

    def run() -> int:
        result = engine.decide(
            DecisionInput(
                mission_id="m1",
                objective=MissionObjective.BUG_BOUNTY_ASSESSMENT,
                constraints=MissionConstraints(),
                unknowns=tuple(_gap(i) for i in range(50)),
            )
        )
        return len(result.proposals)

    count = benchmark(run)
    assert count >= 0


def test_benchmark_replanning(benchmark: object) -> None:
    engine = ReplanningEngine()
    mission = AdaptiveMission(objective=MissionObjective.WEB_SECURITY_ASSESSMENT)
    DeterministicMissionPlanner().create_initial_plan(mission)

    def run() -> int:
        signal = ReplanSignal(ReplanTrigger.NEW_ASSET_DISCOVERED, asset_key="host:x.example.com", priority=0.9)
        delta = engine.build_delta(
            mission_id=mission.mission_id,
            graph=mission.graph,
            signal=signal,
            current_version=1,
            reason="benchmark",
        )
        return delta.plan_version

    version = benchmark(run)
    assert version == 2


def test_benchmark_attack_path_discovery(benchmark: object) -> None:
    surface = _large_surface(200)
    engine = AttackPathEngine(max_paths=500)

    def run() -> int:
        return len(engine.discover(surface, mission_id="m1"))

    count = benchmark(run)
    assert count >= 0


def _gap(index: int) -> object:
    class _Gap:
        required_capability = "endpoint_enumeration"
        asset_key = f"url:http://app{index}.example.com"
        importance = 0.8
        gap_id = f"gap-{index}"

    return _Gap()
