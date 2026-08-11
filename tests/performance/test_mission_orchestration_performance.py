# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance tests for the Autonomous Mission Orchestration.

Sprint 032 §51. Benchmarks 1/10/100 missions, 10k/100k observations and 1k
tool executions; the planner/decision latency must remain bounded.
"""

from __future__ import annotations

import time

from hunterx.domain.mission_orchestration.decision import CandidateAction
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator


def _seed_mission(orchestrator: MissionOrchestrator) -> str:
    mission = orchestrator.create_mission(objective="full_security_assessment", target="https://example.com")
    return mission.mission_id


class TestMissionScalability:
    def test_10_missions_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        started = time.monotonic()
        for _ in range(10):
            _seed_mission(orchestrator)
        elapsed = time.monotonic() - started
        assert len(orchestrator.missions()) == 10
        assert elapsed < 5.0

    def test_100_missions_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        started = time.monotonic()
        for _ in range(100):
            _seed_mission(orchestrator)
        elapsed = time.monotonic() - started
        assert len(orchestrator.missions()) == 100
        assert elapsed < 20.0

    def test_decision_latency_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        mission_id = _seed_mission(orchestrator)
        candidates = tuple(
            CandidateAction(
                action_id=f"a{i}",
                capability="recon",
                tool_ids=("subfinder", "amass"),
                expected_information_gain=0.5 + i * 0.01,
            )
            for i in range(50)
        )
        started = time.monotonic()
        for _ in range(100):
            orchestrator.decide_next(mission_id, candidates=candidates)
        elapsed = time.monotonic() - started
        assert elapsed < 5.0  # 100 decisions over 50 candidates stays bounded

    def test_10k_observations_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        mission_id = _seed_mission(orchestrator)
        started = time.monotonic()
        for index in range(10_000):
            orchestrator.ingest_result(
                mission_id,
                tool_id="httpx",
                asset_key="https://example.com",
                raw={"observation_type": "service", "content": {"index": index}},
            )
        elapsed = time.monotonic() - started
        mission = orchestrator.get(mission_id)
        assert len(mission.observations) == 10_000
        assert elapsed < 15.0

    def test_100k_observations_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        mission_id = _seed_mission(orchestrator)
        started = time.monotonic()
        for index in range(100_000):
            orchestrator.ingest_result(
                mission_id,
                tool_id="httpx",
                asset_key="https://example.com",
                raw={"observation_type": "service", "content": {"index": index}},
            )
        elapsed = time.monotonic() - started
        mission = orchestrator.get(mission_id)
        assert len(mission.observations) == 100_000
        assert elapsed < 60.0

    def test_1000_tool_executions_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        mission_id = _seed_mission(orchestrator)
        started = time.monotonic()
        for index in range(1_000):
            orchestrator.ingest_result(
                mission_id,
                tool_id="tool",
                asset_key=f"https://example.com/{index}",
                raw={"observation_type": "endpoint", "content": {"path": f"/{index}"}},
            )
        elapsed = time.monotonic() - started
        assert orchestrator.get(mission_id).budget.executions_used == 1_000
        assert elapsed < 5.0

    def test_large_target_graph_hypothesis_generation_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        mission_id = _seed_mission(orchestrator)
        started = time.monotonic()
        for index in range(500):
            orchestrator.add_hypothesis(
                mission_id,
                statement=f"hypothesis {index}",
                category="injection",
                priority=0.5 + index * 0.0005,
            )
        elapsed = time.monotonic() - started
        assert len(orchestrator.get(mission_id).hypotheses) == 500
        assert elapsed < 5.0

    def test_parallel_branches_ranked_bounded(self) -> None:
        orchestrator = MissionOrchestrator()
        mission_id = _seed_mission(orchestrator)
        started = time.monotonic()
        for index in range(200):
            orchestrator.fork_branch(
                mission_id,
                hypothesis_id=f"h{index}",
                rationale=f"branch {index}",
                priority=1.0 - index * 0.004,
            )
        open_branches = orchestrator.get(mission_id).open_branches()
        elapsed = time.monotonic() - started
        assert len(open_branches) == 200
        assert elapsed < 5.0
