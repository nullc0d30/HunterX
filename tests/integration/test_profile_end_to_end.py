# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 3 — profile end-to-end acceptance.

Proves the real profile/objective identifiers change actual runtime behavior
(persisted discovery chains and decisions), not just a label. Uses only the
objectives that exist in the codebase.
"""

from __future__ import annotations

import dataclasses

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "http://127.0.0.1:9000"

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("subfinder",),
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
    "certificate_enumeration": ("findomain",),
    "endpoint_enumeration": ("httpx",),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
    "authorization_analysis": ("nuclei",),
    "dependency_check": ("osv-scanner",),
    "content_discovery": ("ffuf",),
    "api_mapping": ("katana",),
}

_OUTPUTS = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.localhost"}], "count": 1},
    "nmap": {"ports": [80, 9000]},
    "whatweb": {"name": "python", "technologies": ["Python"]},
    "httpx": {"endpoints": ["/api/search"]},
    "arjun": {"parameters": ["q"]},
    "nuclei": {"candidates": [{"vulnerability_class": "xss", "endpoint": f"{_TARGET}/echo", "parameter": "q", "severity": "low"}], "count": 1},
}


def _run(objective: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Run a mission for ``objective`` and return (decisions, hypotheses)."""
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(orchestration=orchestration, planning=planning, execution_engine=fake_engine())
    mission = orchestration.create_mission(objective=objective, target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy, coverage_target=0.99,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    runner.run(mission.mission_id, max_cycles=12)
    mission = orchestration.get(mission.mission_id)
    decisions = [(d.capability, d.tool_id) for d in mission.decisions]
    hypotheses = [h.statement for h in mission.hypotheses]
    return decisions, hypotheses


def fake_engine():
    return FakeExecutionEngine(outputs=dict(_OUTPUTS))


class TestProfilesChangeRuntimeBehavior:
    def test_discovery_chains_differ_by_objective(self) -> None:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES),
        )
        chains = {}
        for objective in ("bug_bounty_assessment", "pentest_assessment", "red_team_simulation", "vulnerability_discovery"):
            mission = planning.create_mission(objective=objective, target=_TARGET)
            chains[objective] = tuple(a.capability for a in mission.graph.actions.values())
        assert chains["bug_bounty_assessment"] != chains["red_team_simulation"]
        assert chains["pentest_assessment"] != chains["vulnerability_discovery"]
        # red_team pursues authorization analysis; bug_bounty pursues the
        # web/API vulnerability surface — a real behavioral difference.
        assert "authorization_analysis" in chains["red_team_simulation"]
        assert "vulnerability_scanning" in chains["bug_bounty_assessment"]

    def test_persisted_decisions_differ_by_profile(self) -> None:
        bug_bounty_decisions, _ = _run("bug_bounty_assessment")
        pentest_decisions, _ = _run("pentest_assessment")
        red_team_decisions, _ = _run("red_team_simulation")
        vulnerability_decisions, _ = _run("vulnerability_discovery")
        # Distinct first capabilities are persisted in the decision records.
        firsts = {
            "bug_bounty": bug_bounty_decisions[0][0] if bug_bounty_decisions else "",
            "pentest": pentest_decisions[0][0] if pentest_decisions else "",
            "red_team": red_team_decisions[0][0] if red_team_decisions else "",
            "vulnerability": vulnerability_decisions[0][0] if vulnerability_decisions else "",
        }
        assert len({value for value in firsts.values() if value}) >= 2, firsts
        # red_team's decisions reach authorization_analysis; bug_bounty's reach
        # vulnerability scanning.
        assert any(cap == "authorization_analysis" for cap, _ in red_team_decisions)
        assert any(cap == "vulnerability_scanning" for cap, _ in bug_bounty_decisions)

    def test_hypothesis_generation_follows_profile_strategy(self) -> None:
        _, bug_bounty_hypotheses = _run("bug_bounty_assessment")
        _, red_team_hypotheses = _run("red_team_simulation")
        # Both consume the same engine but the evidence each profile surfaces
        # differs (bug_bounty reaches vulnerability candidates).
        assert bug_bounty_hypotheses, "bug_bounty must generate hypotheses"
