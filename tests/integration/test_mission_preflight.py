# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the mission preflight gate.

Verifies that the mission execution runner consults tool readiness BEFORE
execution: a blocked preflight produces a structured ``blocked`` outcome with
zero executions, a degraded preflight still executes, and a passed preflight
executes normally. The external execution layer is a deterministic fake.
"""

from __future__ import annotations

import dataclasses

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.readiness.models import PreflightResult, PreflightStatus
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "https://juice-shop.herokuapp.com"

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
    "endpoint_enumeration": ("httpx",),
}

_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.target"}]},
    "dnsx": {"records": ["api.target -> 1.2.3.4"]},
    "nmap": {"ports": [80, 443]},
    "whatweb": {"name": "express"},
    "httpx": {"endpoints": ["/api"]},
}


class StubReadiness:
    """Readiness double returning a fixed preflight verdict."""

    def __init__(self, result: PreflightResult) -> None:
        self._result = result
        self.calls: list[str] = []

    def preflight(self, capabilities, *, mission_id="", auto_provision=True, profile_tools=(), **_kwargs):  # noqa: ANN001
        self.calls.append(str(capabilities))
        result = self._result
        return PreflightResult(
            status=result.status,
            mission_id=mission_id,
            required_missing=result.required_missing,
            missing_tools=result.missing_tools,
            optional_missing=result.optional_missing,
            provision_attempted=result.provision_attempted,
            provisioned=result.provisioned,
            provision_failures=result.provision_failures,
            blocked_reason=result.blocked_reason,
        )


def _runner(readiness: StubReadiness | None) -> tuple[MissionExecutionService, MissionOrchestrationService]:
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=_CANDIDATES,
        ),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=FakeExecutionEngine(outputs=dict(_OUTPUTS)),
        readiness=readiness,
    )
    return runner, orchestration


def _mission(orchestration: MissionOrchestrationService):
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(mission.policy, coverage_target=0.99)
    orchestration.start(mission.mission_id)
    return mission


def _blocked() -> PreflightResult:
    return PreflightResult(
        status=PreflightStatus.BLOCKED,
        required_missing=("subdomain_enumeration",),
        missing_tools=("subfinder",),
        blocked_reason="mission blocked: required capabilities without an available provider",
    )


class TestPreflightGate:
    def test_blocked_preflight_prevents_execution(self) -> None:
        runner, orchestration = _runner(StubReadiness(_blocked()))
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=8)

        assert result["status"] == "blocked"
        assert result["cycles_run"] == 0
        assert result["executions_used"] == 0
        assert result["tool_executions"] == 0
        assert "blocked" in result["reason"]
        assert result["preflight"]["status"] == "blocked"
        assert not mission.context.tool_executions, "no execution may start when blocked"

    def test_blocked_preflight_records_no_observations_or_decisions(self) -> None:
        runner, orchestration = _runner(StubReadiness(_blocked()))
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=8)

        assert result["observations"] == 0
        assert result["decisions"] == 0
        assert mission.observations == []
        assert mission.decisions == []

    def test_degraded_preflight_still_executes(self) -> None:
        degraded = PreflightResult(
            status=PreflightStatus.DEGRADED,
            optional_missing=("certificate_enumeration",),
        )
        runner, orchestration = _runner(StubReadiness(degraded))
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=8)

        assert result["status"] == "degraded"
        assert result["cycles_run"] >= 1
        assert result["tool_executions"] > 0
        assert result["observations"] > 0

    def test_passed_preflight_executes(self) -> None:
        runner, orchestration = _runner(StubReadiness(PreflightResult(status=PreflightStatus.PASS)))
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=8)

        # A passed preflight lets execution happen. The terminal is truthful:
        # never a budget exhaustion (the budget is nowhere near used) — an
        # incomplete mission with open hypothesis work honestly reports
        # ``blocked``, never ``exhausted``.
        assert result["status"] in ("completed", "degraded", "blocked")
        assert result["status"] != "exhausted"
        assert result["cycles_run"] >= 1
        assert result["tool_executions"] > 0
        assert result["observations"] > 0

    def test_missing_readiness_skips_the_gate(self) -> None:
        runner, orchestration = _runner(None)
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=8)

        assert result["cycles_run"] >= 1
        assert result["tool_executions"] > 0
