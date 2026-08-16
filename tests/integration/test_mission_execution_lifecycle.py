# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the HuntX mission execution lifecycle.

Reproduces the failure where ``hunterx hunt`` created a mission but execution
never started (``planning_state = discovery``, ``tool_executions = 0``,
``decisions = 0``, ``observations = 0``). After the fix, mission creation is
followed by an initial decision, a real tool-execution attempt, observation
ingestion, target modeling and adaptive continuation.

The external execution layer is replaced by a deterministic fake so the real
orchestration path (planning → decision → execution → ingestion → replanning)
is exercised without network access or external binaries.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.platform import build_platform
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "https://juice-shop.herokuapp.com"

_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "subdomain_enumeration": ("subfinder", "amass", "assetfinder"),
    "dns_enumeration": ("dnsx", "dig"),
    "port_discovery": ("nmap", "rustscan", "masscan"),
    "service_detection": ("nmap", "httpx"),
    "technology_fingerprint": ("whatweb", "wappalyzer"),
    "certificate_enumeration": ("certspotter", "crt.sh"),
    "endpoint_enumeration": ("httpx", "katana", "gospider"),
    "parameter_discovery": ("arjun", "x8"),
    "vulnerability_scanning": ("nuclei", "nikto"),
}

_FAKE_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {
        "discoveries": [{"kind": "subdomain", "name": "api.juice-shop.herokuapp.com"}],
        "count": 1,
    },
    "dnsx": {"records": ["api.juice-shop.herokuapp.com -> 1.2.3.4"]},
    "nmap": {"ports": [80, 443]},
    "whatweb": {"name": "express", "technologies": ["node.js", "express"]},
    "httpx": {"endpoints": ["/rest/products/search", "/api/products"]},
    "arjun": {"parameters": ["q", "id"]},
    "nuclei": {"findings": [{"template": "missing-security-headers", "severity": "low"}]},
    "certspotter": {"certificates": ["juice-shop.herokuapp.com"]},
}


def _runner(fake: FakeExecutionEngine) -> tuple[MissionExecutionService, MissionOrchestrationService]:
    """Assemble a mission execution runner over real planning/orchestration.

    Uses the same deterministic tool-default candidates as the composition
    root so tool selection resolves to real, registered tool ids.
    """
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=_DEFAULT_CANDIDATES,
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
        execution_engine=fake,
    )
    return runner, orchestration


def _mission(orchestration: MissionOrchestrationService, *, coverage_target: float = 0.99):
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=coverage_target,
        stop_conditions=(
            StopCondition.COVERAGE_TARGET_ACHIEVED,
            StopCondition.RESOURCE_BUDGET_EXHAUSTED,
        ),
    )
    orchestration.start(mission.mission_id)
    return mission


class TestMissionStartsExecution:
    def test_creation_is_followed_by_decision_and_execution(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=16)

        # A terminal runner exit finalizes the mission: terminal state, an
        # outcome record and a completed run with a finish timestamp.
        assert mission.mission.state.value == "completed"
        assert mission.outcome is not None
        assert mission.runs, "a run record must exist"
        assert mission.runs[-1].status.value == "completed"
        assert mission.runs[-1].finished_at, "the run must record a finish timestamp"
        assert result["cycles_run"] >= 1
        assert mission.decisions, "an initial decision must be generated"
        assert fake.calls, "a tool execution must be attempted"
        assert mission.context.tool_executions, "tool executions must be recorded"

    def test_first_execution_is_real(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=16)

        assert len(mission.context.tool_executions) > 0
        assert mission.budget.executions_used > 0
        assert len(mission.observations) > 0
        assert len(mission.decisions) > 0
        assert mission.coverage_ratio() > 0.0

    def test_successful_result_ingests_observation_and_updates_target_model(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=16)

        assert mission.observations, "observations must be persisted"
        assert mission.context.technologies, "technology fingerprints must update target modeling"
        assert mission.context.endpoints, "endpoint enumeration must update target modeling"
        assert mission.context.services, "service detection must update target modeling"

    def test_planner_continues_after_first_observation(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=16)

        # At least two distinct actions were decided and executed, proving the
        # planner produced a follow-on decision after the first observation.
        assert len(mission.decisions) >= 2
        executed = {execution["tool_id"] for execution in mission.context.tool_executions}
        assert len(executed) >= 2

    def test_adaptive_replan_after_observation(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)
        planning = runner._planning

        runner.run(mission.mission_id, max_cycles=24)

        # Endpoint discovery schedules parameter discovery via replanning:
        # the plan graph gains the capability and the plan is re-versioned.
        assert any(action.capability == "parameter_discovery" for action in planning.get_plan(mission.mission_id).actions.values())
        assert planning.get_mission(mission.mission_id).plan_version >= 2

    def test_no_premature_termination_without_discovery(self) -> None:
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=MissionOrchestrator()),
        )
        mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)

        # A mission that has not started discovery is not complete.
        assert mission.context.assets == {}
        assert mission.observations == []
        assert mission.mission.state.value != "completed"
        assert mission.outcome is None


class TestToolFailure:
    def test_failure_is_structured_and_observable(self) -> None:
        fake = FakeExecutionEngine(
            outputs=dict(_FAKE_OUTPUTS),
            fail_tools=("subfinder",),
            error="Failed to start tool binary 'subfinder'",
        )
        runner, orchestration = _runner(fake)
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=4)

        assert result["cycles"][0]["status"] == "failed"
        assert mission.negative_evidence, "a failed execution must record negative evidence"
        assert any(record.kind.value == "blocked" for record in mission.negative_evidence)
        assert mission.budget.executions_used > 0
        assert mission.observations, "a failed execution must still produce a persisted observation"
        # the mission is not silently returned to its initial snapshot
        assert mission.context.tool_executions
        assert mission.mission.failures, "the planner must classify the failure"


class TestToolRegistration:
    def test_composition_root_exposes_discovery_capability(self) -> None:
        platform = build_platform()
        # A real discovery adapter is registered on the Tool Integration SDK.
        assert platform.execution_engine.adapter_for("subfinder") is not None
        assert platform.execution_engine.adapter_for("httpx") is not None
        # Capability-driven tool selection resolves a discovery tool.
        mission = platform.adaptive_mission_planning.create_mission(
            objective="attack_surface_discovery",
            target=_TARGET,
        )
        action = next(iter(mission.graph.actions.values()))
        selection = platform.adaptive_mission_planning.select_tool(mission.mission_id, action.action_id)
        assert selection.tool_id, "tool selection must resolve a tool for the discovery capability"


class TestCLIIntegration:
    def test_hunt_reaches_execution_layer(self, capsys: pytest.CaptureFixture[str]) -> None:
        platform = build_platform()
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        platform.mission_execution_service._engine = fake  # noqa: SLF001  # swap the network layer only
        platform.mission_execution_service._readiness = _PassingReadiness()  # noqa: SLF001  # preflight passes

        app = CliApplication()
        register_default_commands(app, platform)

        assert app.run(["hunt", "full_security_assessment", _TARGET]) == 0
        overview = json.loads(capsys.readouterr().out)

        assert fake.calls, "the CLI path must reach the tool execution layer"
        assert overview["counts"]["tool_executions"] > 0
        assert overview["counts"]["decisions"] > 0
        assert overview["counts"]["observations"] > 0
        assert overview["counts"]["negative_evidence"] >= 0
        assert overview["coverage_ratio"] > 0.0
        # The runner finalizes every terminal exit: the mission is never left
        # running when the CLI returns.
        assert overview["planning_state"] == "completed"
        assert overview["outcome"] is not None


class _PassingReadiness:
    """Readiness double whose preflight always allows execution."""

    def preflight(self, capabilities, *, mission_id="", auto_provision=True):  # noqa: ANN001, ANN003
        from hunterx.tools.readiness.models import PreflightResult, PreflightStatus

        return PreflightResult(status=PreflightStatus.PASS, mission_id=mission_id)
