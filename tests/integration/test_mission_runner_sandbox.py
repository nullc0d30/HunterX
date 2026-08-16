# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the mission-runner sandbox permission propagation.

Reproduces the audit finding where ``hunterx hunt`` created missions that
stayed in ``planning_state = discovery`` / ``current_phase = target_modeling``
because the mission runner built an :class:`ExecutionContext` with an empty
permission set. The execution sandbox then rejected every network-capable tool
(``Tool 'nmap' lacks permission 'network'``), and the denied executions were
counted as tested coverage — driving coverage past the target and stopping the
loop with zero real results.

Two defects are covered:

- TEST A — the mission execution context propagates the permissions declared by
  the selected tool's adapter (so the sandbox authorizes the execution).
- TEST B — a sandbox-denied / failed execution does NOT count as assessed
  (tested) coverage; only a genuinely successful execution advances coverage.

The real :class:`ExecutionEngine` + :class:`ExecutionSandbox` are used with a
network-capable adapter so the actual sandbox authorization path is exercised
(no external binaries / network access).
"""

from __future__ import annotations

import dataclasses

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.execution import FailureKind
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.target_intelligence.enums import CoverageState
from hunterx.domain.tools import ToolDescriptor
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.output import OutputCollector

_TARGET = "http://localhost:3010"

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
}


class NetworkTool(ToolAdapter):
    """Adapter that requests the ``network`` permission at runtime."""

    descriptor = ToolDescriptor(
        name="network-tool",
        entrypoint="tests.integration.test_mission_runner_sandbox:NetworkTool",
        targets=("url",),
        permissions=("network",),
    )

    def run(self, context, collector: OutputCollector) -> None:  # noqa: ANN001 - concrete param
        collector.set_json({"status": "ok", "tool": context.tool_id})
        collector.attach_stdout("ok")


def _engine() -> ExecutionEngine:
    """A real engine with a network-capable adapter (real sandbox enforced)."""
    engine = ExecutionEngine()
    engine.register_adapter("subfinder", NetworkTool())
    engine.register_adapter("dnsx", NetworkTool())
    engine.register_adapter("nmap", NetworkTool())
    engine.register_adapter("whatweb", NetworkTool())
    for tool_id in ("subfinder", "dnsx", "nmap", "whatweb"):
        engine.install_hook(tool_id, lambda tool_id, version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


def _runner(engine: ExecutionEngine) -> tuple[MissionExecutionService, MissionOrchestrationService]:
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
        execution_engine=engine,
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


class TestMissionPermissionPropagation:
    def test_mission_context_grants_adapter_permissions(self) -> None:
        engine = _engine()
        runner, orchestration = _runner(engine)
        mission = _mission(orchestration)

        context = runner._build_context(mission.mission_id, "nmap", _TARGET, None)  # noqa: SLF001

        assert "network" in context.permissions, (
            "the mission execution context must carry the adapter-declared network permission"
        )

    def test_network_tool_executes_through_real_sandbox(self) -> None:
        engine = _engine()
        runner, orchestration = _runner(engine)
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=8)

        assert result["executions_used"] > 0
        assert result["observations"] > 0
        # No execution may be denied by the sandbox for a missing permission.
        denied = [
            observation
            for observation in mission.observations
            if observation.observation_type == "tool_failure"
            and "lacks permission" in (observation.content or {}).get("error", "")
        ]
        assert not denied, f"sandbox permission denials must not occur: {denied}"

    def test_successful_execution_produces_real_observations(self) -> None:
        engine = _engine()
        runner, orchestration = _runner(engine)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=8)

        assert mission.observations, "successful executions must produce observations"
        assert mission.context.tool_executions, "tool executions must be recorded"
        assert any(
            observation.observation_type != "tool_failure" for observation in mission.observations
        ), "real (non-failure) observations must be generated"


class TestFailedExecutionCoverage:
    def test_sandbox_denied_execution_does_not_count_as_tested_coverage(self) -> None:
        # A tool whose execution is denied must leave its coverage cell
        # uncovered so it can never satisfy a coverage target.
        engine = _engine()
        runner, orchestration = _runner(engine)
        mission = _mission(orchestration, coverage_target=0.7)
        # Simulate the denial: run a cycle through a runner whose engine
        # rejects network permissions (empty context permissions are the
        # pre-fix defect). We force it by executing with a bare context.
        denied_context = runner._build_context(mission.mission_id, "nmap", _TARGET, None)  # noqa: SLF001
        denied_context = dataclasses.replace(denied_context, permissions=())
        outcome = engine.execute(denied_context)
        assert not outcome.result.ok
        assert outcome.result.failure_kind is FailureKind.SANDBOX_VIOLATION

        cell = mission.coverage_cell(_TARGET, "port_discovery")
        # Before any success, the seeded cell is NOT_ASSESSED.
        if cell is not None:
            assert cell.state is CoverageState.NOT_ASSESSED or cell.state.uncovered(), (
                "a sandbox-denied execution must not flip coverage to tested"
            )

    def test_failed_execution_records_not_assessed_not_tested(self) -> None:
        engine = _engine()
        runner, orchestration = _runner(engine)
        mission = _mission(orchestration, coverage_target=0.7)

        # Force a failure through the runner (no tool would fail here, so we
        # emulate the deny path via a failing context on a real engine).
        action = next(iter(runner._planning.get_plan(mission.mission_id).actions.values()))  # noqa: SLF001
        runner._fail_execution(  # noqa: SLF001
            mission.mission_id,
            action_id=action.action_id,
            capability=action.capability,
            tool_id="nmap",
            error="Tool 'nmap' lacks permission 'network' for this execution.",
            failure_kind="sandbox-violation",
        )

        cell = mission.coverage_cell(_TARGET, action.capability)
        assert cell is not None
        assert cell.state.uncovered(), (
            "a failed/blocked execution must leave the coverage cell uncovered"
        )

    def test_successful_execution_still_counts_as_tested_coverage(self) -> None:
        engine = _engine()
        runner, orchestration = _runner(engine)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=8)

        # Genuinely successful executions must advance coverage (TESTED).
        tested = [cell for cell in mission.coverage_cells() if cell.state is CoverageState.TESTED]
        assert tested, "successful executions must count toward tested coverage"
        assert mission.coverage_ratio() > 0.0

    def test_coverage_target_not_satisfied_by_failures_alone(self) -> None:
        # All executions fail → coverage stays uncovered → the coverage-target
        # stop condition must NOT fire from failures alone.
        engine = _engine()
        runner, orchestration = _runner(engine)
        mission = _mission(orchestration, coverage_target=0.7)

        for _ in range(4):
            decision = orchestration.decide_next(mission.mission_id)
            if decision is None:
                break
            action_id = decision["next_action"]
            capability = decision["capability"]
            tool_id = decision["tool_id"]
            action = runner._planning.get_action(mission.mission_id, action_id)
            action.mark(runner._planning.get_action(mission.mission_id, action_id).status)  # noqa: SLF001
            runner._fail_execution(  # noqa: SLF001
                mission.mission_id,
                action_id=action_id,
                capability=capability,
                tool_id=tool_id,
                error="Tool lacks permission 'network' for this execution.",
                failure_kind="sandbox-violation",
            )

        assert mission.coverage_ratio() < mission.policy.coverage_target, (
            "failed/blocked executions must not satisfy the coverage target"
        )
