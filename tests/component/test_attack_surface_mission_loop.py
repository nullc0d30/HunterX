# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission-loop tests for the target-agnostic attack-surface orchestration.

Proves the Phase 1 loop end to end against a synthetic target: discovery feeds
the surface model, the model maps ``Capability × Surface × Context`` and
schedules the assessment queue, attack observations expand the surface
(Discover → Model → Expand → Map → Attack → Learn → Rediscover), and — once the
assessment queue and verification are genuinely exhausted and discovery goes
stale — the mission terminates with ``ATTACK_SURFACE_EXHAUSTED`` instead of a
cycle/probe/finding count.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.attack_surface.enums import (
    AssessmentStatus,
    CompletionVerdict,
    VerificationState,
)
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "http://synthetic.example:3010"

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("subfinder", "amass"),
    "subdomain_enumeration": ("subfinder", "amass"),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap", "httpx"),
    "technology_fingerprint": ("whatweb",),
    "certificate_enumeration": ("certspotter",),
    "endpoint_enumeration": ("httpx", "katana"),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
}

_OUTPUTS: dict[str, dict[str, Any]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.synthetic.example"}], "count": 1},
    "dnsx": {"records": ["api.synthetic.example -> 127.0.0.1"]},
    "nmap": {"ports": [80, 3010]},
    "whatweb": {"name": "flask", "technologies": ["Flask", "PostgreSQL"]},
    "httpx": {"endpoints": ["/login", "/api/orders", "/api/users"]},
    "arjun": {"parameters": ["q", "id", "url"]},
    "nuclei": {
        "findings": [
            {
                "template_id": "xss-detection",
                "template_name": "Cross-Site Scripting",
                "severity": "medium",
                "matched_at": "http://synthetic.example:3010/",
            }
        ]
    },
}


class _DrainingRunner(MissionExecutionService):
    """Runner that discharges every queued assessment after each observation.

    White-box double: proves that when the assessment queue is genuinely
    drained and discovery goes stale, the exhaustion gate terminates the loop
    with ``ATTACK_SURFACE_EXHAUSTED`` — rather than any cycle/probe count.
    """

    def _surface_feedback(self, mission_id: str, raw: dict[str, Any], capability: str, target: str) -> None:
        super()._surface_feedback(mission_id, raw, capability, target)
        surface = self._attack_surface
        if surface is None:
            return
        for assignment in surface.graph.assignments():
            assignment.mark(AssessmentStatus.COMPLETED)
            assignment.settle(VerificationState.VERIFIED)
        for task in surface.queue.tasks():
            surface.queue.mark(task.task_id, AssessmentStatus.COMPLETED)
            surface.queue.settle(task.task_id, VerificationState.VERIFIED)
        for _ in range(4):
            surface.gate.record_observation(
                surfaces_before=surface.graph.node_count(),
                surfaces_after=surface.graph.node_count(),
            )


def _runner(engine: FakeExecutionEngine) -> tuple[MissionExecutionService, MissionOrchestrationService, str]:
    """Assemble a real execution runner over real planning/orchestration."""
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = _DrainingRunner(
        orchestration=orchestration,
        planning=planning,
        execution_engine=engine,
        attack_surface=AttackSurfaceService(target_key=_TARGET),
    )
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, mission.mission_id


class TestDiscoverModelExpandMap:
    def test_observations_model_and_expand_the_surface(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_OUTPUTS)))
        runner.run(mission_id, max_cycles=24, max_idle_cycles=6)
        surface = runner._attack_surface  # noqa: SLF001  (component test)
        assert surface is not None
        snapshot = surface.snapshot()
        # Discover + model + expand: endpoints and inputs are represented.
        assert snapshot["surfaces"] >= 5
        assert snapshot["inputs"] >= 3
        kinds = set(snapshot["kinds"])
        assert "endpoint" in kinds
        assert "parameter" in kinds

    def test_capability_mapping_schedules_assessment_queue(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_OUTPUTS)))
        runner.run(mission_id, max_cycles=24, max_idle_cycles=6)
        surface = runner._attack_surface  # noqa: SLF001
        assert surface is not None
        assert surface.queue.total() > 0
        capabilities = {assignment.capability_id for assignment in surface.graph.assignments()}
        assert {"sql-injection", "xss", "parameter_discovery"}.issubset(capabilities)

    def test_rediscovery_expands_from_attack_observations(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_OUTPUTS)))
        runner.run(mission_id, max_cycles=24, max_idle_cycles=6)
        surface = runner._attack_surface  # noqa: SLF001
        assert surface is not None
        # The httpx endpoint observation and the arjun parameter observation
        # both expanded the surface: at least the /api/orders endpoint and its
        # id/url parameters were represented.
        names = {node.name for node in surface.graph.nodes()}
        assert any("api/orders" in name for name in names)
        assert "id" in names or "url" in names

    def test_run_summary_carries_surface_report(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_OUTPUTS)))
        result = runner.run(mission_id, max_cycles=24, max_idle_cycles=6)
        assert result["surface"] is not None
        assert "verdict" in result["surface"]
        assert "criteria" in result["surface"]


class TestExhaustionGateCompletes:
    def test_exhausted_surface_terminates_with_attack_surface_exhausted(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_OUTPUTS)))
        result = runner.run(mission_id, max_cycles=24, max_idle_cycles=6)
        mission = orchestration.get(mission_id)
        assert mission.outcome is not None
        assert mission.outcome.stop_condition == StopCondition.ATTACK_SURFACE_EXHAUSTED.value
        assert mission.outcome.objectives_complete
        assert result["surface"]["verdict"] == CompletionVerdict.EXHAUSTED.value
        assert all(result["surface"]["criteria"].values())

    def test_no_cycle_or_probe_count_drives_completion(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_OUTPUTS)))
        result = runner.run(mission_id, max_cycles=24, max_idle_cycles=6)
        mission = orchestration.get(mission_id)
        # Completion is not keyed to the number of cycles run.
        assert mission.outcome is not None
        assert mission.outcome.stop_condition == StopCondition.ATTACK_SURFACE_EXHAUSTED.value
        assert result["cycles_run"] > 0


class TestNoRegression:
    def test_runner_still_terminates_without_exhaustion(self) -> None:
        """Without draining, the gate must not falsely claim exhaustion."""
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES),
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
        )
        mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
        mission.policy = dataclasses.replace(
            mission.policy,
            coverage_target=0.99,
            stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
        )
        orchestration.start(mission.mission_id)
        result = runner.run(mission.mission_id, max_cycles=16)
        # The surface report is informational; it must not claim exhaustion
        # while queued assessments remain undischarged.
        assert result["surface"] is not None
        assert result["surface"]["verdict"] != CompletionVerdict.EXHAUSTED.value
        assert mission.outcome is not None
        assert mission.outcome.stop_condition != StopCondition.ATTACK_SURFACE_EXHAUSTED.value
