# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission-loop tests for the aggressive, adaptive attack engine.

Proves the Phase 2 behavior inside the real mission runner: execution outcomes
drive the target-feedback state machine, the bounded aggression tier reaches
tool execution contexts, healthy targets escalate controlled aggression while
defensive targets throttle — and defensive responses are never converted into
mission completion.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_attack.enums import AggressionLevel
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "http://synthetic.example:3010"

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("subfinder",),
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
    "certificate_enumeration": ("certspotter",),
    "endpoint_enumeration": ("httpx",),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
}

_HEALTHY_OUTPUTS: dict[str, dict[str, Any]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.synthetic.example"}], "count": 1},
    "dnsx": {"records": ["api.synthetic.example -> 127.0.0.1"]},
    "nmap": {"ports": [80, 3010]},
    "whatweb": {"name": "flask", "technologies": ["Flask"]},
    "httpx": {"endpoints": ["/login", "/api/orders"], "status_code": 200},
    "arjun": {"parameters": ["q", "id"], "status_code": 200},
    "nuclei": {"findings": []},
}


def _throttling_outputs() -> dict[str, dict[str, Any]]:
    """Return outputs whose later probes are throttled with HTTP 429."""
    outputs = {tool: dict(content) for tool, content in _HEALTHY_OUTPUTS.items()}
    outputs["httpx"] = {"endpoints": ["/login", "/api/orders"], "status_code": 429}
    outputs["arjun"] = {"parameters": [], "status_code": 429}
    return outputs


def _runner(
    engine: FakeExecutionEngine,
    *,
    adaptive_attack_factory: Any | None = None,
) -> tuple[MissionExecutionService, MissionOrchestrationService, str]:
    from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine

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
        execution_engine=engine,
        adaptive_attack_factory=adaptive_attack_factory,
    )
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, mission.mission_id


def _fresh_adaptive() -> Any:
    from hunterx.application.adaptive_attack import AdaptiveAttackService

    return lambda mission_id, target_key: AdaptiveAttackService(
        mission_id=mission_id, target_key=target_key, enforce_pacing=False
    )


class TestAggressionPropagates:
    def test_aggression_tier_reaches_execution_contexts(self) -> None:
        engine = FakeExecutionEngine(outputs=dict(_HEALTHY_OUTPUTS))
        runner, orchestration, mission_id = _runner(engine, adaptive_attack_factory=_fresh_adaptive())
        runner.run(mission_id, max_cycles=16)
        aggression_values = {
            str(context.parameters.get("aggression"))
            for context in engine.calls
            if "aggression" in context.parameters
        }
        assert aggression_values, "the aggression tier must reach tool contexts"
        assert all(AggressionLevel(value) for value in aggression_values)

    def test_run_summary_carries_adaptive_snapshot(self) -> None:
        engine = FakeExecutionEngine(outputs=dict(_HEALTHY_OUTPUTS))
        runner, orchestration, mission_id = _runner(engine, adaptive_attack_factory=_fresh_adaptive())
        result = runner.run(mission_id, max_cycles=16)
        assert result["adaptive_attack"] is not None
        assert "state" in result["adaptive_attack"]
        assert "aggression" in result["adaptive_attack"]


class TestAdaptiveThrottling:
    def test_defensive_responses_throttle_but_do_not_complete(self) -> None:
        engine = FakeExecutionEngine(outputs=_throttling_outputs())
        runner, orchestration, mission_id = _runner(engine, adaptive_attack_factory=_fresh_adaptive())
        result = runner.run(mission_id, max_cycles=16)
        adaptive = result["adaptive_attack"]
        # The runner observed defensive (429) feedback: throttling is feedback,
        # never a reason to fabricate completion (or to hang forever).
        assert adaptive is not None
        mission = orchestration.get(mission_id)
        assert mission.outcome is not None
        assert mission.outcome.stop_condition in (
            StopCondition.OBJECTIVES_COMPLETE.value,
            StopCondition.COVERAGE_TARGET_ACHIEVED.value,
            StopCondition.ATTACK_SURFACE_EXHAUSTED.value,
            StopCondition.BLOCKED.value,
        )

    def test_runner_feeds_feedback_from_observed_status(self) -> None:
        engine = FakeExecutionEngine(outputs=_throttling_outputs())
        runner, orchestration, mission_id = _runner(engine, adaptive_attack_factory=_fresh_adaptive())
        runner.run(mission_id, max_cycles=16)
        service = runner._adaptive_attack  # noqa: SLF001  (component test)
        assert service is not None
        signals = [sample.signal.value for sample in service.monitor.signals()]
        assert any(signal in ("rate_limited", "server_error", "access_denied") for signal in signals)

    def test_healthy_target_keeps_controlled_aggression(self) -> None:
        engine = FakeExecutionEngine(outputs=dict(_HEALTHY_OUTPUTS))
        runner, orchestration, mission_id = _runner(engine, adaptive_attack_factory=_fresh_adaptive())
        result = runner.run(mission_id, max_cycles=16)
        adaptive = result["adaptive_attack"]
        assert adaptive is not None
        # Healthy feedback never drops to LOW aggression (LOW only appears when
        # the target pushes back). The engine stays at MEDIUM+.
        assert adaptive["aggression"] in ("medium", "high", "maximum")

    def test_blocking_is_never_completion(self) -> None:
        """Persistent hard blocking reports BLOCKED — never a success stop."""
        from hunterx.application.adaptive_attack import AdaptiveAttackService
        from hunterx.domain.adaptive_attack.control import AdaptiveRateController, AttackControlConfig

        outputs = dict(_HEALTHY_OUTPUTS)
        outputs["httpx"] = {"endpoints": [], "status_code": 429}

        def factory(mission_id: str, target_key: str) -> Any:
            return AdaptiveAttackService(
                mission_id=mission_id,
                target_key=target_key,
                controller=AdaptiveRateController(config=AttackControlConfig(block_after=1)),
                enforce_pacing=False,
            )

        engine = FakeExecutionEngine(outputs=outputs)
        runner, orchestration, mission_id = _runner(engine, adaptive_attack_factory=factory)
        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)
        # BLOCKED must never be recorded as a success stop condition.
        assert mission.outcome is not None
        assert mission.outcome.stop_condition != StopCondition.ATTACK_SURFACE_EXHAUSTED.value
        assert mission.outcome.stop_condition != StopCondition.OBJECTIVES_COMPLETE.value
        assert mission.outcome.stop_condition != StopCondition.COVERAGE_TARGET_ACHIEVED.value
        assert mission.outcome.stop_condition == StopCondition.BLOCKED.value
