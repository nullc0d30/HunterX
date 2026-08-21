# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-envelope integration tests.

Regression tests representing the real incident: a ``full_security_assessment``
must NEVER be allowed to consume the host until system memory reaches ~90%+.
HunterX must remain safe and usable on a 4 GB / 2 CPU environment: the mission
runs under a hard resource envelope derived from the environment, the process
tree is accounted, concurrency adapts, and a runaway is terminated gracefully —
never reported as success.

These tests drive the real mission runner (planning + orchestration + the
resource governor) with a deterministic fake execution engine and a fake
resource sampler so the envelope behaviour is verified without external tools.
"""

from __future__ import annotations

import dataclasses
import time

import pytest

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.attack_surface.queue import AssessmentQueue
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.resource import ResourceConfig, ResourceGovernor, ResourceState
from hunterx.resource.detect import EnvironmentInfo, EnvironmentKind
from hunterx.resource.sampler import ProcessSnapshot
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine
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
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.juice-shop.herokuapp.com"}], "count": 1},
    "dnsx": {"records": ["api.juice-shop.herokuapp.com -> 1.2.3.4"]},
    "nmap": {"ports": [80, 443]},
    "whatweb": {"name": "express", "technologies": ["node.js", "express"]},
    "httpx": {"endpoints": ["/rest/products/search", "/api/products"]},
    "arjun": {"parameters": ["q", "id"]},
    "nuclei": {"findings": [{"template": "missing-security-headers", "severity": "low"}]},
    "certspotter": {"certificates": ["juice-shop.herokuapp.com"]},
}

#: 4 GB / 2 CPU environment.
_FOUR_GB_TWO_CPU = EnvironmentInfo(
    kind=EnvironmentKind.BARE_METAL,
    total_memory_mb=4096.0,
    effective_memory_limit_mb=4096.0,
    memory_limit_source="meminfo",
    cpu_count=2,
    cpu_quota=0.0,
)


class GrowingSampler:
    """A sampler whose process-tree RSS climbs after ``threshold`` calls.

    Models the runaway behaviour observed in the real incident: the process
    tree grows until it would consume the host. The governor must detect the
    climb and terminate the mission safely well before the host reaches ~90%.
    """

    def __init__(self, *, low_mb: float, high_mb: float, threshold: int, host_total_mb: float = 4096.0) -> None:
        self._low = low_mb
        self._high = high_mb
        self._threshold = threshold
        self._host_total = host_total_mb
        self.calls = 0

    def snapshot(self) -> ProcessSnapshot:
        self.calls += 1
        rss = self._low if self.calls <= self._threshold else self._high
        return ProcessSnapshot(
            rss_bytes=int(rss * 1024 * 1024),
            rss_mb=rss,
            process_count=1,
            cpu_percent=40.0,
            cpu_cores=2,
            host_total_mb=self._host_total,
            host_available_mb=max(0.0, self._host_total - rss),
            host_used_mb=rss,
        )


def _runner(
    governor: ResourceGovernor,
    fake: FakeExecutionEngine,
) -> tuple[MissionExecutionService, MissionOrchestrationService]:
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
        resource_config=governor._config,
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=fake,
        governor=governor,
    )
    return runner, orchestration


def _mission(orchestration: MissionOrchestrationService):
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=(
            StopCondition.COVERAGE_TARGET_ACHIEVED,
            StopCondition.RESOURCE_BUDGET_EXHAUSTED,
            StopCondition.TIME_BUDGET_EXHAUSTED,
        ),
    )
    orchestration.start(mission.mission_id)
    return mission


class TestResourceEnvelope4Gb2Cpu:
    """A full_security_assessment on a 4 GB / 2 CPU environment stays safe."""

    def test_mission_runs_normally_within_budget(self) -> None:
        sampler = GrowingSampler(low_mb=300.0, high_mb=300.0, threshold=1000)
        governor = ResourceGovernor(ResourceConfig(), environment=_FOUR_GB_TWO_CPU, sampler=sampler)
        runner, orchestration = _runner(governor, FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=16)

        # Under a healthy envelope the mission completes honestly; the governor
        # never interferes with NORMAL execution.
        assert result["status"] in ("completed", "blocked", "degraded")
        assert result["resource"]["state"] in ("normal", "constrained")
        assert result["resource"]["budget_mb"] == pytest.approx(2048.0)
        assert result["resource"]["ceiling_mb"] == pytest.approx(4096.0 * 0.55)
        assert governor.active_process_count() == 0

    def test_runaway_memory_terminates_mission_not_success(self) -> None:
        # The process tree grows past the 4 GB host headroom ceiling (2253 MB).
        sampler = GrowingSampler(low_mb=300.0, high_mb=2400.0, threshold=2)
        governor = ResourceGovernor(ResourceConfig(), environment=_FOUR_GB_TWO_CPU, sampler=sampler)
        runner, orchestration = _runner(governor, FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=16)

        # A resource-triggered stop is NEVER reported as success: it degrades
        # with a structured reason, state is persisted, and the host was never
        # driven to ~90%+ memory.
        assert result["status"] == "degraded"
        assert result["resource"]["state"] == "emergency"
        assert mission.outcome is not None
        assert mission.outcome.stop_condition == StopCondition.MEMORY_BUDGET_EXHAUSTED.value
        assert not mission.outcome.objectives_complete
        # The host never reached ~90% memory: 2400 MB / 4096 MB == 58.6%.
        host_pressure = result["resource"]["system_memory_pressure"]
        assert host_pressure < 0.90

    def test_mission_deadline_degrades_with_structured_reason(self) -> None:
        sampler = GrowingSampler(low_mb=300.0, high_mb=300.0, threshold=1000)
        governor = ResourceGovernor(ResourceConfig(), environment=_FOUR_GB_TWO_CPU, sampler=sampler)
        runner, orchestration = _runner(governor, FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)

        governor.start_mission(mission.mission_id, deadline_s=0.001)
        result = runner.run(mission.mission_id, max_cycles=16)

        assert result["status"] == "degraded"
        assert mission.outcome is not None
        assert mission.outcome.stop_condition == StopCondition.MISSION_DEADLINE_EXCEEDED.value

    def test_concurrency_adapts_under_pressure(self) -> None:
        sampler = GrowingSampler(low_mb=100.0, high_mb=1900.0, threshold=1)
        governor = ResourceGovernor(
            ResourceConfig(memory_soft_ratio=0.6, memory_high_ratio=0.8, memory_hard_ratio=0.92),
            environment=_FOUR_GB_TWO_CPU,
            sampler=sampler,
        )
        assert governor.suggested_concurrency(8) == 8  # normal first
        assert governor.evaluate() in (
            ResourceState.CONSTRAINED,
            ResourceState.DEGRADED,
            ResourceState.CRITICAL,
            ResourceState.EMERGENCY,
        )
        assert governor.suggested_concurrency(8) < 8


class TestToolExecutionAdmission:
    def test_engine_denies_execution_under_emergency(self) -> None:
        class HighSampler:
            def snapshot(self) -> ProcessSnapshot:
                return ProcessSnapshot(rss_bytes=int(3200 * 1024 * 1024), rss_mb=3200.0, process_count=1, cpu_percent=0.0, cpu_cores=2, host_total_mb=4096, host_available_mb=896, host_used_mb=3200)

        governor = ResourceGovernor(ResourceConfig(), environment=_FOUR_GB_TWO_CPU, sampler=HighSampler())
        engine = ExecutionEngine()
        engine.set_resource_governor(governor)
        context = ExecutionContextBuilder(tool_id="nmap", target="127.0.0.1").build()

        result = engine.execute(context)

        assert result.result.failure_kind.value == "resource-exhausted"
        assert "governor" in result.result.error

    def test_tool_timeout_is_always_bounded(self) -> None:
        from hunterx.domain.exceptions import ToolTimeoutError
        from hunterx.tools.recon.runner import BinaryRunner, set_resource_hook

        set_resource_hook(default_timeout_s=lambda: 0.3)
        try:
            runner = BinaryRunner()
            with pytest.raises(ToolTimeoutError):
                runner.run([__import__("sys").executable, "-c", "import time; time.sleep(5)"], tool_id="sleep")
        finally:
            set_resource_hook(default_timeout_s=lambda: 0.0)


class TestProcessTreeCleanup:
    def test_spawned_processes_are_registered_and_unregistered(self) -> None:
        import sys as _sys

        from hunterx.tools.recon.runner import BinaryRunner, set_resource_hook

        governor = ResourceGovernor(ResourceConfig(), environment=_FOUR_GB_TWO_CPU)
        set_resource_hook(
            register_process=governor.register_process,
            unregister_process=governor.unregister_process,
            default_timeout_s=lambda: 10.0,
        )
        try:
            runner = BinaryRunner()
            result = runner.run([_sys.executable, "-c", "print('ok')"], tool_id="echo")
            assert result.returncode == 0
            # The process was unregistered after completion: no orphaned handles.
            assert governor.active_process_count() == 0
        finally:
            set_resource_hook(default_timeout_s=lambda: 0.0)

    def test_emergency_termination_reaps_registered_processes(self) -> None:
        import sys as _sys
        import threading

        from hunterx.tools.recon.runner import BinaryRunner, set_resource_hook

        governor = ResourceGovernor(ResourceConfig(), environment=_FOUR_GB_TWO_CPU)
        set_resource_hook(
            register_process=governor.register_process,
            unregister_process=governor.unregister_process,
            default_timeout_s=lambda: 30.0,
        )
        try:
            runner = BinaryRunner()
            # Spawn a long-lived child; the emergency stop must kill it.
            spawned: list[object] = []
            thread = threading.Thread(
                target=lambda: spawned.append(
                    runner.run([_sys.executable, "-c", "import time; time.sleep(60)"], tool_id="sleeper")
                ),
                daemon=True,
            )
            thread.start()
            deadline = time.monotonic() + 10
            while governor.active_process_count() == 0 and time.monotonic() < deadline:
                time.sleep(0.05)
            assert governor.active_process_count() == 1
            terminated = governor.terminate_process_tree(grace_s=0.5)
            assert terminated >= 1
            assert governor.active_process_count() == 0
            thread.join(timeout=5)
        finally:
            set_resource_hook(default_timeout_s=lambda: 0.0)


class TestQueueBackpressure:
    def test_assessment_queue_is_bounded(self) -> None:
        queue = AssessmentQueue(max_pending=2)
        queue.submit(surface_key="ep1", capability_id="xss")
        queue.submit(surface_key="ep2", capability_id="xss")
        third = queue.submit(surface_key="ep3", capability_id="xss")
        assert queue.remaining() == 2
        assert third.status.value == "skipped"  # hard backpressure, never silent

    def test_replan_budget_bounds_autonomous_loop(self) -> None:
        from hunterx.resource.governor import ResourceGovernor

        governor = ResourceGovernor(ResourceConfig(max_replan_cycles=2), environment=_FOUR_GB_TWO_CPU)
        runner, orchestration = _runner(governor, FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)))
        mission = _mission(orchestration)
        governor.start_mission(mission.mission_id)
        assert runner._replan_allowed(mission.mission_id)
        assert runner._consume_replan(mission.mission_id)
        assert runner._consume_replan(mission.mission_id)
        assert not runner._replan_allowed(mission.mission_id)
        assert not runner._consume_replan(mission.mission_id)


__all__ = []
