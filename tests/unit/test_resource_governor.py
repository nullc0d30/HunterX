# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-governance tests: the centralized Mission Resource Governor.

Covers budget derivation per environment (4 GB / 8 GB / 16+ GB), the absolute
3 GB ceiling, process-tree accounting, state transitions (NORMAL →
CONSTRAINED → DEGRADED → CRITICAL → EMERGENCY), adaptive concurrency, tool /
probe / model admission control, replan budget, mission deadlines, emergency
process-tree termination and honest resource telemetry.
"""

from __future__ import annotations

import pytest

from hunterx.resource.config import ResourceConfig
from hunterx.resource.detect import EnvironmentInfo, EnvironmentKind
from hunterx.resource.governor import ResourceGovernor
from hunterx.resource.sampler import ProcessSnapshot
from hunterx.resource.state import ResourceState


def _env(total_mb: float, limit_mb: float | None = None, cpus: int = 2, quota: float = 0.0) -> EnvironmentInfo:
    return EnvironmentInfo(
        kind=EnvironmentKind.BARE_METAL,
        total_memory_mb=total_mb,
        effective_memory_limit_mb=limit_mb if limit_mb is not None else total_mb,
        memory_limit_source="meminfo",
        cpu_count=cpus,
        cpu_quota=quota,
    )


class FakeSampler:
    """Deterministic sampler returning a configurable process-tree RSS."""

    def __init__(self, rss_mb: float, host_total_mb: float = 0.0, host_used_mb: float = 0.0, cpu: float = 0.0, count: int = 1) -> None:
        self._rss_mb = rss_mb
        self._host_total = host_total_mb
        self._host_used = host_used_mb
        self._cpu = cpu
        self._count = count

    def snapshot(self) -> ProcessSnapshot:
        return ProcessSnapshot(
            rss_bytes=int(self._rss_mb * 1024 * 1024),
            rss_mb=self._rss_mb,
            process_count=self._count,
            cpu_percent=self._cpu,
            cpu_cores=2,
            host_total_mb=self._host_total,
            host_available_mb=max(0.0, self._host_total - self._host_used),
            host_used_mb=self._host_used,
        )


class TestBudgetDerivation:
    def test_4gb_environment_yields_about_2gb_budget(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(4096))
        # 4096 * 0.5 = 2048, below the absolute 3072 ceiling.
        assert gov.mission_budget_mb() == pytest.approx(2048.0)

    def test_8gb_environment_reaches_ceiling(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(8192))
        # 8192 * 0.5 = 4096 -> capped at the absolute 3072 ceiling.
        assert gov.mission_budget_mb() == pytest.approx(3072.0)

    def test_16gb_environment_still_capped_at_3gb(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(16384))
        assert gov.mission_budget_mb() == pytest.approx(3072.0)
        assert gov.memory_ceiling_mb() <= 3072.0

    def test_small_host_ceiling_preserves_headroom(self) -> None:
        # 4 GiB host: ceiling must not exceed 55% of host RAM (2.2 GiB) so the
        # host keeps usable headroom even though the absolute ceiling is 3 GiB.
        gov = ResourceGovernor(ResourceConfig(), environment=_env(4096))
        assert gov.memory_ceiling_mb() == pytest.approx(4096 * 0.55)

    def test_absolute_3gb_ceiling_is_never_exceeded(self) -> None:
        # A 64 GiB host must still respect the absolute 3 GiB ceiling.
        gov = ResourceGovernor(ResourceConfig(), environment=_env(65536))
        assert gov.mission_budget_mb() <= 3072.0
        assert gov.memory_ceiling_mb() <= 3072.0

    def test_cgroup_limit_is_the_effective_limit(self) -> None:
        # Container: host 16 GiB, cgroup limit 2 GiB -> effective 2 GiB.
        info = _env(16384, limit_mb=2048)
        gov = ResourceGovernor(ResourceConfig(), environment=info)
        assert gov.mission_budget_mb() == pytest.approx(1024.0)
        assert gov.environment().memory_limit_source == "meminfo"

    def test_explicit_config_lifts_ceiling(self) -> None:
        # An operator may explicitly raise the ceiling through configuration.
        config = ResourceConfig(memory_ceiling_mb=4096)
        gov = ResourceGovernor(config, environment=_env(32768))
        assert gov.memory_ceiling_mb() == pytest.approx(4096.0)


class TestStateTransitions:
    def test_normal_under_soft_ratio(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=500),
        )
        assert gov.evaluate() is ResourceState.NORMAL

    def test_constrained_between_soft_and_high(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_soft_ratio=0.6, memory_high_ratio=0.8),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.7),  # 70% of the 3 GiB budget
        )
        assert gov.evaluate() is ResourceState.CONSTRAINED

    def test_degraded_between_high_and_hard(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_soft_ratio=0.6, memory_high_ratio=0.8, memory_hard_ratio=0.92),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.85),
        )
        assert gov.evaluate() is ResourceState.DEGRADED

    def test_critical_at_hard_ratio(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_hard_ratio=0.92),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.95),
        )
        assert gov.evaluate() is ResourceState.CRITICAL

    def test_emergency_at_absolute_ceiling(self) -> None:
        # Reaching the absolute ceiling is EMERGENCY regardless of the ratio.
        gov = ResourceGovernor(
            ResourceConfig(),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 + 1),
        )
        assert gov.evaluate() is ResourceState.EMERGENCY

    def test_emergency_on_host_memory_pressure(self) -> None:
        # The host at ~96% memory is an emergency even if the process tree is small.
        gov = ResourceGovernor(
            ResourceConfig(),
            environment=_env(4096),
            sampler=FakeSampler(rss_mb=200, host_total_mb=4096, host_used_mb=3932),
        )
        assert gov.evaluate() is ResourceState.EMERGENCY

    def test_transitions_are_logged_without_flooding(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        gov = ResourceGovernor(
            ResourceConfig(telemetry_interval_s=5.0),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=100),
        )
        with caplog.at_level(logging.INFO, logger="hunterx.resource"):
            gov.evaluate()
        assert any("[RESOURCE]" in record.message for record in caplog.records)


class TestAdaptiveConcurrency:
    def test_normal_keeps_base(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=100),
        )
        assert gov.suggested_concurrency(8) == 8

    def test_constrained_reduces_concurrency(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_soft_ratio=0.6, memory_high_ratio=0.8),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.7),
        )
        reduced = gov.suggested_concurrency(8)
        assert 1 <= reduced < 8

    def test_critical_is_single_worker(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_hard_ratio=0.92),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.95),
        )
        assert gov.suggested_concurrency(8) == 1

    def test_emergency_stops_new_work(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3200),
        )
        assert gov.suggested_concurrency(8) == 0


class TestAdmissionControl:
    def test_tool_admitted_in_normal(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        assert gov.admit_tool(tool_id="nmap", memory_class="high").approved

    def test_high_memory_tool_denied_in_critical(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_hard_ratio=0.92),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.95),
        )
        admission = gov.admit_tool(tool_id="amass", memory_class="high")
        assert not admission.approved
        assert "critical" in admission.reason

    def test_heavy_tool_denied_in_emergency(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(8192), sampler=FakeSampler(rss_mb=3200))
        assert not gov.admit_tool(tool_id="nmap", memory_class="low").approved

    def test_tool_concurrency_cap(self) -> None:
        gov = ResourceGovernor(ResourceConfig(max_tool_concurrency=1), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        first = gov.admit_tool(tool_id="a")
        second = gov.admit_tool(tool_id="b")
        assert first.approved
        assert not second.approved
        assert "concurrency" in second.reason
        gov.release_tool(first)
        assert gov.admit_tool(tool_id="b").approved

    def test_model_call_denied_in_critical(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_hard_ratio=0.92),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.95),
        )
        assert not gov.admit_model_call().approved

    def test_model_concurrency_cap(self) -> None:
        gov = ResourceGovernor(ResourceConfig(max_model_concurrency=1), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        first = gov.admit_model_call()
        assert first.approved
        assert not gov.admit_model_call().approved
        gov.release_model_call(first)
        assert gov.admit_model_call().approved

    def test_probe_admission_and_release(self) -> None:
        gov = ResourceGovernor(ResourceConfig(max_probe_concurrency=1), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        first = gov.admit_probe()
        assert first.approved
        assert not gov.admit_probe().approved
        gov.release_probe(first)
        assert gov.admit_probe().approved

    def test_assessment_scheduling_backpressure(self) -> None:
        gov = ResourceGovernor(ResourceConfig(max_queue_depth=3), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        assert gov.admit_assessment(pending=2).approved
        assert not gov.admit_assessment(pending=3).approved

    def test_assessment_scheduling_denied_in_critical(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(memory_hard_ratio=0.92),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=3072 * 0.95),
        )
        assert not gov.admit_assessment(pending=0).approved


class TestMissionDeadline:
    def test_mission_deadline_is_enforced(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        gov.start_mission("m1", deadline_s=0.05)
        assert not gov.mission_deadline_exceeded("m1")
        import time

        time.sleep(0.1)
        assert gov.mission_deadline_exceeded("m1")

    def test_unlimited_deadline_never_expires(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        gov.start_mission("m1", deadline_s=0)
        assert not gov.mission_deadline_exceeded("m1")

    def test_replan_budget_is_bounded(self) -> None:
        gov = ResourceGovernor(ResourceConfig(max_replan_cycles=3), environment=_env(8192), sampler=FakeSampler(rss_mb=100))
        gov.start_mission("m1")
        for _ in range(3):
            assert gov.replan_budget("m1") > 0
            assert gov.consume_replan("m1")
        assert gov.replan_budget("m1") == 0
        assert not gov.consume_replan("m1")


class TestProcessTreeTermination:
    def test_emergency_terminates_registered_processes(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(8192), sampler=FakeSampler(rss_mb=100))

        class FakeProcess:
            def __init__(self, pid: int) -> None:
                self.pid = pid
                self._alive = True

            def poll(self) -> int | None:
                return None if self._alive else 0

            def kill(self) -> None:
                self._alive = False

        p1 = FakeProcess(9999)
        p2 = FakeProcess(10000)
        gov.register_process(p1)
        gov.register_process(p2)
        assert gov.active_process_count() == 2
        gov.unregister_process(p1)
        assert gov.active_process_count() == 1
        assert gov.terminate_process_tree(grace_s=0.01) >= 1
        assert gov.active_process_count() == 0

    def test_no_orphan_registration_after_termination(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(8192), sampler=FakeSampler(rss_mb=3200))
        assert gov.terminate_process_tree() >= 0
        assert gov.active_process_count() == 0


class TestTelemetry:
    def test_metrics_report_is_json_safe(self) -> None:
        gov = ResourceGovernor(
            ResourceConfig(),
            environment=_env(8192),
            sampler=FakeSampler(rss_mb=500, count=3),
        )
        report = gov.report()
        assert report["state"] == "normal"
        assert report["budget_mb"] == 3072.0
        assert report["ceiling_mb"] == 3072.0
        assert report["process_count"] == 3
        assert report["rss_mb"] == 500.0

    def test_limits_report_documents_every_bound(self) -> None:
        gov = ResourceGovernor(ResourceConfig(), environment=_env(4096))
        limits = gov.describe_limits()
        assert limits["mission_budget_mb"] == pytest.approx(2048.0)
        assert limits["absolute_ceiling_mb"] == pytest.approx(4096 * 0.55)
        assert limits["tool_timeout_s"] == 600.0
        assert limits["max_tool_concurrency"] == 2


__all__ = []
