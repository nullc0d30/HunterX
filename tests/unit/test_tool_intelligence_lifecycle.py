# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the state machine, lifecycle manager, health and performance."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import ToolNotFoundError, ToolRegistrationError, ToolStateTransitionError
from hunterx.domain.tool_intelligence import ToolState
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.health import ToolHealthMonitor
from hunterx.tools.intelligence.lifecycle import ToolLifecycleManager
from hunterx.tools.intelligence.performance import ToolPerformanceAnalyzer
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.state import ToolStateMachine
from tests.framework.tip import make_knowledge, make_metadata


class TestStateMachine:
    def test_legal_transition(self) -> None:
        machine = ToolStateMachine()
        assert machine.can_transition(ToolState.REGISTERED, ToolState.INSTALLED)
        assert machine.can_transition(ToolState.AVAILABLE, ToolState.RUNNING)
        assert machine.can_transition(ToolState.RUNNING, ToolState.COMPLETED)
        assert machine.can_transition(ToolState.RUNNING, ToolState.FAILED)

    def test_illegal_transition_rejected(self) -> None:
        machine = ToolStateMachine()
        assert not machine.can_transition(ToolState.REGISTERED, ToolState.RUNNING)
        assert not machine.can_transition(ToolState.COMPLETED, ToolState.INSTALLED)
        with pytest.raises(ToolStateTransitionError):
            machine.transition(ToolState.REGISTERED, ToolState.RUNNING, tool_id="katana")

    def test_usable_and_terminal(self) -> None:
        machine = ToolStateMachine()
        assert machine.is_usable(ToolState.AVAILABLE)
        assert not machine.is_usable(ToolState.REGISTERED)
        assert machine.is_terminal(ToolState.FAILED)
        assert not machine.is_terminal(ToolState.AVAILABLE)

    def test_allowed_targets(self) -> None:
        machine = ToolStateMachine()
        targets = machine.allowed_targets(ToolState.REGISTERED)
        assert targets == ["deprecated", "disabled", "installed"]


class TestLifecycle:
    def _lifecycle(self) -> tuple[ToolLifecycleManager, ToolIntelligenceRegistry]:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("katana"))
        manager = ToolLifecycleManager(registry, ToolStateMachine(), ToolHealthMonitor(registry))
        return manager, registry

    def test_full_lifecycle(self) -> None:
        manager, registry = self._lifecycle()
        manager.install("katana", version="1.0.0")
        assert registry.get_state("katana").state == ToolState.INSTALLED
        assert registry.get_state("katana").installed_version == "1.0.0"

        manager.verify("katana")
        assert registry.get_state("katana").state == ToolState.VERIFIED
        assert registry.get_state("katana").last_verified_at

        manager.make_available("katana")
        assert registry.get_state("katana").state == ToolState.AVAILABLE
        assert manager.is_usable("katana")

        manager.start("katana")
        assert registry.get_state("katana").state == ToolState.RUNNING

        manager.complete("katana")
        assert registry.get_state("katana").state == ToolState.COMPLETED

    def test_fail_transitions_to_failed_and_degrades_health(self) -> None:
        manager, registry = self._lifecycle()
        manager.install("katana")
        manager.verify("katana")
        manager.make_available("katana")
        manager.start("katana")
        manager.fail("katana")

        state = registry.get_state("katana")
        assert state.state == ToolState.FAILED
        assert state.last_error == "execution failed"
        assert registry.get_health("katana").reliability_score < 1.0

    def test_verify_failure_keeps_state(self) -> None:
        manager, registry = self._lifecycle()
        manager.install("katana")
        state = manager.verify("katana", ok=False)
        assert state.state == ToolState.INSTALLED
        assert state.last_error == "verification failed"

    def test_disable_and_enable(self) -> None:
        manager, registry = self._lifecycle()
        manager.install("katana")
        manager.verify("katana")
        manager.make_available("katana")
        manager.disable("katana")
        assert registry.get_state("katana").state == ToolState.DISABLED
        assert not manager.is_usable("katana")
        manager.enable("katana")
        assert registry.get_state("katana").state == ToolState.AVAILABLE

    def test_deprecate(self) -> None:
        manager, registry = self._lifecycle()
        manager.install("katana")
        manager.deprecate("katana")
        assert registry.get_state("katana").state == ToolState.DEPRECATED

    def test_update_reverifies(self) -> None:
        manager, registry = self._lifecycle()
        manager.install("katana", version="1.0.0")
        manager.verify("katana")
        manager.make_available("katana")
        state = manager.update("katana", version="2.0.0")
        assert state.state == ToolState.INSTALLED
        assert state.installed_version == "2.0.0"
        assert not state.last_verified_at

    def test_update_non_usable_state_rejected(self) -> None:
        manager, _ = self._lifecycle()
        with pytest.raises(ToolRegistrationError):
            manager.update("katana", version="2.0.0")

    def test_unregister_removes_tool(self) -> None:
        manager, registry = self._lifecycle()
        manager.unregister("katana")
        assert registry.get_metadata("katana") is None
        with pytest.raises(ToolNotFoundError):
            manager.unregister("katana")

    def test_operations_on_unknown_tool_raise(self) -> None:
        manager, _ = self._lifecycle()
        with pytest.raises(ToolNotFoundError):
            manager.install("nope")
        with pytest.raises(ToolNotFoundError):
            manager.start("nope")
        assert manager.is_usable("nope") is False

    def test_illegal_transition_via_lifecycle_raises(self) -> None:
        manager, _ = self._lifecycle()
        with pytest.raises(ToolStateTransitionError):
            manager.start("katana")


class TestHealthMonitor:
    def test_success_and_failure_tracking(self) -> None:
        registry = ToolIntelligenceRegistry()
        health = ToolHealthMonitor(registry)
        health.record_success("katana", duration_ms=100)
        health.record_success("katana", duration_ms=300)
        stats = health.get("katana")
        assert stats.samples == 2
        assert stats.average_runtime_ms == pytest.approx(200.0)
        assert stats.reliability_score == pytest.approx(1.0)

    def test_failure_decays_reliability(self) -> None:
        registry = ToolIntelligenceRegistry()
        health = ToolHealthMonitor(registry)
        health.record_success("katana")
        stats = health.record_failure("katana", crash=True, timeout=True)
        assert stats.execution_failures == 1
        assert stats.timeouts == 1
        assert stats.crash_frequency > 0
        assert stats.reliability_score < 1.0

    def test_usage_and_availability(self) -> None:
        registry = ToolIntelligenceRegistry()
        health = ToolHealthMonitor(registry)
        health.record_usage("katana", memory_mb=512.0, cpu_pct=30.0)
        health.set_availability("katana", available=False)
        stats = health.get("katana")
        assert stats.memory_usage_mb == 512.0
        assert stats.cpu_usage_pct == 30.0
        assert stats.availability is False


class TestPerformanceAnalyzer:
    def test_rolling_metrics(self) -> None:
        registry = ToolIntelligenceRegistry()
        analyzer = ToolPerformanceAnalyzer(registry)
        analyzer.record_execution("katana", duration_ms=100, findings=5, succeeded=True)
        analyzer.record_execution("katana", duration_ms=300, findings=9, succeeded=True)
        stats = analyzer.get("katana")
        assert stats.samples == 2
        assert stats.average_duration_ms == pytest.approx(200.0)
        assert stats.average_findings == pytest.approx(7.0)
        assert stats.success_rate == pytest.approx(1.0)

    def test_failure_rate(self) -> None:
        registry = ToolIntelligenceRegistry()
        analyzer = ToolPerformanceAnalyzer(registry)
        analyzer.record_execution("katana", succeeded=True)
        analyzer.record_execution("katana", succeeded=False)
        stats = analyzer.get("katana")
        assert stats.failure_rate == pytest.approx(0.5)
        assert stats.success_rate == pytest.approx(0.5)

    def test_false_positives_and_reset(self) -> None:
        registry = ToolIntelligenceRegistry()
        analyzer = ToolPerformanceAnalyzer(registry)
        analyzer.record_execution("katana", findings=10)
        analyzer.record_false_positive("katana", count=2)
        stats = analyzer.get("katana")
        assert stats.false_positive_rate > 0
        analyzer.reset("katana")
        assert analyzer.get("katana").samples == 0


class TestLifecycleViaAPI:
    def test_facade_lifecycle(self) -> None:
        tip = ToolIntelligenceAPI()
        tip.register_tool(make_metadata("katana"), knowledge=make_knowledge("katana"))
        tip.install("katana", version="1.0.0")
        tip.verify("katana")
        tip.make_available("katana")
        assert tip.state_of("katana") == ToolState.AVAILABLE
        assert tip.is_usable("katana")
