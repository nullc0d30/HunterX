# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for execution SDK services: installer, version, health, capabilities,
plugin, monitor, session, events, scheduler, parallel and adapter factory."""

from __future__ import annotations

import sys

from hunterx.domain.execution import ExecutionResult, ExecutionStatus, RetryPolicy
from hunterx.tools.sdk.adapter import AdapterFactory, LegacyToolBridge
from hunterx.tools.sdk.capabilities import ExecutionCapabilityRegistry
from hunterx.tools.sdk.events import ExecutionEventBus
from hunterx.tools.sdk.health import HealthChecker
from hunterx.tools.sdk.installer import InstallationManager
from hunterx.tools.sdk.monitor import ExecutionMonitor
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.sdk.parallel import ParallelExecutionManager
from hunterx.tools.sdk.plugin import ExecutionPluginManager
from hunterx.tools.sdk.queue import ToolQueue
from hunterx.tools.sdk.resources import ResourceManager
from hunterx.tools.sdk.scheduler import TaskScheduler
from hunterx.tools.sdk.session import ExecutionSession
from hunterx.tools.sdk.version import VersionManager
from tests.framework.execution import FakeAdapter, make_context
from tests.framework.fakes import StaticScanner


class TestInstallationManager:
    def test_install_success_and_tracking(self) -> None:
        installer = InstallationManager()
        installer.register("nmap", lambda tool_id, version: "7.94")
        record = installer.install("nmap", version="7.94")
        assert record.version == "7.94"
        assert record.error is None
        assert installer.is_installed("nmap")
        assert installer.installed_tools() == ["nmap"]

    def test_uninstall(self) -> None:
        installer = InstallationManager()
        installer.register("nmap", lambda tool_id, version: "7.94")
        installer.install("nmap")
        installer.uninstall("nmap")
        assert not installer.is_installed("nmap")


class TestVersionManager:
    def test_record_and_installed(self) -> None:
        versions = VersionManager()
        versions.record("nmap", "7.94")
        assert versions.installed("nmap") == "7.94"
        assert versions.is_known("nmap")
        assert not versions.is_known("httpx")

    def test_satisfies_constraint(self) -> None:
        versions = VersionManager()
        versions.record("nmap", "7.94")
        assert versions.satisfies("nmap", ">=7.80")
        assert versions.satisfies("nmap", None)
        assert not versions.satisfies("nmap", ">=8.00")
        assert not versions.satisfies("httpx", ">=1.0")


class TestHealthChecker:
    def test_healthy_when_installed_and_probe_ok(self) -> None:
        installer = InstallationManager()
        versions = VersionManager()
        installer.register("nmap", lambda tool_id, version: "7.94")
        installer.install("nmap")
        versions.record("nmap", "7.94")
        checker = HealthChecker(installer, versions)
        checker.probe("nmap", lambda tool_id: True)
        result = checker.check("nmap", requirement=">=7.80")
        assert result.healthy
        assert checker.healthy_tools() == ["nmap"]

    def test_unhealthy_when_not_installed(self) -> None:
        checker = HealthChecker(InstallationManager(), VersionManager())
        assert not checker.check("nmap").healthy

    def test_unhealthy_when_probe_reports_false(self) -> None:
        installer = InstallationManager()
        versions = VersionManager()
        installer.register("nmap", lambda tool_id, version: "7.94")
        installer.install("nmap")
        versions.record("nmap", "7.94")
        checker = HealthChecker(installer, versions)
        checker.probe("nmap", lambda tool_id: False)
        assert not checker.check("nmap").healthy


class TestExecutionCapabilityRegistry:
    def test_register_and_query(self) -> None:
        registry = ExecutionCapabilityRegistry()
        registry.register("nmap", ["port-scanning"])
        assert registry.providers_for("port-scanning") == ["nmap"]
        assert registry.capabilities_for("nmap") == ["port-scanning"]
        assert registry.can_provide("port-scanning", "nmap")
        assert registry.capabilities() == ["port-scanning"]


class TestExecutionMonitor:
    def test_reports_and_timeline(self) -> None:
        monitor = ExecutionMonitor()
        context = make_context()
        seen: list[str] = []
        monitor.on_progress(lambda ctx, status, phase, meta: seen.append(phase))
        monitor.report(context, status=ExecutionStatus.RUNNING, phase="execute")
        monitor.report(context, status=ExecutionStatus.COMPLETED, phase="completed")
        assert [p.phase for p in monitor.timeline(context.execution_id)] == ["execute", "completed"]
        assert seen == ["execute", "completed"]
        assert monitor.last(context.execution_id).phase == "completed"


class TestExecutionSession:
    def test_lifecycle_and_status(self) -> None:
        session = ExecutionSession.create(make_context())
        assert session.status is ExecutionStatus.PENDING
        session.begin()
        assert session.status is ExecutionStatus.RUNNING
        result = ExecutionResult(status=ExecutionStatus.COMPLETED)
        session.finish(result)
        assert session.status is ExecutionStatus.COMPLETED
        assert session.has_completed
        assert session.completed_at

    def test_artifacts(self) -> None:
        session = ExecutionSession.create(make_context())
        session.attach("/tmp/out.json", kind="file")
        assert len(session.artifacts) == 1
        assert session.artifacts[0].path == "/tmp/out.json"


class TestExecutionEventBus:
    def test_emits_lifecycle_events(self) -> None:
        bus = ExecutionEventBus()
        bus.started("ex-1", "nmap", context_id="ctx-1")
        bus.completed("ex-1", "nmap", summary="ok")
        bus.failed("ex-1", "nmap", "timeout", "timed out")
        records = bus.events()
        assert [r.event_type.value for r in records] == [
            "execution.started",
            "execution.completed",
            "execution.failed",
        ]
        assert records[0].data["tool_id"] == "nmap"

    def test_pipeline_events(self) -> None:
        bus = ExecutionEventBus()
        bus.output_collected("ex-1", "nmap", ["json"], 12)
        bus.normalization_complete("ex-1", "nmap", 3)
        bus.database_updated("ex-1", "nmap", ["f-1"])
        bus.retried("ex-1", "nmap", 1, "timeout")
        bus.timed_out("ex-1", "nmap", 30.0)
        kinds = {r.event_type.value for r in bus.events()}
        assert kinds == {
            "output.collected",
            "normalization.complete",
            "database.updated",
            "execution.retried",
            "execution.timed_out",
        }

    def test_subscribers_receive_events(self) -> None:
        bus = ExecutionEventBus()
        received: list[str] = []
        bus.subscribe(lambda event_type, data: received.append(event_type.value))
        bus.started("ex-1", "nmap")
        assert received == ["execution.started"]


class TestTaskScheduler:
    def test_drains_queue(self) -> None:
        queue = ToolQueue()
        queue.enqueue(make_context(target="10.0.0.1"))
        queue.enqueue(make_context(target="10.0.0.2"))
        scheduler = TaskScheduler(queue, ResourceManager())
        ran: list[str] = []
        results = scheduler.drain(lambda context: ran.append(context.target) or ExecutionResult(status=ExecutionStatus.COMPLETED))
        assert ran == ["10.0.0.1", "10.0.0.2"]
        assert len(results) == 2
        assert queue.size() == 0

    def test_max_items(self) -> None:
        queue = ToolQueue()
        for _ in range(3):
            queue.enqueue(make_context())
        scheduler = TaskScheduler(queue, ResourceManager())
        scheduler.drain(lambda context: ExecutionResult(status=ExecutionStatus.COMPLETED), max_items=2)
        assert queue.size() == 1


class TestParallelExecutionManager:
    def test_collect_in_order(self) -> None:
        manager = ParallelExecutionManager(max_workers=2)
        futures = [
            manager.submit(lambda ctx: ExecutionResult(status=ExecutionStatus.COMPLETED), make_context())
            for _ in range(3)
        ]
        results = manager.collect(futures)
        assert all(result.ok for result in results)
        manager.shutdown()


class TestOutputCollector:
    def test_structured_output(self) -> None:
        collector = OutputCollector()
        collector.attach_stdout("text")
        collector.set_json({"findings": []})
        output = collector.build()
        assert output.stdout == "text"
        assert output.json == {"findings": []}

    def test_json_auto_detection_from_stdout(self) -> None:
        collector = OutputCollector()
        collector.attach_stdout('{"findings": [{"title": "x"}]}')
        output = collector.build()
        assert output.json == {"findings": [{"title": "x"}]}

    def test_artifacts(self) -> None:
        collector = OutputCollector()
        collector.attach_file("/tmp/a.txt")
        collector.attach_screenshot("/tmp/s.png")
        collector.attach_pcap("/tmp/p.pcap")
        output = collector.build()
        assert output.files == ["/tmp/a.txt", "/tmp/s.png", "/tmp/p.pcap"]
        assert output.screenshots == ["/tmp/s.png"]
        assert output.pcap_references == ["/tmp/p.pcap"]


class TestAdapterFactory:
    def test_bridge_wraps_legacy_tool(self) -> None:
        bridge: LegacyToolBridge = AdapterFactory().bridge(StaticScanner())
        assert isinstance(bridge, LegacyToolBridge)
        assert bridge.tool is not None

    def test_create_from_entrypoint(self) -> None:
        adapter = AdapterFactory().create("tests.framework.execution:FakeAdapter")
        assert isinstance(adapter, FakeAdapter)


class TestExecutionPluginManager:
    def test_load_and_unload(self, tmp_path) -> None:  # noqa: ANN001 - pytest fixture
        module_dir = tmp_path / "sdk_plugin"
        module_dir.mkdir()
        (module_dir / "__init__.py").write_text("", encoding="utf-8")
        module_dir.joinpath("sample.py").write_text(
            "__hunterx_plugin__ = {'name': 'sample', 'version': '1.0.0'}\n"
            "def register_tools():\n"
            "    return ['sample-scan']\n",
            encoding="utf-8",
        )
        sys.path.insert(0, str(tmp_path))
        try:
            manager = ExecutionPluginManager()
            plugin = manager.load("sdk_plugin.sample")
            assert plugin.name == "sample"
            assert plugin.version == "1.0.0"
            assert plugin.tools == ["sample-scan"]
            assert manager.is_loaded("sample")
            manager.unload("sample")
            assert not manager.is_loaded("sample")
        finally:
            sys.path.remove(str(tmp_path))


def test_retry_policy_defaults() -> None:
    assert RetryPolicy().max_attempts == 1
    assert RetryPolicy(max_attempts=2).retries() == 1
