# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the six recon tool adapters.

Every adapter is exercised with a fake binary runner fed golden output, so no
external tool is required. Tests assert the generated command line and the
canonical discovery records attached to the execution output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.recon.models import DiscoveryKind
from hunterx.tools.recon.amass import AmassAdapter
from hunterx.tools.recon.assetfinder import AssetfinderAdapter
from hunterx.tools.recon.bbot import BbotAdapter
from hunterx.tools.recon.findomain import FindomainAdapter
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.recon.theharvester import TheHarvesterAdapter
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.output import OutputCollector

GOLDEN = Path(__file__).parent.parent / "golden" / "recon"


class FakeRunner(BinaryRunner):
    """Binary runner that returns a canned :class:`CommandResult`."""

    def __init__(self, result: CommandResult | None = None, *, stdout: str = "") -> None:
        super().__init__()
        self._result = result or CommandResult(returncode=0, stdout=stdout)
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float = 0.0,
        tool_id: str = "",
    ) -> CommandResult:
        self.calls.append(tuple(argv))
        return self._result


def _context(tool_id: str, *, target: str = "example.com", params: dict[str, object] | None = None) -> ExecutionContext:
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_permissions(("network",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


def _collect(adapter, context: ExecutionContext) -> OutputCollector:
    collector = OutputCollector()
    adapter.run(context, collector)
    return collector


@pytest.fixture
def subfinder_stdout() -> str:
    return (GOLDEN / "subfinder_passive.jsonl").read_text(encoding="utf-8")


class TestSubfinderAdapter:
    def test_passive_argv(self) -> None:
        adapter = SubfinderAdapter()
        argv = adapter.build_argv(_context("subfinder", params={"mode": "passive"}))
        assert "-d" in argv and "example.com" in argv
        assert "-silent" in argv and "-oJ" in argv and "-cs" in argv
        assert "-nW" not in argv

    def test_active_argv_adds_resolution(self) -> None:
        adapter = SubfinderAdapter()
        argv = adapter.build_argv(_context("subfinder", params={"mode": "active", "threads": 5}))
        assert "-nW" in argv and "-oI" in argv
        assert argv[argv.index("-t") + 1] == "5"

    def test_parses_jsonl_to_subdomains(self, subfinder_stdout: str) -> None:
        adapter = SubfinderAdapter(runner=FakeRunner(stdout=subfinder_stdout))
        collector = _collect(adapter, _context("subfinder"))
        payload = collector.build().json or {}
        names = {entry["name"] for entry in payload["discoveries"]}
        kinds = {entry["kind"] for entry in payload["discoveries"]}
        assert {"www.example.com", "api.example.com", "dev.example.com"} <= names
        assert DiscoveryKind.IP_ADDRESS.value in kinds
        assert payload["count"] == 5

    def test_plain_line_fallback(self) -> None:
        adapter = SubfinderAdapter(runner=FakeRunner(stdout="api.example.com\nwww.example.com\n"))
        collector = _collect(adapter, _context("subfinder"))
        payload = collector.build().json or {}
        assert all(entry["kind"] == DiscoveryKind.SUBDOMAIN.value for entry in payload["discoveries"])


class TestAmassAdapter:
    def test_passive_argv_uses_enum(self) -> None:
        adapter = AmassAdapter()
        argv = adapter.build_argv(_context("amass", params={"mode": "passive"}))
        assert argv[:3] == ["amass", "enum", "-passive"]
        assert argv[argv.index("-d") + 1] == "example.com"

    def test_parses_event_stream(self, tmp_path: Path) -> None:
        adapter = AmassAdapter(runner=FakeRunner())
        context = _context("amass")
        context = _with_directory(context, tmp_path)
        (tmp_path / f"amass-{context.execution_id}.json").write_text(
            (GOLDEN / "amass_events.jsonl").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        collector = _collect(adapter, context)
        payload = collector.build().json or {}
        kinds = {entry["kind"] for entry in payload["discoveries"]}
        assert DiscoveryKind.SUBDOMAIN.value in kinds
        assert DiscoveryKind.IP_ADDRESS.value in kinds
        assert DiscoveryKind.CIDR.value in kinds


class TestAssetfinderAdapter:
    def test_argv(self) -> None:
        adapter = AssetfinderAdapter()
        assert adapter.build_argv(_context("assetfinder")) == ["assetfinder", "example.com"]
        argv = adapter.build_argv(_context("assetfinder", params={"subs_only": True}))
        assert argv == ["assetfinder", "--subs-only", "example.com"]

    def test_parses_plain_hosts(self) -> None:
        adapter = AssetfinderAdapter(runner=FakeRunner(stdout=(GOLDEN / "assetfinder_plain.txt").read_text(encoding="utf-8")))
        collector = _collect(adapter, _context("assetfinder"))
        payload = collector.build().json or {}
        names = {entry["name"] for entry in payload["discoveries"]}
        assert names == {"example.com", "www.example.com", "mail.example.com", "api.example.com"}
        domain = next(entry for entry in payload["discoveries"] if entry["name"] == "example.com")
        assert domain["kind"] == DiscoveryKind.DOMAIN.value


class TestFindomainAdapter:
    def test_parses_hosts_and_ips(self) -> None:
        adapter = FindomainAdapter(runner=FakeRunner(stdout=(GOLDEN / "findomain_plain.txt").read_text(encoding="utf-8")))
        collector = _collect(adapter, _context("findomain"))
        payload = collector.build().json or {}
        assert "admin.example.com" in {entry["name"] for entry in payload["discoveries"]}
        assert any(entry["kind"] == DiscoveryKind.IP_ADDRESS.value for entry in payload["discoveries"])


class TestBbotAdapter:
    def test_passive_argv_restricts_modules(self) -> None:
        adapter = BbotAdapter()
        argv = adapter.build_argv(_context("bbot", params={"mode": "passive"}))
        assert argv[argv.index("-rf") + 1] == "passive"

    def test_parses_event_types(self) -> None:
        adapter = BbotAdapter(runner=FakeRunner(stdout=(GOLDEN / "bbot_events.jsonl").read_text(encoding="utf-8")))
        collector = _collect(adapter, _context("bbot"))
        payload = collector.build().json or {}
        kinds = {entry["kind"] for entry in payload["discoveries"]}
        assert {
            DiscoveryKind.SUBDOMAIN.value,
            DiscoveryKind.DOMAIN.value,
            DiscoveryKind.IP_ADDRESS.value,
            DiscoveryKind.CIDR.value,
            DiscoveryKind.ASN.value,
            DiscoveryKind.ORGANIZATION.value,
            DiscoveryKind.EXPOSED_ASSET.value,
        } <= kinds


class TestTheHarvesterAdapter:
    def test_parses_result_file(self, tmp_path: Path) -> None:
        adapter = TheHarvesterAdapter(runner=FakeRunner())
        context = _context("theharvester")
        context = _with_directory(context, tmp_path)
        (tmp_path / f"theharvester-{context.execution_id}.json").write_text(
            (GOLDEN / "theharvester_result.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        collector = _collect(adapter, context)
        payload = collector.build().json or {}
        kinds = {entry["kind"] for entry in payload["discoveries"]}
        names = {entry["name"] for entry in payload["discoveries"]}
        assert DiscoveryKind.HOSTNAME.value in kinds
        assert DiscoveryKind.IP_ADDRESS.value in kinds
        assert DiscoveryKind.EXPOSED_ASSET.value in kinds
        assert "www.example.com" in names
        assert "93.184.216.34" in names


class TestAdapterLifecycleThroughPipeline:
    def test_pipeline_executes_recon_adapter(self) -> None:
        from hunterx.domain.execution import ExecutionStatus
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI
        from hunterx.tools.sdk.engine import ExecutionEngine
        from tests.framework.tip import register_standard_tools

        tip = ToolIntelligenceAPI()
        register_standard_tools(tip)
        engine = ExecutionEngine(intelligence=tip.registry)
        adapter = SubfinderAdapter(
            runner=FakeRunner(stdout=(GOLDEN / "subfinder_passive.jsonl").read_text(encoding="utf-8"))
        )
        engine.register_adapter("subfinder", adapter)
        engine.install_hook("subfinder", lambda tool_id, version: "1.0.0")
        engine.install("subfinder", version="1.0.0")
        context = _context("subfinder", params={"target_id": "target-1"})
        outcome = engine.execute(context)
        assert outcome.result.status is ExecutionStatus.COMPLETED
        assert outcome.result.output.json["count"] == 5


def _with_directory(context: ExecutionContext, directory: Path) -> ExecutionContext:
    return ExecutionContextBuilder.from_context(context).with_directories(
        temp_directory=str(directory)
    ).build()
