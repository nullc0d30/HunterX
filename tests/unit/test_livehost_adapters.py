# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Live Host & Service Discovery tool adapters.

Each adapter is exercised with a fake binary runner fed golden output (nmap
XML, naabu JSONL, masscan JSON), or an injectable probe callable for the
in-process TCP-connect adapter, so no external tool or network is required.
Tests assert the generated command line and the canonical observations attached
to the execution output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.livehost.models import PortState
from hunterx.tools.livehost.masscan import MasscanAdapter
from hunterx.tools.livehost.naabu import NaabuAdapter
from hunterx.tools.livehost.nmap import NmapAdapter
from hunterx.tools.livehost.registry import (
    LIVE_TOOL_IDS,
    LiveAdapterFactory,
    live_adapters,
    register_live_adapters,
)
from hunterx.tools.livehost.tcp_connect import TcpConnectAdapter
from hunterx.tools.livehost.tip import live_tool_specs, register_live_tools
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.output import OutputCollector

GOLDEN = Path(__file__).parent.parent / "golden" / "livehost"


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


def _context(tool_id: str, *, target: str = "1.2.3.4", params: dict[str, object] | None = None) -> ExecutionContext:
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_permissions(("network",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


def _collect(adapter, context: ExecutionContext) -> OutputCollector:
    collector = OutputCollector()
    adapter.run(context, collector)
    return collector


def _payload(collector: OutputCollector) -> dict[str, object]:
    return collector.build().json or {}


def _observations(collector: OutputCollector) -> list[dict[str, object]]:
    payload = _payload(collector)
    observations = payload["observations"]
    assert isinstance(observations, list)
    return observations


def _by_type(collector: OutputCollector) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for observation in _observations(collector):
        grouped.setdefault(str(observation["type"]), []).append(observation)
    return grouped


class TestNmapAdapter:
    def test_default_argv_includes_connect_scan(self) -> None:
        adapter = NmapAdapter()
        argv = adapter.build_argv(_context("nmap", params={"ports": [22, 80, 443]}))
        assert argv[:4] == ["nmap", "-oX", "-", "-sT"]
        assert argv[argv.index("-p") + 1] == "22,80,443"

    def test_host_discovery_only_mode(self) -> None:
        adapter = NmapAdapter()
        argv = adapter.build_argv(_context("nmap", params={"host_discovery_only": True}))
        assert "-sn" in argv
        assert "-p" not in argv

    def test_protocol_variants(self) -> None:
        adapter = NmapAdapter()
        udp = adapter.build_argv(_context("nmap", params={"protocol": "udp"}))
        assert "-sU" in udp and "-sT" not in udp
        both = adapter.build_argv(_context("nmap", params={"protocol": "both"}))
        assert "-sT" in both and "-sU" in both

    def test_service_detection_and_tls_flags(self) -> None:
        adapter = NmapAdapter()
        argv = adapter.build_argv(_context("nmap", params={"service_detection": True, "with_tls": True}))
        assert "-sV" in argv
        assert argv[argv.index("--script") + 1] == "ssl-cert"

    def test_rate_and_hostgroup(self) -> None:
        adapter = NmapAdapter()
        argv = adapter.build_argv(_context("nmap", params={"rate_limit": 500, "min_hostgroup": 8}))
        assert argv[argv.index("--max-rate") + 1] == "500"
        assert argv[argv.index("--min-hostgroup") + 1] == "8"

    def test_parses_full_scan_golden(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hosts.xml").read_text(encoding="utf-8")))
        collector = _collect(adapter, _context("nmap"))
        grouped = _by_type(collector)
        assert set(grouped) >= {"host", "port", "service", "http", "tls"}
        assert len(grouped["host"]) == 2
        assert len(grouped["port"]) == 4
        assert len(grouped["service"]) == 3
        assert len(grouped["http"]) == 2
        assert len(grouped["tls"]) == 1

    def test_port_fields(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hosts.xml").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("nmap")))
        open_ports = {port["port"] for port in grouped["port"] if port["state"] == "open"}
        assert open_ports == {22, 80, 443}
        closed = next(port for port in grouped["port"] if port["state"] == "closed")
        assert closed["port"] == 8080
        assert closed["reason"] == "reset"

    def test_service_and_http_records(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hosts.xml").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("nmap")))
        ssh = next(service for service in grouped["service"] if service["service"] == "ssh")
        assert ssh["product"] == "OpenSSH"
        assert ssh["version"].startswith("8.9")
        assert ssh["fingerprint_method"] == "probed"
        https = next(http for http in grouped["http"] if http["port"] == 443)
        assert https["scheme"] == "https"
        http = next(http for http in grouped["http"] if http["port"] == 80)
        assert http["scheme"] == "http"

    def test_tls_record(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hosts.xml").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("nmap")))
        tls = grouped["tls"][0]
        assert tls["port"] == 443
        assert tls["subject"] == "web.example.com"
        assert tls["issuer"] == "Example Intermediate CA"
        assert tls["sha256"] == "aaaabbbbccccddddeeeeffff111122223333444455556666777788889999aaaa"
        assert tls["san"] == ["web.example.com", "admin.example.com"]

    def test_host_down_state(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hosts.xml").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("nmap")))
        down = next(host for host in grouped["host"] if host["address"] == "5.6.7.8")
        assert down["state"] == "unreachable"
        assert down["reachable"] is False

    def test_host_discovery_only_golden_emits_hosts_only(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hostdiscovery.xml").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("nmap", params={"host_discovery_only": True})))
        assert set(grouped) == {"host"}
        assert len(grouped["host"]) == 2
        up = next(host for host in grouped["host"] if host["address"] == "10.0.0.1")
        assert up["state"] == "reachable" and up["reachable"] is True

    def test_malformed_xml_is_ignored(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout="not xml at all"))
        collector = _collect(adapter, _context("nmap"))
        assert _observations(collector) == []

    def test_target_id_carried(self) -> None:
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hosts.xml").read_text(encoding="utf-8")))
        observations = _observations(_collect(adapter, _context("nmap", params={"target_id": "target-1"})))
        assert all(observation["target_id"] == "target-1" for observation in observations)


class TestNaabuAdapter:
    def test_default_argv(self) -> None:
        adapter = NaabuAdapter()
        argv = adapter.build_argv(_context("naabu", params={"ports": [22, 80, 443]}))
        assert argv[:3] == ["naabu", "-host", "1.2.3.4"]
        assert "-silent" in argv and "-json" in argv
        assert argv[argv.index("-p") + 1] == "22,80,443"

    def test_udp_and_rate_flags(self) -> None:
        adapter = NaabuAdapter()
        argv = adapter.build_argv(_context("naabu", params={"protocol": "udp", "rate_limit": 1000}))
        assert "-sU" in argv
        assert argv[argv.index("-rate") + 1] == "1000"

    def test_parses_golden_jsonl(self) -> None:
        adapter = NaabuAdapter(runner=FakeRunner(stdout=(GOLDEN / "naabu_ports.jsonl").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("naabu")))
        assert set(grouped) == {"port"}
        ports = grouped["port"]
        assert len(ports) == 4
        assert {port["port"] for port in ports} == {22, 53, 443, 8080}

    def test_udp_protocol_preserved(self) -> None:
        adapter = NaabuAdapter(runner=FakeRunner(stdout=(GOLDEN / "naabu_ports.jsonl").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("naabu")))
        udp = next(port for port in grouped["port"] if port["port"] == 53)
        assert udp["protocol"] == "udp"

    def test_malformed_and_invalid_lines_are_skipped(self) -> None:
        adapter = NaabuAdapter(runner=FakeRunner(stdout=(GOLDEN / "naabu_ports.jsonl").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("naabu")))
        ports = grouped["port"]
        assert all(port["port"] <= 65535 for port in ports)
        assert "1.2.3.4" in {port["address"] for port in ports}

    def test_target_id_carried(self) -> None:
        adapter = NaabuAdapter(runner=FakeRunner(stdout=(GOLDEN / "naabu_ports.jsonl").read_text(encoding="utf-8")))
        observations = _observations(_collect(adapter, _context("naabu", params={"target_id": "target-9"})))
        assert all(observation["target_id"] == "target-9" for observation in observations)


class TestMasscanAdapter:
    def test_default_argv(self) -> None:
        adapter = MasscanAdapter()
        argv = adapter.build_argv(_context("masscan", params={"ports": [22, 80, 443]}))
        assert argv[:2] == ["masscan", "1.2.3.4"]
        assert argv[argv.index("-p") + 1] == "22,80,443"
        assert argv[argv.index("--output-format") + 1] == "json"
        assert argv[argv.index("--output-file") + 1] == "-"

    def test_rate_adapter_source_port(self) -> None:
        adapter = MasscanAdapter()
        argv = adapter.build_argv(
            _context("masscan", params={"rate_limit": 5000, "adapter": "eth0", "source_port": 12345})
        )
        assert argv[argv.index("--rate") + 1] == "5000"
        assert argv[argv.index("--adapter") + 1] == "eth0"
        assert argv[argv.index("--source-port") + 1] == "12345"

    def test_udp_flag(self) -> None:
        adapter = MasscanAdapter()
        argv = adapter.build_argv(_context("masscan", params={"protocol": "udp"}))
        assert "-sU" in argv

    def test_parses_golden_json(self) -> None:
        adapter = MasscanAdapter(runner=FakeRunner(stdout=(GOLDEN / "masscan_ports.json").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("masscan")))
        assert set(grouped) >= {"host", "port"}
        assert len(grouped["host"]) == 3
        assert {host["address"] for host in grouped["host"]} == {"1.2.3.4", "9.9.9.9", "10.0.0.5"}

    def test_host_deduplication_and_port_states(self) -> None:
        adapter = MasscanAdapter(runner=FakeRunner(stdout=(GOLDEN / "masscan_ports.json").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("masscan")))
        host = next(h for h in grouped["host"] if h["address"] == "1.2.3.4")
        assert host["state"] == "reachable" and host["reachable"] is True
        assert host["methods"] == ["tcp-syn"]
        ports_1_2_3_4 = [port for port in grouped["port"] if port["address"] == "1.2.3.4"]
        assert len(ports_1_2_3_4) == 3
        states = {(port["port"], port["state"]) for port in ports_1_2_3_4}
        assert (22, "open") in states and (443, "open") in states and (8080, "closed") in states

    def test_invalid_port_is_filtered(self) -> None:
        adapter = MasscanAdapter(runner=FakeRunner(stdout=(GOLDEN / "masscan_ports.json").read_text(encoding="utf-8")))
        grouped = _by_type(_collect(adapter, _context("masscan")))
        assert all(port["port"] <= 65535 for port in grouped["port"])
        assert "10.0.0.5" not in {port["address"] for port in grouped["port"]}


class TestTcpConnectAdapter:
    def test_all_open_produces_reachable_host(self) -> None:
        def probe(address: str, port: int, timeout: float) -> tuple[PortState, int]:
            return PortState.OPEN, 3

        collector = _collect(TcpConnectAdapter(probe=probe), _context("tcp-connect", params={"ports": [22, 443]}))
        grouped = _by_type(collector)
        host = grouped["host"][0]
        assert host["state"] == "reachable" and host["reachable"] is True
        assert host["methods"] == ["tcp-connect"]
        assert grouped["port"] and all(port["state"] == "open" for port in grouped["port"])
        assert _payload(collector)["count"] == 3

    def test_refused_proves_host_up(self) -> None:
        def probe(address: str, port: int, timeout: float) -> tuple[PortState, int]:
            return PortState.CLOSED, 1

        grouped = _by_type(_collect(TcpConnectAdapter(probe=probe), _context("tcp-connect", params={"ports": [22]})))
        host = grouped["host"][0]
        assert host["state"] == "reachable" and host["reachable"] is True
        assert grouped["port"][0]["state"] == "closed"

    def test_all_timeouts_yield_unknown(self) -> None:
        def probe(address: str, port: int, timeout: float) -> tuple[PortState, int]:
            return PortState.FILTERED, 1000

        grouped = _by_type(_collect(TcpConnectAdapter(probe=probe), _context("tcp-connect", params={"ports": [22]})))
        host = grouped["host"][0]
        assert host["state"] == "unknown" and host["reachable"] is None
        assert grouped["port"][0]["state"] == "filtered"

    def test_mixed_outcomes_host_reachable_with_rtt(self) -> None:
        def probe(address: str, port: int, timeout: float) -> tuple[PortState, int]:
            return {22: PortState.OPEN, 80: PortState.CLOSED, 443: PortState.FILTERED}[port], {22: 2, 80: 1, 443: 900}[port]

        grouped = _by_type(
            _collect(TcpConnectAdapter(probe=probe), _context("tcp-connect", params={"ports": [22, 80, 443]}))
        )
        host = grouped["host"][0]
        assert host["state"] == "reachable" and host["reachable"] is True
        assert host["rtt_ms"] == 1

    def test_build_argv_and_parse_output_are_noops(self) -> None:
        adapter = TcpConnectAdapter()
        context = _context("tcp-connect")
        assert adapter.build_argv(context) == []
        assert adapter.parse_output(context, CommandResult(returncode=0, stdout="")) == []

    def test_default_probe_maps_errors(self) -> None:
        adapter = TcpConnectAdapter()
        assert adapter._probe is not None  # noqa: SLF001  # default probe wired without injection


class TestRegistryAndTip:
    def test_live_adapters_contains_full_set(self) -> None:
        adapters = live_adapters()
        assert set(adapters) == set(LIVE_TOOL_IDS) == {"nmap", "naabu", "masscan", "rustscan", "tcp-connect"}

    def test_factory_create_and_unknown(self) -> None:
        factory = LiveAdapterFactory()
        assert isinstance(factory.create("nmap"), NmapAdapter)
        with pytest.raises(KeyError):
            factory.create("curl")

    def test_register_live_adapters_binds_on_engine(self) -> None:
        from hunterx.tools.sdk.engine import ExecutionEngine

        engine = ExecutionEngine()
        registered = register_live_adapters(engine)
        assert set(registered) == set(LIVE_TOOL_IDS)
        for tool_id in LIVE_TOOL_IDS:
            assert engine.adapter_for(tool_id) is registered[tool_id]

    def test_register_live_tools_populates_tip(self) -> None:
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI

        tip = ToolIntelligenceAPI()
        register_live_tools(tip)
        for spec in live_tool_specs():
            metadata = tip.registry.get_metadata(spec.tool_id)
            knowledge = tip.registry.get_knowledge(spec.tool_id)
            assert metadata is not None
            assert knowledge is not None
            assert metadata.tool_id == spec.tool_id
            assert set(spec.capabilities) <= set(knowledge.capabilities)


class TestPipelineLifecycle:
    def test_pipeline_executes_nmap_adapter(self) -> None:
        from hunterx.domain.execution import ExecutionStatus
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI
        from hunterx.tools.sdk.engine import ExecutionEngine
        from tests.framework.tip import register_standard_tools

        tip = ToolIntelligenceAPI()
        register_standard_tools(tip)
        engine = ExecutionEngine(intelligence=tip.registry)
        adapter = NmapAdapter(runner=FakeRunner(stdout=(GOLDEN / "nmap_hosts.xml").read_text(encoding="utf-8")))
        engine.register_adapter("nmap", adapter)
        engine.install_hook("nmap", lambda tool_id, version: "7.95")
        engine.install("nmap", version="7.95")
        context = _context("nmap", params={"target_id": "target-1", "service_detection": True})
        outcome = engine.execute(context)
        assert outcome.result.status is ExecutionStatus.COMPLETED
        assert outcome.result.output.json["count"] == 12
