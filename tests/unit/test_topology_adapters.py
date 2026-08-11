# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the topology (route-mapping) tool adapters.

The traceroute adapter is exercised with a fake binary runner fed golden
output (plain numeric, hostname, unreachable and malformed variants) so no
external tool or network is required. Tests assert the generated command line
and the canonical route records attached to the execution output.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.topology.registry import (
    TOPOLOGY_TOOL_IDS,
    TopologyAdapterFactory,
    register_topology_adapters,
    topology_adapters,
)
from hunterx.tools.topology.tip import register_topology_tools, topology_tool_specs
from hunterx.tools.topology.traceroute import TracerouteAdapter

GOLDEN = Path(__file__).parent.parent / "golden" / "topology"


class FakeRunner(BinaryRunner):
    """Binary runner that returns a canned :class:`CommandResult`."""

    def __init__(self, result: CommandResult | None = None, *, stdout: str = "") -> None:
        super().__init__()
        self._result = result or CommandResult(returncode=0, stdout=stdout)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv, *, timeout_s: float = 0.0, tool_id: str = ""):
        self.calls.append(tuple(argv))
        return self._result


def _golden(name: str) -> str:
    return (GOLDEN / name).read_text()


def _context(tool_id: str, *, target: str = "93.184.216.34", params: dict[str, object] | None = None) -> ExecutionContext:
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


def _routes(collector: OutputCollector) -> list[dict[str, object]]:
    payload = _payload(collector)
    routes = payload["routes"]
    assert isinstance(routes, list)
    return routes


class TestTracerouteAdapter:
    def test_default_argv_uses_numeric(self) -> None:
        adapter = TracerouteAdapter()
        argv = adapter.build_argv(_context("traceroute"))
        assert argv[:2] == ["traceroute", "-n"]
        assert argv[-1] == "93.184.216.34"

    def test_argv_with_max_hops(self) -> None:
        adapter = TracerouteAdapter()
        argv = adapter.build_argv(_context("traceroute", params={"max_hops": 15, "wait": 2}))
        assert "-m" in argv
        assert argv[argv.index("-m") + 1] == "15"
        assert "-w" in argv

    def test_parses_plain_golden(self) -> None:
        adapter = TracerouteAdapter(runner=FakeRunner(stdout=_golden("traceroute_plain.txt")))
        collector = _collect(adapter, _context("traceroute"))
        routes = _routes(collector)
        assert len(routes) == 7
        assert routes[0]["hop"] == 1
        assert routes[0]["address"] == "192.168.1.1"
        assert routes[4]["address"] is None  # unreachable asterisk hop
        assert routes[-1]["address"] == "93.184.216.34"

    def test_parses_hostname_golden(self) -> None:
        adapter = TracerouteAdapter(runner=FakeRunner(stdout=_golden("traceroute_names.txt")))
        collector = _collect(adapter, _context("traceroute", target="example.com"))
        routes = _routes(collector)
        assert routes[0]["hostname"] == "gateway.example.net"
        assert routes[0]["address"] == "192.168.1.1"

    def test_parses_unreachable_golden(self) -> None:
        adapter = TracerouteAdapter(runner=FakeRunner(stdout=_golden("traceroute_unreachable.txt")))
        collector = _collect(adapter, _context("traceroute"))
        routes = _routes(collector)
        assert routes[2]["address"] is None
        assert routes[3]["address"] is None
        assert routes[-1]["address"] == "203.0.113.10"

    def test_malformed_lines_are_skipped(self) -> None:
        adapter = TracerouteAdapter(runner=FakeRunner(stdout=_golden("traceroute_malformed.txt")))
        collector = _collect(adapter, _context("traceroute"))
        routes = _routes(collector)
        assert len(routes) == 2  # only real hop lines parsed

    def test_nonzero_exit_is_invalid(self) -> None:
        adapter = TracerouteAdapter(runner=FakeRunner(CommandResult(returncode=1, stdout="")))
        context = _context("traceroute")
        collector = _collect(adapter, context)
        output = collector.build()
        ok, errors = adapter.validate_output(context, output)
        assert not ok
        assert any("exit code" in error for error in errors)


class TestTopologyRegistry:
    def test_registered_tool_ids(self) -> None:
        assert TOPOLOGY_TOOL_IDS == ("traceroute",)
        assert set(topology_adapters()) == set(TOPOLOGY_TOOL_IDS)

    def test_factory_create(self) -> None:
        adapter = TopologyAdapterFactory().create("traceroute")
        assert isinstance(adapter, TracerouteAdapter)

    def test_factory_unknown_tool_raises(self) -> None:
        try:
            TopologyAdapterFactory().create("nope")
        except KeyError:
            pass
        else:
            raise AssertionError("expected KeyError")

    def test_register_on_engine(self) -> None:
        from hunterx.tools.sdk.engine import ExecutionEngine

        engine = ExecutionEngine()
        mapping = register_topology_adapters(engine)
        assert engine.adapter_for("traceroute") is not None
        assert set(mapping) == set(TOPOLOGY_TOOL_IDS)


class TestTopologyTip:
    def test_register_tools(self) -> None:
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI

        tip = ToolIntelligenceAPI()
        register_topology_tools(tip)
        ids = [tool.tool_id for tool in tip.list_tools()]
        assert "traceroute" in ids

    def test_specs_match_descriptor(self) -> None:
        specs = {spec.tool_id: spec for spec in topology_tool_specs()}
        assert "traceroute" in specs
        spec = specs["traceroute"]
        assert spec.capabilities == ("route-mapping", "network-topology")
        assert spec.cli_binary == "traceroute"
