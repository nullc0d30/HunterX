# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the LiveHostService orchestrator.

Exercises a full live host & service discovery run: tool selection, execution
through the SDK pipeline with fake binary runners fed golden output (nmap XML,
naabu JSONL, masscan JSON) and an injectable TCP-connect probe, normalization,
validation, correlation, conflict resolution, historical comparison, TIDB
persistence and the ``host.*`` event stream.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.application.livehost import LiveHostService
from hunterx.domain.entities.tidb.network import HostObservation as TidbHostObservation
from hunterx.domain.entities.tidb.network import PortObservation as TidbPortObservation
from hunterx.domain.entities.tidb.network import ServiceObservation as TidbServiceObservation
from hunterx.domain.livehost.correlator import LiveCorrelator
from hunterx.domain.livehost.models import PortState
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.livehost.masscan import MasscanAdapter
from hunterx.tools.livehost.naabu import NaabuAdapter
from hunterx.tools.livehost.nmap import NmapAdapter
from hunterx.tools.livehost.tcp_connect import TcpConnectAdapter
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "livehost"


class FakeRunner(BinaryRunner):
    """Binary runner that returns a canned :class:`CommandResult`."""

    def __init__(self, *, stdout: str = "") -> None:
        super().__init__()
        self._result = CommandResult(returncode=0, stdout=stdout)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: list[str], *, timeout_s: float = 0.0, tool_id: str = "") -> CommandResult:
        self.calls.append(tuple(argv))
        return self._result


def _golden(name: str) -> str:
    return (GOLDEN / name).read_text(encoding="utf-8")


def _open_probe(address: str, port: int, timeout: float) -> tuple[PortState, int]:
    return PortState.OPEN, 2


def _live_engine(*tools: str) -> ExecutionEngine:
    """Build an engine with live discovery adapters on fake runners/probes."""
    nmap_adapter = NmapAdapter(runner=FakeRunner(stdout=_golden("nmap_hosts.xml")))
    naabu_adapter = NaabuAdapter(runner=FakeRunner(stdout=_golden("naabu_ports.jsonl")))
    masscan_adapter = MasscanAdapter(runner=FakeRunner(stdout=_golden("masscan_ports.json")))
    tcp_connect_adapter = TcpConnectAdapter(probe=_open_probe)
    adapters: dict[str, object] = {
        "nmap": nmap_adapter,
        "naabu": naabu_adapter,
        "masscan": masscan_adapter,
        "tcp-connect": tcp_connect_adapter,
    }
    engine = ExecutionEngine()
    for tool_id in tools:
        adapter = adapters[tool_id]
        engine.register_adapter(tool_id, adapter)
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


def _event_recorder(bus: InMemoryEventBus) -> list[str]:
    captured: list[str] = []
    bus.subscribe("host.#", lambda event: captured.append(event.event_type))
    return captured


class TestLiveHostServiceSelection:
    def test_selects_only_registered_tools(self) -> None:
        service = LiveHostService(engine=_live_engine("nmap"))
        batch = service.run(target="1.2.3.4", mode="active")
        assert [execution.tool_id for execution in batch.executions] == ["nmap"]

    def test_requested_unregistered_tool_raises(self) -> None:
        service = LiveHostService(engine=_live_engine("nmap"))
        with pytest.raises(ValueError, match="not registered"):
            service.run(target="1.2.3.4", tools=["masscan"])

    def test_cidr_target_type_inferred(self) -> None:
        service = LiveHostService(engine=_live_engine("nmap"))
        batch = service.run(target="10.0.0.0/24", mode="active")
        assert batch.target.target_type == "cidr"


class TestLiveHostServiceRun:
    def test_correlates_observations_from_tool(self) -> None:
        service = LiveHostService(engine=_live_engine("nmap"))
        batch = service.run(mission_id="mission-1", target="1.2.3.4", mode="active")
        assert batch.mission_id == "mission-1"
        assert batch.correlation_id
        assert [execution.tool_id for execution in batch.executions] == ["nmap"]
        assert batch.host_count() >= 1
        assert batch.port_count() >= 4
        assert batch.service_count() >= 3
        states = {port.state for port in batch.ports}
        assert PortState.OPEN in states
        assert PortState.CLOSED in states

    def test_correlates_across_multiple_tools(self) -> None:
        service = LiveHostService(engine=_live_engine("nmap", "naabu"))
        batch = service.run(target="1.2.3.4", mode="active")
        assert {execution.tool_id for execution in batch.executions} == {"nmap", "naabu"}
        assert batch.host_count() >= 1
        assert batch.port_count() >= 4

    def test_normalizes_and_validates_observations(self) -> None:
        service = LiveHostService(engine=_live_engine("nmap"))
        batch = service.run(target="1.2.3.4", mode="active")
        host = next(host for host in batch.hosts if host.address == "1.2.3.4")
        assert host.state.value == "reachable"
        assert host.reachable is True
        ssh = next(service for service in batch.services if service.service == "ssh")
        assert ssh.product == "OpenSSH"
        assert ssh.version.startswith("8.9")

    def test_tcp_connect_probe_populates_ports(self) -> None:
        service = LiveHostService(engine=_live_engine("tcp-connect"))
        batch = service.run(target="1.2.3.4", mode="active", ports=[22, 443])
        assert batch.host_count() == 1
        assert batch.port_count() == 2
        assert all(port.state is PortState.OPEN for port in batch.ports)
        assert batch.open_port_count() == 2

    def test_persists_observations_into_tidb(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = LiveHostService(engine=_live_engine("nmap"), stores=stores)
        batch = service.run(target="1.2.3.4", mode="active")
        assert stores.repository_for(TidbHostObservation).count() == batch.host_count()
        assert stores.repository_for(TidbPortObservation).count() == batch.port_count()
        assert stores.repository_for(TidbServiceObservation).count() == batch.service_count()

    def test_publishes_live_event_stream(self) -> None:
        bus = InMemoryEventBus()
        captured = _event_recorder(bus)
        service = LiveHostService(engine=_live_engine("nmap", "tcp-connect"), event_bus=bus)
        service.run(mission_id="mission-1", target="1.2.3.4", mode="active")
        assert captured[0] == "host.discovery.started"
        assert "host.phase.started" in captured
        assert "host.host.discovered" in captured
        assert "host.port.discovered" in captured
        assert "host.service.discovered" in captured
        assert "host.correlation.completed" in captured
        assert captured[-1] == "host.discovery.completed"

    def test_historical_comparison(self) -> None:
        from hunterx.domain.livehost.models import make_host

        historical = [make_host("1.2.3.4", reachable=True)]
        service = LiveHostService(engine=_live_engine("nmap"))
        batch = service.run(
            target="1.2.3.4",
            mode="active",
            with_history=True,
            historical=historical,
        )
        assert batch.changes

    def test_passive_mode_selects_no_tools(self) -> None:
        service = LiveHostService(engine=_live_engine("nmap"))
        batch = service.run(target="1.2.3.4", mode="passive")
        assert batch.executions == []


class _ExplodingCorrelator(LiveCorrelator):
    def correlate(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        raise RuntimeError("correlation exploded")


class TestLiveHostServiceFailure:
    def test_failure_publishes_failed_event_and_raises(self) -> None:
        bus = InMemoryEventBus()
        captured = _event_recorder(bus)
        service = LiveHostService(
            engine=_live_engine("nmap"),
            event_bus=bus,
            correlator=_ExplodingCorrelator(),
        )
        with pytest.raises(RuntimeError, match="correlation exploded"):
            service.run(target="1.2.3.4", mode="active")
        assert captured[0] == "host.discovery.started"
        assert captured[-1] == "host.discovery.failed"
