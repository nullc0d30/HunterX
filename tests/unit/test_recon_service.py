# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ReconService orchestrator.

Exercises a full reconnaissance run: tool selection through the engine
registry, execution through the SDK pipeline with fake runners, correlation
across tools, TIDB persistence and the ``recon.*`` event stream.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from hunterx.application.recon import ReconService
from hunterx.domain.entities.tidb.network import ASN, CIDR, Domain, Hostname, IPAddress, Subdomain
from hunterx.domain.recon.correlator import ReconCorrelator
from hunterx.domain.recon.models import DiscoveryRecord, ReconMode, ReconTarget
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.recon.assetfinder import AssetfinderAdapter
from hunterx.tools.recon.bbot import BbotAdapter
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "recon"


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


def _recon_engine(*tools: str) -> ExecutionEngine:
    """Build an engine with the requested recon adapters on fake runners."""
    runners = {
        "subfinder": _golden("subfinder_passive.jsonl"),
        "assetfinder": _golden("assetfinder_plain.txt"),
        "bbot": _golden("bbot_events.jsonl"),
    }
    adapters = {
        "subfinder": SubfinderAdapter,
        "assetfinder": AssetfinderAdapter,
        "bbot": BbotAdapter,
    }
    engine = ExecutionEngine()
    for tool_id in tools:
        engine.register_adapter(tool_id, adapters[tool_id](runner=FakeRunner(stdout=runners[tool_id])))
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


def _event_recorder(bus: InMemoryEventBus) -> list[str]:
    captured: list[str] = []
    bus.subscribe("recon.#", lambda event: captured.append(event.event_type))
    return captured


class TestReconServiceSelection:
    def test_selects_only_registered_tools(self) -> None:
        service = ReconService(engine=_recon_engine("subfinder"))
        batch = service.run(target="example.com", mode="passive")
        assert [execution.tool_id for execution in batch.executions] == ["subfinder"]
        assert batch.mode is ReconMode.PASSIVE

    def test_requested_unregistered_tool_raises(self) -> None:
        service = ReconService(engine=_recon_engine("subfinder"))
        with pytest.raises(ValueError, match="not registered"):
            service.run(target="example.com", tools=["amass"])


class TestReconServiceRun:
    def test_correlates_records_across_tools(self) -> None:
        service = ReconService(engine=_recon_engine("subfinder", "assetfinder", "bbot"))
        batch = service.run(mission_id="mission-1", target="example.com", mode="hybrid")
        assert batch.mission_id == "mission-1"
        assert batch.correlation_id
        assert [execution.tool_id for execution in batch.executions] == [
            "subfinder",
            "assetfinder",
            "bbot",
        ]
        assert all(execution.status == "completed" for execution in batch.executions)
        assert batch.count() == 11
        assert batch.distinct() == 11

        www = next(record for record in batch.records if record.name == "www.example.com")
        assert set(www.details["tools"]) == {"subfinder", "assetfinder", "bbot"}
        assert www.confidence == 1.0

    def test_persists_correlated_records_into_tidb(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = ReconService(engine=_recon_engine("subfinder", "assetfinder", "bbot"), stores=stores)
        service.run(target="example.com", mode="passive")
        assert stores.repository_for(Domain).count() == 1
        assert stores.repository_for(Subdomain).count() == 5
        assert stores.repository_for(Hostname).count() == 5
        assert stores.repository_for(IPAddress).count() == 2
        assert stores.repository_for(CIDR).count() == 1
        assert stores.repository_for(ASN).count() == 1

        domain = stores.repository_for(Domain).list_by("name", "example.com")
        assert domain and domain[0].confidence == 0.9

        asn = stores.repository_for(ASN).list()
        assert asn and asn[0].number == 15133

    def test_target_id_propagates_to_persisted_records(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = ReconService(engine=_recon_engine("assetfinder"), stores=stores)
        target = ReconTarget(value="example.com", target_type="domain", target_id="target-abc")
        service.run(target=target, mode="passive")
        domains = stores.repository_for(Domain).list_by("target_id", "target-abc")
        assert domains and domains[0].name == "example.com"

    def test_publishes_recon_event_stream(self) -> None:
        bus = InMemoryEventBus()
        captured = _event_recorder(bus)
        stores = InMemoryTidbRepositoryFactory()
        service = ReconService(
            engine=_recon_engine("subfinder", "assetfinder", "bbot"),
            stores=stores,
            event_bus=bus,
        )
        service.run(mission_id="mission-1", target="example.com", mode="passive")
        assert captured[0] == "recon.started"
        assert captured.count("recon.tool_completed") == 3
        assert "recon.correlated" in captured
        assert "recon.persisted" in captured
        assert captured[-1] == "recon.completed"


class _ExplodingCorrelator(ReconCorrelator):
    def correlate(self, records: Sequence[DiscoveryRecord], *, scope: str = "") -> list[DiscoveryRecord]:
        raise RuntimeError("correlation exploded")


class TestReconServiceFailure:
    def test_failure_publishes_failed_event_and_raises(self) -> None:
        bus = InMemoryEventBus()
        captured = _event_recorder(bus)
        service = ReconService(
            engine=_recon_engine("subfinder"),
            event_bus=bus,
            correlator=_ExplodingCorrelator(),
        )
        with pytest.raises(RuntimeError, match="correlation exploded"):
            service.run(target="example.com", mode="passive")
        assert captured[0] == "recon.started"
        assert captured[-1] == "recon.failed"
