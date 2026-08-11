# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DnsService orchestrator.

Exercises a full DNS intelligence run: tool selection, execution through the
SDK pipeline with a fake dnsx runner and an injectable dnspython resolver,
normalization, validation, correlation, DNSSEC/mail analysis, historical
comparison, TIDB persistence and the ``dns.*`` event stream.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.application.dns import DnsService
from hunterx.domain.dns.correlator import DnsCorrelator
from hunterx.domain.dns.models import DnsRecord, DnsRecordType, make_record
from hunterx.domain.entities.tidb.network import DNSRecord as TidbDnsRecord
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.dns.dnspython import DnspythonAdapter
from hunterx.tools.dns.dnsx import DnsxAdapter
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "dns"


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


def _dns_engine(*tools: str, dnsx_stdout: str | None = None) -> ExecutionEngine:
    """Build an engine with DNS adapters on fake runners/resolvers."""
    runners = {
        "dnsx": dnsx_stdout if dnsx_stdout is not None else _golden("dnsx_records.jsonl"),
    }
    adapters: dict[str, object] = {
        "dnsx": DnsxAdapter,
        "dnspython": DnspythonAdapter,
    }
    engine = ExecutionEngine()
    for tool_id in tools:
        if tool_id == "dnspython":
            adapter = DnspythonAdapter(resolve=_fake_resolver())
        else:
            adapter = adapters[tool_id](runner=FakeRunner(stdout=runners[tool_id]))
        engine.register_adapter(tool_id, adapter)
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine


def _fake_resolver():
    def resolve(name: str, *args, **kwargs) -> list[DnsRecord]:  # noqa: ANN001, ANN002, ANN003
        return [
            make_record(name, DnsRecordType.A, "93.184.216.34", resolver="1.1.1.1", tool_id="dnspython"),
            make_record(name, DnsRecordType.AAAA, "2606:2800:220:1:248:1893:25c8:1946", resolver="1.1.1.1", tool_id="dnspython"),
        ]

    return resolve


def _event_recorder(bus: InMemoryEventBus) -> list[str]:
    captured: list[str] = []
    bus.subscribe("dns.#", lambda event: captured.append(event.event_type))
    return captured


class TestDnsServiceSelection:
    def test_selects_only_registered_tools(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx"))
        batch = service.run(target="example.com", mode="active")
        assert [execution.tool_id for execution in batch.executions] == ["dnsx"]

    def test_requested_unregistered_tool_raises(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx"))
        with pytest.raises(ValueError, match="not registered"):
            service.run(target="example.com", tools=["dnspython"])

    def test_ip_target_type_inferred(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx"))
        batch = service.run(target="1.2.3.4", mode="passive")
        assert batch.target.target_type == "ip"


class TestDnsServiceRun:
    def test_correlates_records_from_tool(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx"))
        batch = service.run(mission_id="mission-1", target="example.com", mode="active")
        assert batch.mission_id == "mission-1"
        assert batch.correlation_id
        assert [execution.tool_id for execution in batch.executions] == ["dnsx"]
        assert batch.count() >= 10
        types = {record.record_type for record in batch.records}
        assert types >= {DnsRecordType.A, DnsRecordType.MX, DnsRecordType.SOA}

    def test_normalizes_and_validates_records(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx"))
        batch = service.run(target="example.com", mode="active")
        a = next(record for record in batch.records if record.record_type is DnsRecordType.A)
        assert a.validation_status == "valid"
        assert a.name == "example.com"

    def test_resolutions_populated(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx", "dnspython"))
        batch = service.run(target="example.com", mode="active")
        assert any(resolution.status == "resolved" for resolution in batch.resolutions)

    def test_dnssec_analysis(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx", dnsx_stdout=_golden("dnsx_dnssec.jsonl")))
        batch = service.run(target="example.com", mode="active", with_dnssec=True)
        assert batch.dnssec  # zone findings keyed by zone

    def test_mail_analysis(self) -> None:
        service = DnsService(engine=_dns_engine("dnsx", dnsx_stdout=_golden("dnsx_mail.jsonl")))
        batch = service.run(target="example.com", mode="active", with_mail=True)
        finding = batch.mail.get("example.com")
        assert finding is not None
        assert finding.spf_analysis["valid"] == "true"
        assert finding.spf_analysis["mechanisms"] != ""
        assert finding.dmarc_analysis["policy"] == "reject"
        assert "google" in finding.dkim_selectors
        assert finding.mx_hosts == ("mail.example.com", "mail2.example.com")

    def test_persists_records_into_tidb(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = DnsService(engine=_dns_engine("dnsx"), stores=stores)
        batch = service.run(target="example.com", mode="active")
        assert stores.repository_for(TidbDnsRecord).count() == batch.count()

    def test_publishes_dns_event_stream(self) -> None:
        bus = InMemoryEventBus()
        captured = _event_recorder(bus)
        service = DnsService(engine=_dns_engine("dnsx", "dnspython"), event_bus=bus)
        service.run(mission_id="mission-1", target="example.com", mode="active")
        assert captured[0] == "dns.intelligence.started"
        assert "dns.phase.started" in captured
        assert "dns.resolution.started" in captured
        assert "dns.resolution.completed" in captured
        assert "dns.record.discovered" in captured
        assert "dns.correlation.completed" in captured
        assert captured[-1] == "dns.intelligence.completed"

    def test_historical_comparison(self) -> None:
        historical = [make_record("example.com", DnsRecordType.A, "93.184.216.34")]
        service = DnsService(engine=_dns_engine("dnsx"))
        batch = service.run(
            target="example.com",
            mode="active",
            with_history=True,
            historical=historical,
        )
        assert batch.changes


class _ExplodingCorrelator(DnsCorrelator):
    def correlate(self, records: list[DnsRecord]):  # noqa: ANN001, ANN201
        raise RuntimeError("correlation exploded")


class TestDnsServiceFailure:
    def test_failure_publishes_failed_event_and_raises(self) -> None:
        bus = InMemoryEventBus()
        captured = _event_recorder(bus)
        service = DnsService(
            engine=_dns_engine("dnsx"),
            event_bus=bus,
            correlator=_ExplodingCorrelator(),
        )
        with pytest.raises(RuntimeError, match="correlation exploded"):
            service.run(target="example.com", mode="active")
        assert captured[0] == "dns.intelligence.started"
        assert captured[-1] == "dns.resolution.failed"
