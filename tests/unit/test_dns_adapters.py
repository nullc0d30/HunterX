# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DNS tool adapters (dnsx, dnspython, resolver).

Every adapter is exercised with a fake binary runner fed golden output, or an
injectable resolve callable, so no external tool or network is required. Tests
assert the generated command line and the canonical DNS records attached to the
execution output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.domain.dns.models import DnsRecord, DnsRecordType
from hunterx.domain.execution import ExecutionContext, ExecutionStatus
from hunterx.tools.dns.dnspython import DnspythonAdapter
from hunterx.tools.dns.dnsx import DnsxAdapter
from hunterx.tools.dns.resolver import ResolverClient
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.output import OutputCollector

GOLDEN = Path(__file__).parent.parent / "golden" / "dns"


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
def dnsx_records_stdout() -> str:
    return (GOLDEN / "dnsx_records.jsonl").read_text(encoding="utf-8")


class TestDnsxAdapter:
    def test_default_argv_includes_core_types(self) -> None:
        adapter = DnsxAdapter()
        argv = adapter.build_argv(_context("dnsx"))
        assert argv[:4] == ["dnsx", "-d", "example.com", "-resp"]
        assert "-j" in argv and "-silent" in argv
        assert "-a" in argv and "-mx" in argv and "-soa" in argv

    def test_custom_record_types_and_resolvers(self) -> None:
        adapter = DnsxAdapter()
        argv = adapter.build_argv(
            _context("dnsx", params={"record_types": ["A", "MX"], "resolvers": ["1.1.1.1", "8.8.8.8"], "rate_limit": 50})
        )
        assert "-a" in argv and "-mx" in argv
        assert "-cname" not in argv
        assert argv[argv.index("-r") + 1] == "1.1.1.1,8.8.8.8"
        assert argv[argv.index("-rl") + 1] == "50"

    def test_wildcard_flag(self) -> None:
        adapter = DnsxAdapter()
        argv = adapter.build_argv(_context("dnsx", params={"wildcard": True}))
        assert "-wd" in argv

    def test_parses_records(self, dnsx_records_stdout: str) -> None:
        adapter = DnsxAdapter(runner=FakeRunner(stdout=dnsx_records_stdout))
        collector = _collect(adapter, _context("dnsx"))
        payload = collector.build().json or {}
        records = payload["dns_records"]
        types = {record["record_type"] for record in records}
        assert payload["count"] == 10
        assert types >= {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"}

    def test_mx_priority_split(self, dnsx_records_stdout: str) -> None:
        adapter = DnsxAdapter(runner=FakeRunner(stdout=dnsx_records_stdout))
        collector = _collect(adapter, _context("dnsx"))
        payload = collector.build().json or {}
        mx = next(record for record in payload["dns_records"] if record["record_type"] == "MX")
        assert mx["value"] == "10 mail.example.com"

    def test_multi_answer_list_expands(self) -> None:
        adapter = DnsxAdapter(runner=FakeRunner(stdout='{"host":"example.com","type":"A","ttl":300,"resp":["1.2.3.4","5.6.7.8"]}\n'))
        collector = _collect(adapter, _context("dnsx"))
        payload = collector.build().json or {}
        assert payload["count"] == 2

    def test_malformed_lines_are_skipped(self) -> None:
        adapter = DnsxAdapter(runner=FakeRunner(stdout=(GOLDEN / "dnsx_malformed.jsonl").read_text(encoding="utf-8")))
        collector = _collect(adapter, _context("dnsx"))
        payload = collector.build().json or {}
        values = {record["value"] for record in payload["dns_records"]}
        assert "not a json line at all" not in values
        assert len(payload["dns_records"]) >= 5

    def test_target_id_carried(self, dnsx_records_stdout: str) -> None:
        adapter = DnsxAdapter(runner=FakeRunner(stdout=dnsx_records_stdout))
        collector = _collect(adapter, _context("dnsx", params={"target_id": "target-1"}))
        payload = collector.build().json or {}
        assert all(record["target_id"] == "target-1" for record in payload["dns_records"])


class TestDnspythonAdapter:
    def test_run_resolves_in_process(self) -> None:
        def fake(name: str, record_type: DnsRecordType, resolver: str = "", tool_id: str = "") -> list[DnsRecord]:
            return [DnsRecord(name=name, record_type=record_type, value="93.184.216.34", resolver=resolver, tool_id=tool_id)]

        adapter = DnspythonAdapter(resolve=fake)
        collector = _collect(adapter, _context("dnspython", params={"record_types": ["A"]}))
        payload = collector.build().json or {}
        assert payload["count"] == 1
        assert payload["dns_records"][0]["record_type"] == "A"

    def test_build_argv_is_empty(self) -> None:
        adapter = DnspythonAdapter()
        assert adapter.build_argv(_context("dnspython")) == []

    def test_parse_output_unused(self) -> None:
        adapter = DnspythonAdapter()
        result = CommandResult(returncode=0, stdout="")
        assert adapter.parse_output(_context("dnspython"), result) == []


class TestResolverClient:
    def test_resolve_type_with_injected_resolve(self) -> None:
        client = ResolverClient()
        client.resolve = lambda name, record_type, resolver="", tool_id="": [  # noqa: E731
            DnsRecord(name=name, record_type=record_type, value="1.2.3.4", resolver=resolver, tool_id=tool_id)
        ]
        records = client.resolve_type("example.com", DnsRecordType.A, tool_id="dnspython")
        assert len(records) == 1
        assert records[0].value == "1.2.3.4"

    def test_resolve_names_deduplicates(self) -> None:
        client = ResolverClient()
        client.resolve = lambda name, record_type, resolver="", tool_id="": [  # noqa: E731
            DnsRecord(name=name, record_type=record_type, value="1.2.3.4", resolver=resolver, tool_id=tool_id)
        ]
        records = client.resolve_names(["a.example.com", "a.example.com"], DnsRecordType.A)
        assert len(records) == 1

    def test_cache_used_when_configured(self) -> None:
        from hunterx.domain.ports.messaging import CachePort

        class FakeCache(CachePort):
            def __init__(self) -> None:
                self.store: dict[str, object] = {}
                self.gets = 0

            def get(self, key: str) -> object | None:
                self.gets += 1
                return self.store.get(key)

            def set(self, key: str, value: object, *, ttl_seconds: int | None = None) -> None:
                self.store[key] = value

            def delete(self, key: str) -> None:
                self.store.pop(key, None)

            def flush(self) -> None:
                self.store.clear()

        cache = FakeCache()
        client = ResolverClient(cache=cache)
        client.resolve = lambda name, record_type, resolver="", tool_id="": [  # noqa: E731
            DnsRecord(name=name, record_type=record_type, value="1.2.3.4")
        ]
        first = client.resolve_type("example.com", DnsRecordType.A)
        second = client.resolve_type("example.com", DnsRecordType.A)
        assert len(first) == 1
        assert len(second) == 1
        assert cache.gets >= 1

    def test_error_isolation_across_resolvers(self) -> None:
        calls = {"ok": 0, "bad": 0}

        def resolve(name: str, record_type: DnsRecordType, resolver: str = "", tool_id: str = "") -> list[DnsRecord]:
            if resolver == "bad":
                calls["bad"] += 1
                raise RuntimeError("resolver down")
            calls["ok"] += 1
            return [DnsRecord(name=name, record_type=record_type, value="1.2.3.4", resolver=resolver)]

        client = ResolverClient(resolvers=("bad", "ok"))
        client.resolve = resolve
        records = client.resolve_type("example.com", DnsRecordType.A)
        assert len(records) == 1
        assert records[0].resolver == "ok"


class TestDnsAdapterLifecycleThroughPipeline:
    def test_pipeline_executes_dnsx_adapter(self) -> None:
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI
        from hunterx.tools.sdk.engine import ExecutionEngine
        from tests.framework.tip import register_standard_tools

        tip = ToolIntelligenceAPI()
        register_standard_tools(tip)
        engine = ExecutionEngine(intelligence=tip.registry)
        adapter = DnsxAdapter(runner=FakeRunner(stdout=(GOLDEN / "dnsx_records.jsonl").read_text(encoding="utf-8")))
        engine.register_adapter("dnsx", adapter)
        engine.install_hook("dnsx", lambda tool_id, version: "1.1.9")
        engine.install("dnsx", version="1.1.9")
        context = _context("dnsx", params={"target_id": "target-1"})
        outcome = engine.execute(context)
        assert outcome.result.status is ExecutionStatus.COMPLETED
        assert outcome.result.output.json["count"] == 10
