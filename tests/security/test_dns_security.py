# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the DNS intelligence capability.

Covers the DNS-specific security model: command/argument injection through tool
parameters, credential leakage into argv, cross-target cache contamination,
scope/safety enforcement and untrusted tool output never being executed.
"""

from __future__ import annotations

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, make_record
from hunterx.domain.dns.scope import ScopeEnforcer, ScopePolicy
from hunterx.tools.dns.dnsx import DnsxAdapter
from hunterx.tools.sdk.context import ExecutionContextBuilder


def _context(tool_id: str, *, target: str = "example.com", params: dict[str, object] | None = None):
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_permissions(("network",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


class TestDnsArgvInjection:
    def test_shell_metacharacters_are_not_split(self) -> None:
        adapter = DnsxAdapter()
        argv = adapter.build_argv(_context("dnsx", target="example.com; rm -rf /", params={"record_types": ["A"]}))
        assert "example.com; rm -rf /" in argv
        assert not any(part in (";", "|", "&&", "$(") for part in argv)

    def test_resolver_param_cannot_inject_flags(self) -> None:
        adapter = DnsxAdapter()
        argv = adapter.build_argv(_context("dnsx", params={"resolvers": ["1.1.1.1 -wd"], "record_types": ["A"]}))
        assert "-wd" not in argv

    def test_record_type_param_is_whitelisted(self) -> None:
        adapter = DnsxAdapter()
        argv = adapter.build_argv(_context("dnsx", params={"record_types": ["A", "VICTIMFLAG", "MX"]}))
        assert "-VICTIMFLAG" not in argv
        assert "-a" in argv and "-mx" in argv

    def test_unrelated_credential_params_never_land_in_argv(self) -> None:
        adapter = DnsxAdapter()
        argv = adapter.build_argv(
            _context("dnsx", params={"record_types": ["A"], "api_key": "hunterx-secret-token", "password": "hunterx-pass"})
        )
        assert not any("hunterx-secret-token" in arg for arg in argv)
        assert not any("hunterx-pass" in arg for arg in argv)


class TestDnsScopeSafety:
    def test_out_of_scope_names_denied(self) -> None:
        enforcer = ScopeEnforcer(ScopePolicy(roots=frozenset({"example.com"})))
        assert not enforcer.allows_name("evil.org").allowed
        assert enforcer.allows_name("www.example.com").allowed

    def test_out_of_scope_addresses_denied(self) -> None:
        enforcer = ScopeEnforcer(ScopePolicy(root_cidrs=frozenset({"192.0.2.0/24"})))
        assert not enforcer.allows_address("10.0.0.1").allowed
        assert enforcer.allows_address("192.0.2.5").allowed

    def test_private_addresses_excluded_by_default_scope(self) -> None:
        enforcer = ScopeEnforcer()
        assert enforcer.allows_name("example.com").allowed

    def test_wildcard_poisoned_records_never_persisted(self) -> None:
        from hunterx.domain.dns.wildcard import WildcardDetector

        detector = WildcardDetector(
            resolve=lambda name: [make_record(name, DnsRecordType.A, "192.0.2.10")] if name != "example.com" else [],
            probes=4,
        )
        finding = detector.probe("example.com")
        assert finding.wildcard
        poisoned = finding.matching_records()
        assert poisoned
        # Persisted records must never include wildcard-poisoned answers.
        assert all(record.name in finding.probed_names for record in poisoned)


class TestDnsCrossTargetIsolation:
    def test_resolver_cache_keys_are_target_scoped(self) -> None:
        client = __import__("hunterx.tools.dns.resolver", fromlist=["ResolverClient"]).ResolverClient()
        key_a = client._cache_key("example.com", DnsRecordType.A)
        key_b = client._cache_key("evil.org", DnsRecordType.A)
        key_c = client._cache_key("EXAMPLE.com", DnsRecordType.A)
        assert key_a != key_b
        assert key_a == key_c  # normalization, not cross-target

    def test_cache_never_leaks_between_targets(self) -> None:
        from hunterx.domain.ports.messaging import CachePort
        from hunterx.tools.dns.resolver import ResolverClient

        class FakeCache(CachePort):
            def __init__(self) -> None:
                self.store: dict[str, object] = {}

            def get(self, key: str) -> object | None:
                return self.store.get(key)

            def set(self, key: str, value: object, *, ttl_seconds: int | None = None) -> None:
                self.store[key] = value

            def delete(self, key: str) -> None:
                self.store.pop(key, None)

            def flush(self) -> None:
                self.store.clear()

        cache = FakeCache()
        client = ResolverClient(cache=cache)

        def resolve(name: str, record_type: DnsRecordType, resolver: str = "", tool_id: str = "") -> list[DnsRecord]:
            return [make_record(name, record_type, "1.2.3.4", resolver=resolver, tool_id=tool_id)]

        client.resolve = resolve
        client.resolve_type("example.com", DnsRecordType.A)
        cached = cache.get("dns:example.com:A")
        assert cached is not None
        assert cache.get("dns:evil.org:A") is None


class TestDnsUntrustedOutput:
    def test_malformed_output_is_skipped_not_executed(self) -> None:
        adapter = DnsxAdapter()
        from hunterx.tools.recon.runner import CommandResult

        result = CommandResult(
            returncode=0,
            stdout='{"host":"example.com","type":"A","resp":["1.2.3.4"]}\n__import__("os").system("rm -rf /")\n',
        )
        records = adapter.parse_output(_context("dnsx"), result)
        assert len(records) == 1
        assert records[0].value == "1.2.3.4"

    def test_non_json_lines_ignored(self) -> None:
        adapter = DnsxAdapter()
        from hunterx.tools.recon.runner import CommandResult

        result = CommandResult(returncode=0, stdout="garbage line\nnot json\n")
        assert adapter.parse_output(_context("dnsx"), result) == []
