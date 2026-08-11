# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""dnspython-based active resolver adapter.

Performs direct DNS resolution through the ``dnspython`` library (the runtime
dependency used for active-mode collection) and emits canonical
:class:`DnsRecord` instances. Unlike binary adapters this adapter has no CLI;
it resolves the target through a pool of configured resolvers with per-query
timeouts.

The resolution callable is injectable so unit tests never touch the network:
``DnspythonAdapter(resolve=fake_resolve)``.
"""

from __future__ import annotations

from collections.abc import Callable

from hunterx.domain.dns.models import DnsRecord, DnsRecordType
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.dns.base import DnsToolAdapter
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.sdk.output import OutputCollector

_VERSION = "2.8.0"

#: Canonical type lookup used to build answers.
_TYPE_TO_DNS: dict[DnsRecordType, str] = {
    DnsRecordType.A: "A",
    DnsRecordType.AAAA: "AAAA",
    DnsRecordType.CNAME: "CNAME",
    DnsRecordType.MX: "MX",
    DnsRecordType.NS: "NS",
    DnsRecordType.TXT: "TXT",
    DnsRecordType.SOA: "SOA",
    DnsRecordType.PTR: "PTR",
    DnsRecordType.SRV: "SRV",
    DnsRecordType.CAA: "CAA",
    DnsRecordType.DS: "DS",
    DnsRecordType.DNSKEY: "DNSKEY",
    DnsRecordType.TLSA: "TLSA",
    DnsRecordType.NAPTR: "NAPTR",
}


class DnspythonAdapter(DnsToolAdapter):
    """SDK adapter performing active resolution with dnspython.

    The adapter exposes a ``descriptor`` for registration and an execution
    lifecycle so it participates in the standard pipeline, but ``run`` performs
    in-process resolution rather than a subprocess invocation.
    """

    descriptor = ToolDescriptor(
        name="dnspython",
        version=_VERSION,
        description="Active DNS resolution through the dnspython library.",
        entrypoint="hunterx.tools.dns.dnspython:DnspythonAdapter",
        targets=("domain", "host", "ip"),
        capabilities=("dns-records", "dns-resolution", "dnssec"),
        permissions=("network",),
        parameters={
            "record_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Record types to resolve (default: A, AAAA, MX, NS, TXT, SOA, CAA).",
            },
            "resolvers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Resolver addresses to query through.",
            },
            "timeout": {
                "type": "integer",
                "description": "Per-query timeout in seconds.",
            },
            "lifetime": {
                "type": "integer",
                "description": "Total lifetime for one query in seconds.",
            },
        },
    )

    def __init__(self, resolve: Callable[..., list[DnsRecord]] | None = None) -> None:
        super().__init__()
        self._resolve = resolve

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """No CLI; returns an empty command line for the descriptor contract."""
        return []

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Resolve the target through dnspython and emit DNS records."""
        from hunterx.tools.dns.resolver import ResolverClient

        record_types = _selected_types(context)
        resolvers = _selected_resolvers(context)
        timeout = self._param_int(context, "timeout", 0) or 3
        lifetime = self._param_int(context, "lifetime", 0) or 8
        client = ResolverClient(resolvers=resolvers, timeout_s=timeout, lifetime_s=lifetime)
        client.resolve = self._resolve if self._resolve is not None else client.resolve
        records: list[DnsRecord] = []
        for record_type in record_types:
            records.extend(client.resolve_type(context.target, record_type, tool_id="dnspython"))
        collector.set_exit_code(0)
        collector.set_json(self._payload(records))

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DnsRecord]:
        """Unused for the in-process adapter; returns no records."""
        return []


def _selected_types(context: ExecutionContext) -> list[DnsRecordType]:
    """Resolve the record types to query for an execution."""
    requested = context.parameters.get("record_types")
    if isinstance(requested, (list, tuple)) and requested:
        types = []
        for value in requested:
            try:
                record_type = DnsRecordType(str(value).upper())
            except ValueError:
                continue
            if record_type in _TYPE_TO_DNS:
                types.append(record_type)
        return types or [DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.MX]
    return [DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.MX, DnsRecordType.NS, DnsRecordType.TXT]


def _selected_resolvers(context: ExecutionContext) -> list[str]:
    """Resolve the resolver addresses for an execution."""
    resolvers = context.parameters.get("resolvers")
    if isinstance(resolvers, (list, tuple)) and resolvers:
        return [str(resolver) for resolver in resolvers]
    return []
