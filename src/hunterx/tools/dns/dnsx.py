# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNSx tool adapter.

Integrates ProjectDiscovery's ``dnsx`` — a fast, multi-purpose DNS toolkit —
into the Tool Integration SDK. The adapter builds the CLI command from the
execution context (record types, resolvers, rate controls, concurrency),
parses the JSONL output (``{"host", "type", "ttl", "resp", "resolver"}``)
into canonical :class:`DnsRecord` instances and publishes them on the
execution output.

CLI contract (verified against ProjectDiscovery docs):
    ``dnsx -d <domain> -a -aaaa -cname -mx -ns -txt -soa -ptr -srv -caa
    -ds -dnskey -any -resp -j`` emits one JSON line per answer; ``-r`` sets
    custom resolvers, ``-rl`` rate limits and ``-t`` concurrency.
"""

from __future__ import annotations

import json

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, make_record
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.dns.base import DnsToolAdapter
from hunterx.tools.recon.runner import CommandResult

_VERSION = "1.1.9"

#: dnsx CLI flags per canonical record type.
_TYPE_FLAGS: dict[DnsRecordType, str] = {
    DnsRecordType.A: "-a",
    DnsRecordType.AAAA: "-aaaa",
    DnsRecordType.CNAME: "-cname",
    DnsRecordType.MX: "-mx",
    DnsRecordType.NS: "-ns",
    DnsRecordType.TXT: "-txt",
    DnsRecordType.SOA: "-soa",
    DnsRecordType.PTR: "-ptr",
    DnsRecordType.SRV: "-srv",
    DnsRecordType.CAA: "-caa",
    DnsRecordType.DS: "-ds",
    DnsRecordType.DNSKEY: "-dnskey",
    DnsRecordType.ANY: "-any",
}


class DnsxAdapter(DnsToolAdapter):
    """SDK adapter for the ``dnsx`` DNS toolkit."""

    descriptor = ToolDescriptor(
        name="dnsx",
        version=_VERSION,
        description="Fast and versatile DNS toolkit by ProjectDiscovery.",
        entrypoint="hunterx.tools.dns.dnsx:DnsxAdapter",
        targets=("domain", "host", "ip"),
        capabilities=("dns-records", "dns-resolution", "dnssec"),
        permissions=("network",),
        parameters={
            "record_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Record types to query (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA, DS, DNSKEY).",
            },
            "resolvers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Custom resolvers to query through.",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum queries per second.",
            },
            "threads": {
                "type": "integer",
                "description": "Concurrent queries.",
            },
            "timeout": {
                "type": "integer",
                "description": "Per-query timeout in seconds.",
            },
            "retries": {
                "type": "integer",
                "description": "Retries for failed queries.",
            },
            "wildcard": {
                "type": "boolean",
                "description": "Filter wildcard responses.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``dnsx`` command line for ``context``."""
        target = context.target
        argv = ["dnsx", "-d", target, "-resp", "-j", "-silent"]
        record_types = context.parameters.get("record_types")
        if isinstance(record_types, (list, tuple)) and record_types:
            flags = []
            for record_type in record_types:
                flag = _TYPE_FLAGS.get(_coerce_type(record_type))
                if flag and flag not in flags:
                    flags.append(flag)
            argv += flags
        else:
            argv += ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-ptr"]
        resolvers = context.parameters.get("resolvers")
        if isinstance(resolvers, (list, tuple)) and resolvers:
            argv += ["-r", ",".join(str(resolver) for resolver in resolvers)]
        rate_limit = self._param_int(context, "rate_limit", 0)
        if rate_limit > 0:
            argv += ["-rl", str(rate_limit)]
        threads = self._param_int(context, "threads", 10)
        if threads > 0:
            argv += ["-t", str(threads)]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["-timeout", str(timeout)]
        retries = self._param_int(context, "retries", 0)
        if retries > 0:
            argv += ["-retry", str(retries)]
        if bool(context.parameters.get("wildcard")):
            argv += ["-wd"]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DnsRecord]:
        """Parse dnsx JSONL output into canonical DNS records."""
        records: list[DnsRecord] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                continue
            records.extend(_parse_json_line(line, context))
        return records


def _parse_json_line(line: str, context: ExecutionContext) -> list[DnsRecord]:
    """Parse one dnsx JSON answer into DNS records."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    host = str(payload.get("host") or "").strip()
    if not host:
        return []
    record_type = _coerce_type(payload.get("type"))
    response = payload.get("resp")
    if response is None:
        return []
    ttl = _optional_int(payload.get("ttl"))
    resolver = str(payload.get("resolver") or "")
    source = resolver or str(payload.get("error") or "")
    target_id = context.parameters.get("target_id") if isinstance(context.parameters.get("target_id"), str) else None
    if isinstance(response, list):
        return [
            make_record(
                host,
                record_type,
                str(answer),
                ttl=ttl,
                source=source,
                tool_id="dnsx",
                resolver=resolver,
                execution_id=context.execution_id,
                correlation_id=context.correlation_id,
                target_id=target_id,
            )
            for answer in response
        ]
    return [
        make_record(
            host,
            record_type,
            str(response),
            ttl=ttl,
            source=source,
            tool_id="dnsx",
            resolver=resolver,
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
            target_id=target_id,
        )
    ]


def _coerce_type(value: object) -> DnsRecordType:
    """Coerce a dnsx type string into a canonical :class:`DnsRecordType`."""
    name = str(value or "OTHER").strip().upper()
    try:
        return DnsRecordType(name)
    except ValueError:
        return DnsRecordType.OTHER


def _optional_int(value: object) -> int | None:
    """Return an int value or ``None`` when not numeric."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
