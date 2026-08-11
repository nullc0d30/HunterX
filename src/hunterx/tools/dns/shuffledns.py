# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shuffledns tool adapter.

Integrates ProjectDiscovery's ``shuffledns`` — a wrapper around massdns for
fast brute-forcing of DNS subdomains — into the Tool Integration SDK. The
adapter writes the target domain list to a per-execution scratch file, invokes
the binary through the shared runner seam and parses the JSONL output
(``{"host", "ip", "type", "source"}``) into canonical :class:`DnsRecord`
instances.

``shuffledns -d <domain> -r <resolvers> -w <wordlist> -o J`` emits JSONL; the
wordlist is treated strictly as data, never executed.
"""

from __future__ import annotations

import json
import pathlib

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, make_record
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.dns.base import DnsToolAdapter
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.sdk.output import OutputCollector

_VERSION = "1.0.9"


class ShufflednsAdapter(DnsToolAdapter):
    """SDK adapter for the ``shuffledns`` brute-force DNS wrapper."""

    descriptor = ToolDescriptor(
        name="shuffledns",
        version=_VERSION,
        description="Fast subdomain brute-forcing wrapper around massdns.",
        entrypoint="hunterx.tools.dns.shuffledns:ShufflednsAdapter",
        targets=("domain",),
        capabilities=("brute-force-dns", "subdomain-discovery", "dns-resolution"),
        permissions=("network",),
        parameters={
            "wordlist": {
                "type": "string",
                "description": "Path to the subdomain wordlist (required).",
            },
            "resolvers": {
                "type": "string",
                "description": "Comma-separated resolver IPs.",
            },
            "threads": {
                "type": "integer",
                "description": "Concurrent resolution threads.",
            },
            "wildcard": {
                "type": "boolean",
                "description": "Perform wildcard filtering.",
            },
        },
    )

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke shuffledns with a scratch resolver file and emit records."""
        resolvers = _resolver_string(context)
        resolver_path = _write_resolvers(context, resolvers)
        argv = self.build_argv(context, resolver_path)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        records = self.parse_output(context, result)
        collector.set_json(self._payload(records))

    def build_argv(self, context: ExecutionContext, resolver_path: str = "") -> list[str]:
        """Build the ``shuffledns`` command line for ``context``."""
        target = str(context.target).strip()
        wordlist = context.parameters.get("wordlist")
        if not isinstance(wordlist, str) or not wordlist:
            raise ValueError("shuffledns requires a 'wordlist' parameter")
        argv = [
            "shuffledns",
            "-d",
            target,
            "-r",
            resolver_path,
            "-w",
            wordlist,
            "-o",
            "J",
        ]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        if bool(context.parameters.get("wildcard")):
            argv.append("-wildcard")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DnsRecord]:
        """Parse shuffledns JSONL output into canonical DNS records."""
        records: list[DnsRecord] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            records.extend(_parse_json_line(line, context))
        return records


def _parse_json_line(line: str, context: ExecutionContext) -> list[DnsRecord]:
    """Parse one shuffledns JSONL record."""
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    host = str(payload.get("host") or "").strip()
    if not host:
        return []
    ip = str(payload.get("ip") or "").strip()
    record_type = _coerce_type(payload.get("type"))
    source = str(payload.get("source") or "shuffledns")
    target_id = context.parameters.get("target_id") if isinstance(context.parameters.get("target_id"), str) else None
    return [
        make_record(
            host,
            record_type,
            ip,
            source=source,
            tool_id="shuffledns",
            resolver="",
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
            target_id=target_id,
        )
    ]


def _coerce_type(value: object) -> DnsRecordType:
    name = str(value or "A").strip().upper()
    try:
        return DnsRecordType(name)
    except ValueError:
        return DnsRecordType.A


def _resolver_string(context: ExecutionContext) -> str:
    value = context.parameters.get("resolvers")
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (list, tuple)) and value:
        return ",".join(str(item) for item in value)
    return "8.8.8.8,1.1.1.1"


def _write_resolvers(context: ExecutionContext, resolvers: str) -> str:
    base = context.temp_directory or context.working_directory or "."
    path = pathlib.Path(base) / f"shuffledns-resolvers-{context.execution_id}.txt"
    lines = "\n".join(item for item in resolvers.split(",") if item.strip())
    path.write_text(lines + "\n", encoding="utf-8")
    return str(path)


__all__ = ["ShufflednsAdapter"]
