# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Subfinder tool adapter.

Integrates ProjectDiscovery's ``subfinder`` — a fast, passive subdomain
enumeration tool — into the Tool Integration SDK. The adapter builds the CLI
command from the execution context (mode, sources, rate limits), parses the
JSONL output (``{"host", "ip", "source"}``) into canonical discovery records and
publishes them on the execution output.

CLI contract (verified against ProjectDiscovery docs):
    ``subfinder -d <domain> -silent -oJ -cs`` emits JSONL to stdout; adding
    ``-nW -oI`` enables active resolution and includes resolved IP addresses.
"""

from __future__ import annotations

import json

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.recon.models import DiscoveryKind, DiscoveryRecord, infer_ip_version
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.base import ReconToolAdapter, discovery_record
from hunterx.tools.recon.runner import CommandResult

_VERSION = "2.14.0"


class SubfinderAdapter(ReconToolAdapter):
    """SDK adapter for the ``subfinder`` passive subdomain tool."""

    descriptor = ToolDescriptor(
        name="subfinder",
        version=_VERSION,
        description="Passive subdomain enumeration from curated online sources.",
        entrypoint="hunterx.tools.recon.subfinder:SubfinderAdapter",
        targets=("domain",),
        capabilities=("subdomain-discovery", "host-discovery"),
        permissions=("network",),
        parameters={
            "sources": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific passive sources to use (e.g. crtsh,github).",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum HTTP requests per second.",
            },
            "threads": {
                "type": "integer",
                "description": "Concurrent goroutines for active resolution.",
            },
            "resolvers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Comma separated custom resolvers.",
            },
            "max_time": {
                "type": "integer",
                "description": "Maximum minutes to wait for enumeration.",
            },
            "active": {
                "type": "boolean",
                "description": "Force active resolution of discovered subdomains.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``subfinder`` command line for ``context``."""
        target = context.target
        mode = str(context.parameters.get("mode") or "hybrid").lower()
        active = bool(context.parameters.get("active")) or mode in {"active", "hybrid"}

        argv = ["subfinder", "-d", target, "-silent", "-oJ", "-cs"]
        if active:
            argv += ["-nW", "-oI"]
            threads = self._param_int(context, "threads", 10)
            if threads > 0:
                argv += ["-t", str(threads)]
        rate_limit = self._param_int(context, "rate_limit", 0)
        if rate_limit > 0:
            argv += ["-rl", str(rate_limit)]
        max_time = self._param_int(context, "max_time", 0)
        if max_time > 0:
            argv += ["-max-time", str(max_time)]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["-timeout", str(timeout)]
        sources = context.parameters.get("sources")
        if isinstance(sources, (list, tuple)) and sources:
            argv += ["-s", ",".join(str(source) for source in sources)]
        resolvers = context.parameters.get("resolvers")
        if isinstance(resolvers, (list, tuple)) and resolvers:
            argv += ["-r", ",".join(str(resolver) for resolver in resolvers)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DiscoveryRecord]:
        """Parse subfinder JSONL output into discovery records."""
        records: list[DiscoveryRecord] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith(("{", "[")):
                records.extend(_parse_json_line(line, context))
            else:
                records.extend(_parse_plain_line(line, context))
        return records


def _parse_json_line(line: str, context: ExecutionContext) -> list[DiscoveryRecord]:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    host = str(payload.get("host") or "").strip()
    if not host:
        return []
    source = str(payload.get("source") or "")
    records = [discovery_record(DiscoveryKind.SUBDOMAIN, host, "subfinder", context, source=source)]
    ip = str(payload.get("ip") or "").strip()
    if ip:
        records.append(
            discovery_record(
                DiscoveryKind.IP_ADDRESS,
                ip,
                "subfinder",
                context,
                source=source,
                details={"ip_version": infer_ip_version(ip)},
            )
        )
    return records


def _parse_plain_line(line: str, context: ExecutionContext) -> list[DiscoveryRecord]:
    if " " in line:
        return []
    return [discovery_record(DiscoveryKind.SUBDOMAIN, line, "subfinder", context)]
