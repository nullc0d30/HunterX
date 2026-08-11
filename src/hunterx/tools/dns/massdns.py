# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""MassDNS tool adapter.

Integrates ``massdns`` — a high-performance DNS stub resolver for bulk
subdomain resolution — into the Tool Integration SDK. The adapter writes the
target domain list to a per-execution scratch file, invokes the binary through
the shared :class:`~hunterx.tools.recon.runner.BinaryRunner` seam with JSON
output (``-o J``) and parses the answers into canonical :class:`DnsRecord`
instances.

Bulk resolver tools read a domain list; a single target domain is expanded
into a one-entry list. Resolution output is a candidate observation, never a
validated finding.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, make_record
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.dns.base import DnsToolAdapter
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.sdk.output import OutputCollector

_VERSION = "1.4.0"

_DEFAULT_RESOLVERS = "8.8.8.8,1.1.1.1"


class MassdnsAdapter(DnsToolAdapter):
    """SDK adapter for the ``massdns`` bulk DNS resolver."""

    descriptor = ToolDescriptor(
        name="massdns",
        version=_VERSION,
        description="High-performance DNS stub resolver for bulk subdomain resolution.",
        entrypoint="hunterx.tools.dns.massdns:MassdnsAdapter",
        targets=("domain",),
        capabilities=("brute-force-dns", "dns-records", "dns-resolution"),
        permissions=("network",),
        parameters={
            "domains": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Domain list to resolve (defaults to the target).",
            },
            "resolvers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Resolver IPs (comma separated on the CLI).",
            },
            "record_type": {
                "type": "string",
                "description": "Record type to query (default A).",
            },
            "queries_per_second": {
                "type": "integer",
                "description": "Maximum queries per second.",
            },
            "threads": {
                "type": "integer",
                "description": "Number of resolver threads.",
            },
        },
    )

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Write the domain list, invoke massdns and emit DNS records."""
        domains = _domain_list(context)
        if not domains:
            collector.set_exit_code(0)
            collector.set_json(self._payload([]))
            return
        list_path = _write_domains(context, domains)
        argv = self.build_argv(context, list_path)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        records = self.parse_output(context, result)
        collector.set_json(self._payload(records))

    def build_argv(self, context: ExecutionContext, list_path: str = "") -> list[str]:
        """Build the ``massdns`` command line for ``context``."""
        record_type = str(context.parameters.get("record_type") or "A").strip().upper()
        resolvers = _resolver_list(context.parameters.get("resolvers"))
        argv = [
            "massdns",
            "-r",
            ",".join(resolvers),
            "-t",
            record_type,
            "-o",
            "J",
            "-s",
            str(self._param_int(context, "queries_per_second", 1000)),
        ]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-n", str(threads)]
        argv.append(list_path or "-")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DnsRecord]:
        """Parse massdns JSON output into canonical DNS records."""
        records: list[DnsRecord] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                records.extend(_parse_json_line(line, context))
            elif " " in line:
                records.extend(_parse_simple_line(line, context))
        return records


def _parse_json_line(line: str, context: ExecutionContext) -> list[DnsRecord]:
    """Parse one massdns JSON result line."""
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    name = str(payload.get("name") or "").strip().rstrip(".")
    if not name:
        return []
    status = str(payload.get("status") or "").upper()
    if status not in ("NOERROR", "NXDOMAIN") and status:
        return []
    record_type = _coerce_type(payload.get("type"))
    answers = payload.get("data", {}).get("answers") if isinstance(payload.get("data"), dict) else None
    if not isinstance(answers, list):
        return []
    target_id = context.parameters.get("target_id") if isinstance(context.parameters.get("target_id"), str) else None
    records: list[DnsRecord] = []
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        value = str(answer.get("data") or answer.get("name") or "")
        if not value:
            continue
        records.append(
            make_record(
                name,
                _coerce_type(answer.get("type")) if answer.get("type") else record_type,
                value,
                source="massdns",
                tool_id="massdns",
                resolver="",
                execution_id=context.execution_id,
                correlation_id=context.correlation_id,
                target_id=target_id,
            )
        )
    return records


def _parse_simple_line(line: str, context: ExecutionContext) -> list[DnsRecord]:
    """Parse ``name. TYPE value`` simple output."""
    parts = line.split()
    if len(parts) < 3:
        return []
    name = str(parts[0]).strip().rstrip(".")
    record_type = _coerce_type(parts[1])
    value = " ".join(parts[2:])
    target_id = context.parameters.get("target_id") if isinstance(context.parameters.get("target_id"), str) else None
    return [
        make_record(
            name,
            record_type,
            value,
            source="massdns",
            tool_id="massdns",
            resolver="",
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
            target_id=target_id,
        )
    ]


def _coerce_type(value: object) -> DnsRecordType:
    name = str(value or "OTHER").strip().upper()
    try:
        return DnsRecordType(name)
    except ValueError:
        return DnsRecordType.OTHER


def _domain_list(context: ExecutionContext) -> list[str]:
    domains = context.parameters.get("domains")
    if isinstance(domains, (list, tuple)) and domains:
        return [str(domain).strip() for domain in domains if str(domain).strip()]
    target = str(context.target).strip()
    return [target] if target else []


def _resolver_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)) and value:
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value:
        return [item.strip() for item in value.split(",") if item.strip()]
    return [item for item in _DEFAULT_RESOLVERS.split(",")]


def _write_domains(context: ExecutionContext, domains: list[str]) -> str:
    base = context.temp_directory or context.working_directory or "."
    path = pathlib.Path(base) / f"massdns-{context.execution_id}.txt"
    path.write_text("\n".join(domains) + "\n", encoding="utf-8")
    return str(path)


__all__ = ["MassdnsAdapter"]
