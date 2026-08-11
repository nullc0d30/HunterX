# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""BBOT tool adapter.

Integrates Black Lantern Security's ``bbot`` — a modular recursive OSINT
framework — into the Tool Integration SDK. The adapter drives the
``subdomain-enum`` preset, captures the NDJSON event stream and maps bbot
event types (``DNS_NAME``, ``IP_ADDRESS``, ``IP_NETWORK``, ``ASN``, ``ORG``,
``URL``) onto canonical discovery records.

CLI contract (verified against bbot usage):
    ``bbot -t <domain> -f subdomain-enum --json -n <name> -o <dir> [-rf passive]``
    prints one JSON event per line to stdout.
"""

from __future__ import annotations

import json
import os
import tempfile

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.recon.models import DiscoveryKind, DiscoveryRecord, infer_ip_version
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.base import ReconToolAdapter, discovery_record
from hunterx.tools.recon.runner import CommandResult

_VERSION = "2.3.0"


class BbotAdapter(ReconToolAdapter):
    """SDK adapter for the ``bbot`` reconnaissance framework."""

    descriptor = ToolDescriptor(
        name="bbot",
        version=_VERSION,
        description="Modular, recursive attack surface discovery with passive and active modules.",
        entrypoint="hunterx.tools.recon.bbot:BbotAdapter",
        targets=("domain",),
        capabilities=("subdomain-discovery", "host-discovery"),
        permissions=("network",),
        parameters={
            "mode": {
                "type": "string",
                "enum": ["passive", "active", "hybrid"],
                "description": "Restrict bbot to passive, active or all modules.",
            },
            "modules": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra bbot modules to enable.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``bbot`` command line for ``context``."""
        mode = str(context.parameters.get("mode") or "hybrid").lower()
        argv = [
            "bbot",
            "-t",
            context.target,
            "-f",
            "subdomain-enum",
            "--json",
            "-n",
            f"hx-{context.execution_id}",
            "-o",
            self._output_path(context),
        ]
        if mode == "passive":
            argv += ["-rf", "passive"]
        elif mode == "active":
            argv += ["-rf", "active"]
        modules = context.parameters.get("modules")
        if isinstance(modules, (list, tuple)) and modules:
            argv += ["-m", ",".join(str(module) for module in modules)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DiscoveryRecord]:
        """Parse the bbot NDJSON event stream into discovery records."""
        records: list[DiscoveryRecord] = []
        target = context.target.strip().lower()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.extend(_parse_event(payload, context, target))
        return records

    @staticmethod
    def _output_path(context: ExecutionContext) -> str:
        """Return a deterministic per-execution output directory."""
        base = context.output_directory or context.temp_directory or tempfile.gettempdir()
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, f"bbot-{context.execution_id}")


def _parse_event(payload: dict[str, object], context: ExecutionContext, target: str) -> list[DiscoveryRecord]:
    event_type = str(payload.get("type") or "").upper()
    data = str(payload.get("data") or "").strip()
    source = str(payload.get("source") or "")
    if not data:
        return []
    if event_type == "DNS_NAME":
        kind = DiscoveryKind.DOMAIN if data.lower() == target else DiscoveryKind.SUBDOMAIN
        return [discovery_record(kind, data, "bbot", context, source=source)]
    if event_type == "IP_ADDRESS":
        return [
            discovery_record(
                DiscoveryKind.IP_ADDRESS,
                data,
                "bbot",
                context,
                source=source,
                details={"ip_version": infer_ip_version(data)},
            )
        ]
    if event_type == "IP_NETWORK":
        return [discovery_record(DiscoveryKind.CIDR, data, "bbot", context, source=source)]
    if event_type == "ASN":
        return [_asn_record(data, context, source)]
    if event_type == "ORG":
        return [discovery_record(DiscoveryKind.ORGANIZATION, data, "bbot", context, source=source)]
    if event_type == "URL":
        return [discovery_record(DiscoveryKind.EXPOSED_ASSET, data, "bbot", context, source=source)]
    return []


def _asn_record(data: str, context: ExecutionContext, source: str) -> DiscoveryRecord:
    number = _asn_number(data)
    return discovery_record(
        DiscoveryKind.ASN,
        f"AS{number}" if number else data,
        "bbot",
        context,
        source=source,
        details={"number": number} if number else {},
    )


def _asn_number(value: str) -> int:
    candidate = value.removeprefix("AS").removeprefix("as")
    try:
        return int(candidate)
    except ValueError:
        return 0
