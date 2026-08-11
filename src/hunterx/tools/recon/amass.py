# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Amass tool adapter.

Integrates OWASP ``amass`` (v4 interface: ``amass enum``) into the Tool
Integration SDK. The adapter drives ``amass enum`` in passive or active mode,
captures the JSONL event stream to a per-execution file and parses it into
canonical discovery records (subdomains, IP addresses, CIDR ranges).

CLI contract (verified against OWASP amass v4 docs):
    ``amass enum -passive -d <domain> -json <file>`` writes JSONL events; the
    event stream carries ``name``, ``domain``, ``addresses`` and an
    ``event_type`` (``subdomain``, ``address``, ``cidr``).
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

_VERSION = "4.2.0"


class AmassAdapter(ReconToolAdapter):
    """SDK adapter for the OWASP ``amass`` enumeration tool."""

    descriptor = ToolDescriptor(
        name="amass",
        version=_VERSION,
        description="In-depth external attack surface mapping and enumeration.",
        entrypoint="hunterx.tools.recon.amass:AmassAdapter",
        targets=("domain",),
        capabilities=("subdomain-discovery", "host-discovery"),
        permissions=("network",),
        parameters={
            "mode": {
                "type": "string",
                "enum": ["passive", "active"],
                "description": "Passive (default) or active discovery methods.",
            },
            "timeout_minutes": {
                "type": "integer",
                "description": "Maximum minutes to allow enumeration to run.",
            },
            "wordlist": {
                "type": "string",
                "description": "Wordlist for active brute forcing.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``amass enum`` command line for ``context``."""
        mode = str(context.parameters.get("mode") or "passive").lower()
        passive = mode == "passive"
        argv = ["amass", "enum", "-passive" if passive else "-active", "-d", context.target]
        minutes = self._param_int(context, "timeout_minutes", 10)
        if minutes > 0:
            argv += ["-timeout", str(minutes)]
        wordlist = context.parameters.get("wordlist")
        if isinstance(wordlist, str) and wordlist:
            argv += ["-w", wordlist]
        argv += ["-json", self._output_path(context)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DiscoveryRecord]:
        """Parse the amass JSONL event stream into discovery records."""
        records: list[DiscoveryRecord] = []
        stream = _read_output(self._output_path(context))
        if not stream:
            stream = result.stdout
        for line in stream.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            records.extend(_parse_event(line, context))
        return records

    @staticmethod
    def _output_path(context: ExecutionContext) -> str:
        """Return a deterministic per-execution JSON output path."""
        base = context.output_directory or context.temp_directory or tempfile.gettempdir()
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, f"amass-{context.execution_id}.json")


def _parse_event(line: str, context: ExecutionContext) -> list[DiscoveryRecord]:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    name = str(payload.get("name") or "").strip()
    event_type = str(payload.get("event_type") or payload.get("type") or "").lower()
    records: list[DiscoveryRecord] = []
    if name and event_type in {"subdomain", "domain", ""}:
        kind = DiscoveryKind.DOMAIN if "." in name and event_type == "domain" else DiscoveryKind.SUBDOMAIN
        records.append(discovery_record(kind, name, "amass", context))
    if event_type in {"address", "ip", "ip-address"} and name:
        records.append(
            discovery_record(
                DiscoveryKind.IP_ADDRESS,
                name,
                "amass",
                context,
                details={"ip_version": infer_ip_version(name)},
            )
        )
    if event_type == "cidr" and name:
        records.append(discovery_record(DiscoveryKind.CIDR, name, "amass", context))
    for address in payload.get("addresses") or []:
        address = str(address).strip()
        if address:
            records.append(
                discovery_record(
                    DiscoveryKind.IP_ADDRESS,
                    address,
                    "amass",
                    context,
                    details={"ip_version": infer_ip_version(address)},
                )
            )
    cidr = payload.get("cidr")
    if cidr and str(cidr).strip():
        records.append(discovery_record(DiscoveryKind.CIDR, str(cidr).strip(), "amass", context))
    return records


def _read_output(path: str) -> str:
    """Return the file contents, or an empty string when unreadable."""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""
