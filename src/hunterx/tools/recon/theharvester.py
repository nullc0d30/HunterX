# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""theHarvester tool adapter.

Integrates ``theHarvester`` — a passive OSINT email/subdomain/IP collector —
into the Tool Integration SDK. The adapter drives the search across the
configured sources, reads the JSON result file the tool writes and maps
hosts, IPs and interesting URLs onto canonical discovery records.

CLI contract (verified against theHarvester usage):
    ``theHarvester -d <domain> -b <sources> -l <limit> -f <base>`` writes
    ``<base>.json`` with ``{"emails", "hosts", "ips", "interesting_urls"}``;
    ``hosts`` entries are ``"host: ip"`` strings.
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

_VERSION = "4.3.0"

_DEFAULT_SOURCES = (
    "baidu,bing,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,intelx,"
    "netcraft,otx,rapiddns,threatcrowd,threatminer,urlscan,virustotal"
)


class TheHarvesterAdapter(ReconToolAdapter):
    """SDK adapter for the ``theHarvester`` OSINT collector."""

    descriptor = ToolDescriptor(
        name="theharvester",
        version=_VERSION,
        description="Passive OSINT collection of hosts, IPs and exposed assets.",
        entrypoint="hunterx.tools.recon.theharvester:TheHarvesterAdapter",
        targets=("domain",),
        capabilities=("host-discovery",),
        permissions=("network",),
        parameters={
            "sources": {
                "type": "string",
                "description": "Comma-separated search sources (default: curated set).",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum results per source.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``theHarvester`` command line for ``context``."""
        sources = context.parameters.get("sources")
        source_csv = str(sources) if isinstance(sources, str) and sources else _DEFAULT_SOURCES
        limit = self._param_int(context, "limit", 500)
        argv = ["theHarvester", "-d", context.target, "-b", source_csv, "-l", str(limit)]
        base = self._output_base(context)
        os.makedirs(os.path.dirname(base), exist_ok=True)
        argv += ["-f", base]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DiscoveryRecord]:
        """Parse the theHarvester JSON result file into discovery records."""
        payload = _read_json(self._output_base(context) + ".json")
        if not payload:
            return []
        records: list[DiscoveryRecord] = []
        hosts = payload.get("hosts")
        if isinstance(hosts, list):
            for host_entry in hosts:
                host, _, address = str(host_entry).partition(":")
                host = host.strip()
                address = address.strip()
                if host:
                    records.append(discovery_record(DiscoveryKind.HOSTNAME, host, "theharvester", context))
                if address:
                    records.append(
                        discovery_record(
                            DiscoveryKind.IP_ADDRESS,
                            address,
                            "theharvester",
                            context,
                            details={"ip_version": infer_ip_version(address)},
                        )
                    )
        ips = payload.get("ips")
        if isinstance(ips, list):
            for ip in ips:
                ip = str(ip).strip()
                if ip:
                    records.append(
                        discovery_record(
                            DiscoveryKind.IP_ADDRESS,
                            ip,
                            "theharvester",
                            context,
                            details={"ip_version": infer_ip_version(ip)},
                        )
                    )
        urls = payload.get("interesting_urls")
        if isinstance(urls, list):
            for url in urls:
                url = str(url).strip()
                if url:
                    records.append(discovery_record(DiscoveryKind.EXPOSED_ASSET, url, "theharvester", context))
        return records

    @staticmethod
    def _output_base(context: ExecutionContext) -> str:
        """Return the deterministic result-file base path for an execution."""
        base = context.output_directory or context.temp_directory or tempfile.gettempdir()
        os.makedirs(base, exist_ok=True)
        return os.path.join(base, f"theharvester-{context.execution_id}")


def _read_json(path: str) -> dict[str, object] | None:
    """Return parsed JSON from ``path``, or ``None`` when unreadable."""
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None
