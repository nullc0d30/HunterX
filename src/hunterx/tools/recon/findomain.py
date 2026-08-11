# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Findomain tool adapter.

Integrates ``findomain`` — a cross-platform subdomain enumerator using CT logs,
passive DNS and (optionally) wordlist brute force — into the Tool Integration
SDK.

CLI contract (verified against findomain usage):
    ``findomain -t <domain> -q`` prints one subdomain per line to stdout.
    ``-i`` also resolves and reports IPs, ``-w <file>`` enables brute force.
"""

from __future__ import annotations

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.recon.models import DiscoveryKind, DiscoveryRecord, infer_ip_version
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.base import ReconToolAdapter, discovery_record
from hunterx.tools.recon.runner import CommandResult

_VERSION = "9.0.1"


class FindomainAdapter(ReconToolAdapter):
    """SDK adapter for the ``findomain`` subdomain enumerator."""

    descriptor = ToolDescriptor(
        name="findomain",
        version=_VERSION,
        description="Subdomain discovery from certificate transparency and passive DNS.",
        entrypoint="hunterx.tools.recon.findomain:FindomainAdapter",
        targets=("domain",),
        capabilities=("subdomain-discovery",),
        permissions=("network",),
        parameters={
            "get_ip": {
                "type": "boolean",
                "description": "Resolve discovered subdomains and report IPs.",
            },
            "resolved": {
                "type": "boolean",
                "description": "Only output resolved (live) subdomains.",
            },
            "wordlist": {
                "type": "string",
                "description": "Wordlist path to enable brute-force discovery.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``findomain`` command line for ``context``."""
        argv = ["findomain", "-t", context.target, "-q"]
        if bool(context.parameters.get("get_ip")):
            argv.append("-i")
        if bool(context.parameters.get("resolved")):
            argv.append("-r")
        wordlist = context.parameters.get("wordlist")
        if isinstance(wordlist, str) and wordlist:
            argv += ["-w", wordlist]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DiscoveryRecord]:
        """Parse the findomain output into discovery records."""
        records: list[DiscoveryRecord] = []
        target = context.target.strip().lower()
        for line in result.stdout.splitlines():
            line = line.strip().lower()
            if not line or " " in line:
                continue
            if ":" in line and not _is_ip(line):
                host, _, address = line.partition(":")
                if _is_ip(address) and _looks_like_host(host):
                    records.append(discovery_record(_host_kind(host, target), host, "findomain", context))
                    records.append(
                        discovery_record(
                            DiscoveryKind.IP_ADDRESS,
                            address,
                            "findomain",
                            context,
                            details={"ip_version": infer_ip_version(address)},
                        )
                    )
                    continue
            records.append(discovery_record(_host_kind(line, target), line, "findomain", context))
        return records


def _host_kind(name: str, target: str) -> DiscoveryKind:
    """Classify a hostname as the scope domain or a subdomain."""
    return DiscoveryKind.DOMAIN if name == target else DiscoveryKind.SUBDOMAIN


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _looks_like_host(value: str) -> bool:
    return "." in value and " " not in value
