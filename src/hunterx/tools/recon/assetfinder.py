# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Assetfinder tool adapter.

Integrates tomnomnom's ``assetfinder`` — a minimal passive subdomain/domain
finder backed by certificate transparency and passive DNS sources — into the
Tool Integration SDK.

CLI contract (verified against the assetfinder README):
    ``assetfinder [--subs-only] <domain>`` prints one hostname per line to
    stdout. The ``-subs-only`` flag restricts results to subdomains.
"""

from __future__ import annotations

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.recon.models import DiscoveryKind, DiscoveryRecord
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.base import ReconToolAdapter, discovery_record
from hunterx.tools.recon.runner import CommandResult, guard_positional_target

_VERSION = "0.4.0"


class AssetfinderAdapter(ReconToolAdapter):
    """SDK adapter for the ``assetfinder`` passive asset finder."""

    descriptor = ToolDescriptor(
        name="assetfinder",
        version=_VERSION,
        description="Passive discovery of domains and subdomains via CT logs and DNS sources.",
        entrypoint="hunterx.tools.recon.assetfinder:AssetfinderAdapter",
        targets=("domain",),
        capabilities=("subdomain-discovery",),
        permissions=("network",),
        parameters={
            "subs_only": {
                "type": "boolean",
                "description": "Return only subdomains (omit the parent domain).",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``assetfinder`` command line for ``context``."""
        argv: list[str] = ["assetfinder"]
        if bool(context.parameters.get("subs_only")):
            argv.append("--subs-only")
        argv.append(guard_positional_target(context.target, label="assetfinder target"))
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DiscoveryRecord]:
        """Parse the plain hostname list into discovery records."""
        records: list[DiscoveryRecord] = []
        target = context.target.strip().lower()
        for line in result.stdout.splitlines():
            name = line.strip().lower()
            if not name or " " in name:
                continue
            kind = DiscoveryKind.DOMAIN if name == target else DiscoveryKind.SUBDOMAIN
            records.append(discovery_record(kind, name, "assetfinder", context))
        return records
