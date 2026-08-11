# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Traceroute tool adapter.

Integrates ``traceroute``/``tracepath`` into the Tool Integration SDK. The
adapter builds the CLI command (numeric output by default), parses the plain
text hop lines into canonical :class:`RouteRecord` instances and serializes
them under the pipeline payload's ``routes`` key. The topology service converts
consecutive hops into ``routes_to`` relationships.

Text contract (verified against ``traceroute -n`` output):
    Header lines are ignored; hop lines look like `` N  <addr>  <rtt> ms ...``
    or `` N  * * *``. Addresses are IPs when ``-n`` is used; hostnames may
    appear with the IP in parentheses otherwise.
"""

from __future__ import annotations

import re

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult, guard_positional_target
from hunterx.tools.topology.base import TopologyToolAdapter
from hunterx.tools.topology.models import RouteRecord

_VERSION = "2.1.0"

#: `` 1  192.168.1.1  0.5 ms  0.4 ms  0.4 ms`` / `` 1  host.example.com (1.2.3.4)  ...``
_HOP_RE = re.compile(
    r"^\s*(?P<hop>\d+)\s+(?P<first>\S+)(?:\s+\((?P<addr>[0-9a-fA-F:.]+)\))?(?P<rest>.*)$"
)
_MS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms")


class TracerouteAdapter(TopologyToolAdapter):
    """SDK adapter for the ``traceroute`` route-mapping tool."""

    descriptor = ToolDescriptor(
        name="traceroute",
        version=_VERSION,
        description="Map the network path (hop-by-hop route) to a target.",
        entrypoint="hunterx.tools.topology.traceroute:TracerouteAdapter",
        targets=("ip", "host", "domain"),
        capabilities=("route-mapping", "network-topology"),
        permissions=("network",),
        parameters={
            "numeric": {
                "type": "boolean",
                "description": "Use numeric addresses only (-n).",
            },
            "max_hops": {
                "type": "integer",
                "description": "Maximum hop count (-m).",
            },
            "first_ttl": {
                "type": "integer",
                "description": "First TTL to start from (-f).",
            },
            "wait": {
                "type": "integer",
                "description": "Seconds to wait per probe (-w).",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``traceroute`` command line for ``context``."""
        argv = ["traceroute"]
        if bool(context.parameters.get("numeric", True)):
            argv.append("-n")
        max_hops = self._param_int(context, "max_hops", 0)
        if max_hops > 0:
            argv += ["-m", str(max_hops)]
        first_ttl = self._param_int(context, "first_ttl", 0)
        if first_ttl > 0:
            argv += ["-f", str(first_ttl)]
        wait = self._param_int(context, "wait", 0)
        if wait > 0:
            argv += ["-w", str(wait)]
        argv.append(guard_positional_target(context.target, label="traceroute target"))
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[RouteRecord]:
        """Parse traceroute hop lines into route records."""
        target = context.target
        records: list[RouteRecord] = []
        for line in (result.stdout or "").splitlines():
            match = _HOP_RE.match(line)
            if not match:
                continue
            hop = int(match.group("hop"))
            first = match.group("first")
            address = match.group("addr")
            if first == "*" and address is None:
                records.append(
                    RouteRecord(target=target, hop=hop, address=None, tool_id=context.tool_id, source="traceroute")
                )
                continue
            if address is None:
                address = first
                hostname = ""
            else:
                hostname = first
            rtts = _MS_RE.findall(match.group("rest") or "")
            rtt_ms = int(float(rtts[0])) if rtts else None
            records.append(
                RouteRecord(
                    target=target,
                    hop=hop,
                    address=address,
                    hostname=hostname or None,
                    rtt_ms=rtt_ms,
                    tool_id=context.tool_id,
                    source="traceroute",
                )
            )
        return records
