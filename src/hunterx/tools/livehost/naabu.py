# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Naabu tool adapter.

Integrates ProjectDiscovery's ``naabu`` — a fast port scanner — into the Tool
Integration SDK. The adapter builds the CLI command from the execution context
(target, ports, protocol, rate controls, concurrency), parses the JSONL output
(``{"host", "port", "protocol", "reason"}``) into canonical
:class:`PortFinding` records and publishes them on the execution output.

CLI contract (verified against ProjectDiscovery docs):
    ``naabu -host <target> -p <ports> -silent -json`` emits one JSON line per
    discovered (open) port; ``-sU`` enables UDP scanning, ``-rate`` limits the
    packet rate and ``-c`` sets concurrency.
"""

from __future__ import annotations

import json

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.livehost.models import (
    DEFAULT_TOP_PORTS,
    PortState,
    TransportProtocol,
    make_port,
)
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.livehost.base import LiveToolAdapter
from hunterx.tools.recon.runner import CommandResult

_VERSION = "2.3.4"


class NaabuAdapter(LiveToolAdapter):
    """SDK adapter for the ``naabu`` fast port scanner."""

    descriptor = ToolDescriptor(
        name="naabu",
        version=_VERSION,
        description="Fast port scanner by ProjectDiscovery with configurable rate control.",
        entrypoint="hunterx.tools.livehost.naabu:NaabuAdapter",
        targets=("ip", "cidr", "host", "domain"),
        capabilities=("host-discovery", "port-scanning"),
        permissions=("network",),
        parameters={
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Ports to probe (default: top well-known ports).",
            },
            "protocol": {
                "type": "string",
                "enum": ["tcp", "udp", "both"],
                "description": "Transport protocol(s) to scan.",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum packets per second.",
            },
            "threads": {
                "type": "integer",
                "description": "Concurrent scan threads.",
            },
            "timeout": {
                "type": "integer",
                "description": "Per-host timeout in milliseconds.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``naabu`` command line for ``context``."""
        argv = ["naabu", "-host", context.target, "-silent", "-json"]
        protocol = str(context.parameters.get("protocol") or "tcp").lower()
        if protocol in ("udp", "both"):
            argv.append("-sU")
        ports = self._param_ports(context, DEFAULT_TOP_PORTS)
        if ports:
            argv += ["-p", ",".join(str(port) for port in ports)]
        rate_limit = self._param_int(context, "rate_limit", 0)
        if rate_limit > 0:
            argv += ["-rate", str(rate_limit)]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-c", str(threads)]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["-timeout", str(timeout)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[object]:
        """Parse naabu JSONL output into canonical port observations."""
        observations: list[object] = []
        target_id = self._target_id(context)
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            finding = _parse_json_line(line)
            if finding is None:
                continue
            address, port, protocol = finding
            observations.append(
                make_port(
                    address,
                    port,
                    protocol=protocol,
                    state=PortState.OPEN,
                    reason="naabu-open",
                    tool_id="naabu",
                    source="naabu",
                    target_id=target_id,
                    execution_id=context.execution_id,
                    correlation_id=context.correlation_id,
                )
            )
        return observations


def _parse_json_line(line: str) -> tuple[str, int, TransportProtocol] | None:
    """Parse one naabu JSON answer into ``(address, port, protocol)``."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    address = str(payload.get("host") or "").strip()
    raw_port = payload.get("port")
    if raw_port is None:
        return None
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        return None
    if not address or not 1 <= port <= 65535:
        return None
    try:
        protocol = TransportProtocol(str(payload.get("protocol") or "tcp").lower())
    except ValueError:
        protocol = TransportProtocol.TCP
    return address, port, protocol
