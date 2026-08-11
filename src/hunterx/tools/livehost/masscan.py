# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Masscan tool adapter.

Integrates ``masscan`` — the high-throughput SYN scanner — into the Tool
Integration SDK. The adapter builds the CLI command from the execution context
(target, ports, rate, protocol), parses the JSON output (``{"ip", "timestamp",
"ports": [{"port", "proto", "status", "reason"}]}``) into canonical
:class:`LiveHost` and :class:`PortFinding` observations and publishes them on
the execution output.

CLI contract (verified against Masscan docs):
    ``masscan <target> -p <ports> --rate <n> --output-format json --output-file -``
    emits one JSON object per host; each object lists the discovered ports.
    SYN scanning requires root/raw-socket privileges.
"""

from __future__ import annotations

import json

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.livehost.models import (
    DEFAULT_TOP_PORTS,
    HostState,
    PortState,
    ReachabilityMethod,
    TransportProtocol,
    make_host,
    make_port,
)
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.livehost.base import LiveToolAdapter
from hunterx.tools.recon.runner import CommandResult, guard_positional_target

_VERSION = "1.3.2"


class MasscanAdapter(LiveToolAdapter):
    """SDK adapter for the ``masscan`` high-throughput SYN scanner."""

    descriptor = ToolDescriptor(
        name="masscan",
        version=_VERSION,
        description="High-throughput TCP port scanner for large address ranges.",
        entrypoint="hunterx.tools.livehost.masscan:MasscanAdapter",
        targets=("ip", "cidr"),
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
                "enum": ["tcp", "udp"],
                "description": "Transport protocol to scan (SYN default; UDP with -sU).",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum packets per second.",
            },
            "adapter": {
                "type": "string",
                "description": "Source adapter/interface used for the scan.",
            },
            "source_port": {
                "type": "integer",
                "description": "Source port to use for the scan.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``masscan`` command line for ``context``."""
        argv = ["masscan", guard_positional_target(context.target, label="masscan target")]
        ports = self._param_ports(context, DEFAULT_TOP_PORTS)
        protocol = str(context.parameters.get("protocol") or "tcp").lower()
        if protocol == "udp":
            argv.append("-sU")
        if ports:
            argv += ["-p", ",".join(str(port) for port in ports)]
        rate_limit = self._param_int(context, "rate_limit", 0)
        if rate_limit > 0:
            argv += ["--rate", str(rate_limit)]
        adapter = context.parameters.get("adapter")
        if adapter:
            argv += ["--adapter", str(adapter)]
        source_port = self._param_int(context, "source_port", 0)
        if source_port > 0:
            argv += ["--source-port", str(source_port)]
        argv += ["--output-format", "json", "--output-file", "-"]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[object]:
        """Parse Masscan JSON output into canonical observations."""
        observations: list[object] = []
        target_id = self._target_id(context)
        seen_addresses: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            address, ports = _parse_json_line(line)
            if not address:
                continue
            if address not in seen_addresses:
                seen_addresses.add(address)
                observations.append(
                    make_host(
                        address,
                        state=HostState.REACHABLE,
                        reachable=True,
                        methods=(ReachabilityMethod.TCP_SYN,),
                        tool_id="masscan",
                        source="masscan",
                        target_id=target_id,
                        execution_id=context.execution_id,
                        correlation_id=context.correlation_id,
                    )
                )
            for port, protocol, state in ports:
                observations.append(
                    make_port(
                        address,
                        port,
                        protocol=protocol,
                        state=state,
                        reason="syn-ack" if state is PortState.OPEN else "reset",
                        tool_id="masscan",
                        source="masscan",
                        target_id=target_id,
                        execution_id=context.execution_id,
                        correlation_id=context.correlation_id,
                    )
                )
        return observations


def _parse_json_line(line: str) -> tuple[str, list[tuple[int, TransportProtocol, PortState]]]:
    """Parse one Masscan JSON host into ``(address, [(port, protocol, state)])``."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return "", []
    if not isinstance(payload, dict):
        return "", []
    address = str(payload.get("ip") or "").strip()
    if not address:
        return "", []
    ports: list[tuple[int, TransportProtocol, PortState]] = []
    raw_ports = payload.get("ports")
    if isinstance(raw_ports, list):
        for entry in raw_ports:
            if not isinstance(entry, dict):
                continue
            raw_port = entry.get("port")
            if raw_port is None:
                continue
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if not 1 <= port <= 65535:
                continue
            protocol = _parse_protocol(entry.get("proto"))
            state = _parse_state(entry.get("status"))
            ports.append((port, protocol, state))
    return address, ports


def _parse_protocol(value: object) -> TransportProtocol:
    try:
        return TransportProtocol(str(value or "tcp").lower())
    except ValueError:
        return TransportProtocol.TCP


def _parse_state(value: object) -> PortState:
    status = str(value or "unknown").lower()
    if status in ("open", "open|filtered"):
        return PortState.OPEN
    if status == "closed":
        return PortState.CLOSED
    if status in ("filtered", "admin-prohibited"):
        return PortState.FILTERED
    if status == "unfiltered":
        return PortState.UNFILTERED
    return PortState.UNKNOWN
