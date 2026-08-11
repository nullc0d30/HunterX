# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""RustScan tool adapter.

Integrates ``rustscan`` — an ultra-fast port scanner written in Rust — into the
Tool Integration SDK. The adapter builds the CLI command from the execution
context (target, port range, batches, ulimit) and parses the ``--json`` output
(``{"host", "port", "proto"}``) into canonical :class:`PortFinding` records.

RustScan is a discovery tool: an open port is an observation that must be
confirmed and fingerprinted before it becomes a service finding.
"""

from __future__ import annotations

import json

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.livehost.models import (
    PortState,
    TransportProtocol,
    make_port,
)
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.livehost.base import LiveToolAdapter
from hunterx.tools.recon.runner import CommandResult

_VERSION = "2.2.1"


class RustScanAdapter(LiveToolAdapter):
    """SDK adapter for the ``rustscan`` fast port scanner."""

    descriptor = ToolDescriptor(
        name="rustscan",
        version=_VERSION,
        description="Ultra-fast port scanner (Rust) with batching and greppable/JSON output.",
        entrypoint="hunterx.tools.livehost.rustscan:RustScanAdapter",
        targets=("ip", "cidr", "host", "domain"),
        capabilities=("host-discovery", "port-scanning"),
        permissions=("network",),
        parameters={
            "ports": {
                "type": "string",
                "description": "Port range(s) to scan (e.g. 80,443 or 1-1000).",
            },
            "threads": {
                "type": "integer",
                "description": "Number of threads per batch.",
            },
            "batches": {
                "type": "integer",
                "description": "Number of target batches.",
            },
            "timeout": {
                "type": "integer",
                "description": "Connection timeout in milliseconds.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``rustscan`` command line for ``context``."""
        argv = ["rustscan", "-a", context.target, "--json", "-b"]
        batches = self._param_int(context, "batches", 0)
        argv.append(str(batches) if batches > 0 else "1500")
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["--timeout", str(timeout)]
        ports = context.parameters.get("ports")
        if isinstance(ports, str) and ports:
            argv += ["-p", ports]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[object]:
        """Parse rustscan JSON output into canonical port observations."""
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
                    reason="rustscan-open",
                    tool_id="rustscan",
                    source="rustscan",
                    target_id=target_id,
                    execution_id=context.execution_id,
                    correlation_id=context.correlation_id,
                )
            )
        return observations


def _parse_json_line(line: str) -> tuple[str, int, TransportProtocol] | None:
    """Parse one rustscan JSON answer into ``(address, port, protocol)``."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    address = str(payload.get("host") or payload.get("address") or "").strip()
    raw_port = payload.get("port")
    if raw_port is None:
        return None
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        return None
    if not address or not 1 <= port <= 65535:
        return None
    protocol = _protocol(payload.get("proto") or payload.get("protocol"))
    return address, port, protocol


def _protocol(value: object) -> TransportProtocol:
    try:
        return TransportProtocol(str(value or "tcp").lower())
    except ValueError:
        return TransportProtocol.TCP


__all__ = ["RustScanAdapter"]
