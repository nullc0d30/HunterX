# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process TCP-connect probe adapter.

Performs host reachability and TCP port discovery with a plain TCP connect —
the binary-free fallback that requires no external tool and no raw sockets.
Unlike binary adapters this adapter has no CLI; ``run`` probes the target
through an injectable connection callable with a per-port timeout, so unit
tests never touch the network: ``TcpConnectAdapter(probe=fake_probe)``.

A refused connection proves the host is reachable (a live service just does
not listen on that port); timeouts are treated as inconclusive rather than as
proof the host is offline.
"""

from __future__ import annotations

import socket  # nosec B105  # the adapter only performs plain TCP connects
from collections.abc import Callable
from dataclasses import dataclass

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.livehost.models import (
    DEFAULT_TOP_PORTS,
    HostState,
    PortState,
    ReachabilityMethod,
    make_host,
    make_port,
)
from hunterx.domain.tools import ToolDescriptor
from hunterx.shared.time import monotonic_ms
from hunterx.tools.livehost.base import LiveToolAdapter
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.sdk.output import OutputCollector

_VERSION = "1.0.0"

#: Probe signature: ``(address, port, timeout_s) -> (state, rtt_ms)``.
ProbeFn = Callable[[str, int, float], tuple[PortState, int]]


@dataclass(frozen=True, slots=True)
class _Probe:
    """Result of probing a single port."""

    port: int
    state: PortState
    rtt_ms: int


class TcpConnectAdapter(LiveToolAdapter):
    """SDK adapter performing in-process TCP-connect port discovery.

    The adapter exposes a ``descriptor`` for registration and an execution
    lifecycle so it participates in the standard pipeline, but ``run`` performs
    in-process probing rather than a subprocess invocation.
    """

    descriptor = ToolDescriptor(
        name="tcp-connect",
        version=_VERSION,
        description="In-process TCP-connect host reachability and port discovery.",
        entrypoint="hunterx.tools.livehost.tcp_connect:TcpConnectAdapter",
        targets=("ip", "host"),
        capabilities=("host-discovery", "port-scanning"),
        permissions=("network",),
        parameters={
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Ports to probe (default: top well-known ports).",
            },
            "timeout": {
                "type": "number",
                "description": "Per-connect timeout in seconds.",
            },
        },
    )

    def __init__(self, probe: ProbeFn | None = None) -> None:
        super().__init__()
        self._probe = probe or _default_probe

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """No CLI; returns an empty command line for the descriptor contract."""
        return []

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Probe the target's ports and emit discovery observations."""
        address = context.target.strip()
        ports = self._param_ports(context, DEFAULT_TOP_PORTS)
        timeout = _optional_float(context.parameters.get("timeout"), 1.0)
        target_id = self._target_id(context)
        probes = [_Probe(port, *self._probe(address, port, timeout)) for port in ports]

        observations: list[object] = []
        for probe in probes:
            observations.append(
                make_port(
                    address,
                    probe.port,
                    state=probe.state,
                    reason=_reason_for(probe.state, probe.rtt_ms),
                    tool_id="tcp-connect",
                    source="tcp-connect",
                    target_id=target_id,
                    execution_id=context.execution_id,
                    correlation_id=context.correlation_id,
                )
            )
        completed = [probe for probe in probes if probe.state in (PortState.OPEN, PortState.CLOSED)]
        reachable = True if completed else None
        state = HostState.REACHABLE if completed else HostState.UNKNOWN
        observations.insert(
            0,
            make_host(
                address,
                state=state,
                reachable=reachable,
                methods=(ReachabilityMethod.TCP_CONNECT,),
                rtt_ms=min((probe.rtt_ms for probe in completed), default=0),
                tool_id="tcp-connect",
                source="tcp-connect",
                target_id=target_id,
                execution_id=context.execution_id,
                correlation_id=context.correlation_id,
            ),
        )
        collector.set_exit_code(0)
        collector.set_json(self._payload(observations))

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[object]:
        """Unused for the in-process adapter; returns no observations."""
        return []


def _default_probe(address: str, port: int, timeout: float) -> tuple[PortState, int]:
    """Connect to ``address:port`` and classify the outcome."""
    start = monotonic_ms()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return PortState.OPEN, int(monotonic_ms() - start)
    except TimeoutError:
        return PortState.FILTERED, int(monotonic_ms() - start)
    except (ConnectionRefusedError, ConnectionResetError):
        return PortState.CLOSED, int(monotonic_ms() - start)
    except OSError:
        return PortState.CLOSED, int(monotonic_ms() - start)
    except Exception:  # noqa: BLE001  # any other outcome is inconclusive
        return PortState.UNKNOWN, int(monotonic_ms() - start)


def _reason_for(state: PortState, rtt_ms: int) -> str:
    """Return the connect-scan reason string for a probe outcome."""
    reasons = {
        PortState.OPEN: "connect",
        PortState.CLOSED: "refused",
        PortState.FILTERED: "timeout",
        PortState.UNKNOWN: "error",
    }
    return f"{reasons.get(state, 'unknown')} rtt={rtt_ms}ms"


def _optional_float(value: object, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default
