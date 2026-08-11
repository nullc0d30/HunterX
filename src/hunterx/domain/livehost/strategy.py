# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery collection strategy.

Maps an execution mode (passive/active/hybrid) and a target onto the concrete
set of tools, ports and analyses the capability should run. The strategy is a
pure function of (mode, target, requested features) so the same inputs always
yield the same collection plan, and it fails closed for passive postures.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from hunterx.domain.livehost.models import DEFAULT_TOP_PORTS
from hunterx.domain.recon.models import ReconMode

#: Tools available for direct (active) discovery; passive runs use none.
_ACTIVE_TOOLS = ("nmap", "masscan", "naabu", "tcp-connect")

#: Supported transport protocols.
_PROTOCOLS = ("tcp", "udp", "both")


@dataclass(frozen=True, slots=True)
class LiveStrategy:
    """A concrete collection plan for a discovery target.

    Attributes:
        target: the target value (IP, CIDR, hostname or domain).
        target_kind: canonical target kind (``domain``, ``host``, ``ip``,
            ``cidr``).
        mode: the execution posture.
        ports: the ports to probe.
        protocol: ``tcp``, ``udp`` or ``both``.
        with_service_detection: whether to fingerprint services.
        with_tls: whether to collect TLS metadata.
        with_http: whether to collect HTTP service surfaces.
        with_history: whether to compare with historical data.
        tools: the tool ids to run.
        max_concurrency: execution concurrency ceiling.

    """

    target: str
    target_kind: str = "ip"
    mode: ReconMode = ReconMode.HYBRID
    ports: tuple[int, ...] = DEFAULT_TOP_PORTS
    protocol: str = "tcp"
    with_service_detection: bool = True
    with_tls: bool = True
    with_http: bool = True
    with_history: bool = False
    tools: tuple[str, ...] = _ACTIVE_TOOLS
    max_concurrency: int = 8


class LiveStrategyBuilder:
    """Build a :class:`LiveStrategy` for a target and mode."""

    def build(
        self,
        target: str,
        *,
        mode: ReconMode = ReconMode.HYBRID,
        target_kind: str = "",
        ports: tuple[int, ...] = (),
        protocol: str = "tcp",
        with_service_detection: bool | None = None,
        with_tls: bool | None = None,
        with_http: bool | None = None,
        with_history: bool = False,
        tools: tuple[str, ...] = (),
        max_concurrency: int = 8,
    ) -> LiveStrategy:
        """Build the strategy for ``target``."""
        if not target_kind:
            target_kind = _infer_target_kind(target)
        if protocol not in _PROTOCOLS:
            protocol = "tcp"
        passive = mode is ReconMode.PASSIVE
        return LiveStrategy(
            target=target.strip(),
            target_kind=target_kind,
            mode=mode,
            ports=tuple(ports) if ports else DEFAULT_TOP_PORTS,
            protocol=protocol,
            with_service_detection=_feature_default(passive, with_service_detection),
            with_tls=_feature_default(passive, with_tls),
            with_http=_feature_default(passive, with_http),
            with_history=with_history,
            tools=tuple(tools) if tools else self.tools_for(mode),
            max_concurrency=max(1, max_concurrency),
        )

    def tools_for(self, mode: ReconMode) -> tuple[str, ...]:
        """Return the tool ids available for a posture (empty in passive)."""
        return () if mode is ReconMode.PASSIVE else _ACTIVE_TOOLS


def _feature_default(passive: bool, requested: bool | None) -> bool:
    """Default a feature flag off for passive postures unless requested."""
    if requested is not None:
        return requested
    return not passive


def _infer_target_kind(value: str) -> str:
    """Infer a canonical target kind from a target value."""
    candidate = value.strip()
    if "/" in candidate:
        try:
            ipaddress.ip_network(candidate, strict=False)
            return "cidr"
        except ValueError:
            return "host"
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        return "domain" if "." in candidate else "host"
