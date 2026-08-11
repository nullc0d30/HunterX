# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery tool adapters.

SDK tool adapters for live host & service discovery: nmap (primary, XML
contract covering host/port/service/version/TLS), naabu (fast TCP ports,
JSONL), masscan (large-scale SYN/UDP, JSON) and an in-process TCP-connect
probe (binary-free fallback). All external invocations flow through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam; adapters serialize
canonical observations under the pipeline payload's ``observations`` key with a
``type`` discriminator.
"""

from hunterx.tools.livehost.base import LiveToolAdapter
from hunterx.tools.livehost.masscan import MasscanAdapter
from hunterx.tools.livehost.naabu import NaabuAdapter
from hunterx.tools.livehost.nmap import NmapAdapter
from hunterx.tools.livehost.registry import (
    LIVE_TOOL_IDS,
    LiveAdapterFactory,
    live_adapters,
    register_live_adapters,
)
from hunterx.tools.livehost.rustscan import RustScanAdapter
from hunterx.tools.livehost.tcp_connect import TcpConnectAdapter
from hunterx.tools.livehost.tip import register_live_tools

__all__ = [
    "LIVE_TOOL_IDS",
    "LiveAdapterFactory",
    "LiveToolAdapter",
    "MasscanAdapter",
    "NaabuAdapter",
    "NmapAdapter",
    "RustScanAdapter",
    "TcpConnectAdapter",
    "live_adapters",
    "register_live_adapters",
    "register_live_tools",
]
