# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology fingerprinting tool adapters.

SDK tool adapters for technology fingerprinting: httpx (ProjectDiscovery,
machine-readable JSON with ``-tech-detect`` and CDN detection), whatweb (deep
plugin-based fingerprinting with JSON logging) and an in-process signature
detector (binary-free fallback over HTTP evidence). All external invocations
flow through the shared :class:`~hunterx.tools.recon.runner.BinaryRunner` seam;
adapters serialize canonical technology observations under the pipeline
payload's ``technologies`` key with a ``type`` discriminator.
"""

from hunterx.tools.tech.base import TechToolAdapter
from hunterx.tools.tech.httpclient import FetchFn, HttpFetcher
from hunterx.tools.tech.httpx import HttpxAdapter
from hunterx.tools.tech.registry import (
    TECH_TOOL_IDS,
    TechAdapterFactory,
    register_tech_adapters,
    tech_adapters,
)
from hunterx.tools.tech.signature import SignatureAdapter
from hunterx.tools.tech.tip import register_tech_tools
from hunterx.tools.tech.whatweb import WhatWebAdapter

__all__ = [
    "FetchFn",
    "HttpFetcher",
    "HttpxAdapter",
    "SignatureAdapter",
    "TECH_TOOL_IDS",
    "TechAdapterFactory",
    "TechToolAdapter",
    "WhatWebAdapter",
    "register_tech_adapters",
    "register_tech_tools",
    "tech_adapters",
]
