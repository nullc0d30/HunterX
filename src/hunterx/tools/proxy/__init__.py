# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Proxy / interception tool adapters."""

from hunterx.tools.proxy.adapters import MitmproxyAdapter, ProxyToolAdapter, ZapAdapter
from hunterx.tools.proxy.registry import (
    PROXY_TOOL_IDS,
    ProxyAdapterFactory,
    proxy_adapters,
    register_proxy_adapters,
)

__all__ = [
    "MitmproxyAdapter",
    "PROXY_TOOL_IDS",
    "ProxyAdapterFactory",
    "ProxyToolAdapter",
    "ZapAdapter",
    "proxy_adapters",
    "register_proxy_adapters",
]
