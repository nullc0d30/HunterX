# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication intelligence tool adapters.

The authentication intelligence capability ships a single in-process analyzer
adapter. Importing this package exposes the adapter, base and registry helpers.
"""

from __future__ import annotations

from hunterx.tools.auth.base import AuthToolAdapter
from hunterx.tools.auth.registry import (
    AUTH_TOOL_IDS,
    AuthAdapterFactory,
    auth_adapters,
    register_auth_adapters,
)
from hunterx.tools.auth.tip import auth_tool_specs, register_auth_tools

__all__ = [
    "AUTH_TOOL_IDS",
    "AuthAdapterFactory",
    "AuthToolAdapter",
    "auth_adapters",
    "auth_tool_specs",
    "register_auth_adapters",
    "register_auth_tools",
]
