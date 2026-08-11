# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization intelligence tool adapters.

The authorization intelligence capability ships a single in-process analyzer
adapter. Importing this package exposes the adapter, base and registry helpers.
"""

from __future__ import annotations

from hunterx.tools.authorization.base import AuthorizationToolAdapter
from hunterx.tools.authorization.registry import (
    AUTHORIZATION_TOOL_IDS,
    AuthorizationAdapterFactory,
    authorization_adapters,
    register_authorization_adapters,
)
from hunterx.tools.authorization.tip import (
    authorization_tool_specs,
    register_authorization_tools,
)

__all__ = [
    "AUTHORIZATION_TOOL_IDS",
    "AuthorizationAdapterFactory",
    "AuthorizationToolAdapter",
    "authorization_adapters",
    "authorization_tool_specs",
    "register_authorization_adapters",
    "register_authorization_tools",
]
