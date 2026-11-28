# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence tool adapters."""

from __future__ import annotations

from hunterx.tools.api.adapters import (
    ApiHintsAdapter,
    GraphQLDiscoveryAdapter,
    OpenAPIDiscoveryAdapter,
    SoapDiscoveryAdapter,
    SwaggerDiscoveryAdapter,
    WebSocketDiscoveryAdapter,
)
from hunterx.tools.api.base import ApiToolAdapter
from hunterx.tools.api.graphql_binaries import GraphQLmapAdapter, InQLAdapter
from hunterx.tools.api.registry import API_TOOL_IDS, APIAdapterFactory, api_adapters, register_api_adapters
from hunterx.tools.sdk.adapter import ToolAdapter

__all__ = [
    "API_TOOL_IDS",
    "APIAdapterFactory",
    "ApiHintsAdapter",
    "ApiToolAdapter",
    "GraphQLDiscoveryAdapter",
    "GraphQLmapAdapter",
    "InQLAdapter",
    "OpenAPIDiscoveryAdapter",
    "SoapDiscoveryAdapter",
    "SwaggerDiscoveryAdapter",
    "ToolAdapter",
    "WebSocketDiscoveryAdapter",
    "api_adapters",
    "register_api_adapters",
]
