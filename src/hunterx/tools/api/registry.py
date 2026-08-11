# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence tool adapter registry.

Builds and registers the API intelligence adapters (OpenAPI, Swagger, GraphQL,
WebSocket, SOAP, hints) on an :class:`~hunterx.tools.sdk.engine.ExecutionEngine`.
This is the single place that knows the API intelligence tool set, so callers
(tests, the API service, the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.api.adapters import (
    ApiHintsAdapter,
    GraphQLDiscoveryAdapter,
    OpenAPIDiscoveryAdapter,
    SoapDiscoveryAdapter,
    SwaggerDiscoveryAdapter,
    WebSocketDiscoveryAdapter,
)
from hunterx.tools.api.graphql_binaries import GraphQLmapAdapter, InQLAdapter
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated API intelligence tools.
API_TOOL_IDS: tuple[str, ...] = (
    "api-openapi",
    "api-swagger",
    "api-graphql",
    "api-websocket",
    "api-soap",
    "api-hints",
    "graphqlmap",
    "inql",
)


class APIAdapterFactory:
    """Instantiate the API intelligence tool adapters."""

    def build(self) -> dict[str, ToolAdapter]:
        """Return a fresh set of API adapters keyed by tool id."""
        return {
            "api-openapi": OpenAPIDiscoveryAdapter(),
            "api-swagger": SwaggerDiscoveryAdapter(),
            "api-graphql": GraphQLDiscoveryAdapter(),
            "api-websocket": WebSocketDiscoveryAdapter(),
            "api-soap": SoapDiscoveryAdapter(),
            "api-hints": ApiHintsAdapter(),
            "graphqlmap": GraphQLmapAdapter(),
            "inql": InQLAdapter(),
        }

    def create(self, tool_id: str) -> ToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown API tool '{tool_id}'")
        return adapters[tool_id]


def api_adapters() -> dict[str, ToolAdapter]:
    """Return a fresh mapping of API tool id to adapter instance."""
    return APIAdapterFactory().build()


def register_api_adapters(engine: ExecutionEngine) -> Mapping[str, ToolAdapter]:
    """Register every API adapter on ``engine`` and return the mapping."""
    adapters = api_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
