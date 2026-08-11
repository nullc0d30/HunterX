# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization intelligence tool adapter registry.

Builds and registers the authorization intelligence adapters (the in-process
analyzer) on an :class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the
single place that knows the authorization tool set, so callers (tests, the
authorization service, the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.authorization.analyzer import AuthorizationAnalyzerAdapter
from hunterx.tools.authorization.base import AuthorizationToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated authorization tools.
AUTHORIZATION_TOOL_IDS: tuple[str, ...] = (
    "authorization-analysis",
)


class AuthorizationAdapterFactory:
    """Instantiate the authorization intelligence tool adapters."""

    def build(self) -> dict[str, AuthorizationToolAdapter]:
        """Return a fresh set of authorization adapters keyed by tool id."""
        return {
            "authorization-analysis": AuthorizationAnalyzerAdapter(),
        }

    def create(self, tool_id: str) -> AuthorizationToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown authorization tool '{tool_id}'")
        return adapters[tool_id]


def authorization_adapters() -> dict[str, AuthorizationToolAdapter]:
    """Return a fresh mapping of authorization tool id to adapter instance."""
    return AuthorizationAdapterFactory().build()


def register_authorization_adapters(engine: ExecutionEngine) -> Mapping[str, AuthorizationToolAdapter]:
    """Register every authorization adapter on ``engine`` and return the mapping."""
    adapters = authorization_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
