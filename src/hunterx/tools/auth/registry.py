# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication intelligence tool adapter registry.

Builds and registers the authentication intelligence adapters (the in-process
analyzer) on an :class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the
single place that knows the auth tool set, so callers (tests, the auth service,
the platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.auth.analyzer import AuthAnalyzerAdapter
from hunterx.tools.auth.base import AuthToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical order and set of the integrated authentication tools.
AUTH_TOOL_IDS: tuple[str, ...] = (
    "auth-analysis",
)


class AuthAdapterFactory:
    """Instantiate the authentication intelligence tool adapters."""

    def build(self) -> dict[str, AuthToolAdapter]:
        """Return a fresh set of auth adapters keyed by tool id."""
        return {
            "auth-analysis": AuthAnalyzerAdapter(),
        }

    def create(self, tool_id: str) -> AuthToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown authentication tool '{tool_id}'")
        return adapters[tool_id]


def auth_adapters() -> dict[str, AuthToolAdapter]:
    """Return a fresh mapping of auth tool id to adapter instance."""
    return AuthAdapterFactory().build()


def register_auth_adapters(engine: ExecutionEngine) -> Mapping[str, AuthToolAdapter]:
    """Register every auth adapter on ``engine`` and return the mapping."""
    adapters = auth_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
