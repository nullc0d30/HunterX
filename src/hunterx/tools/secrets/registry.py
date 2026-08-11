# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Secret discovery tool adapter registry.

Builds and registers the secret discovery adapters (gitleaks) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.secrets.base import SecretToolAdapter
from hunterx.tools.secrets.gitleaks import GitleaksAdapter
from hunterx.tools.secrets.trufflehog import TrufflehogAdapter

#: Canonical order and set of the integrated secret discovery tools.
SECRETS_TOOL_IDS: tuple[str, ...] = ("gitleaks", "trufflehog")


class SecretsAdapterFactory:
    """Instantiate the secret discovery tool adapters."""

    def build(self) -> dict[str, SecretToolAdapter]:
        """Return a fresh set of secret adapters keyed by tool id."""
        return {
            "gitleaks": GitleaksAdapter(),
            "trufflehog": TrufflehogAdapter(),
        }

    def create(self, tool_id: str) -> SecretToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown secrets tool '{tool_id}'")
        return adapters[tool_id]


def secrets_adapters() -> dict[str, SecretToolAdapter]:
    """Return a fresh mapping of secret tool id to adapter instance."""
    return SecretsAdapterFactory().build()


def register_secrets_adapters(engine: ExecutionEngine) -> Mapping[str, SecretToolAdapter]:
    """Register every secrets adapter on ``engine`` and return the mapping."""
    adapters = secrets_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
