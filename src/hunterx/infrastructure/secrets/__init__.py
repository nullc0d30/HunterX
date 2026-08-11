# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Secrets adapters."""

from __future__ import annotations

import os

from hunterx.domain.exceptions import SecretResolutionError
from hunterx.domain.ports.services import SecretsPort


class EnvironmentSecrets(SecretsPort):
    """Secrets resolved from environment variables.

    Names are mapped to ``HUNTERX_SECRET_<NAME>`` environment variables by
    default. This keeps secrets out of code and configuration files.
    """

    def __init__(self, prefix: str = "HUNTERX_SECRET_") -> None:
        self._prefix = prefix

    def _key(self, name: str) -> str:
        return f"{self._prefix}{name.upper().replace('-', '_')}"

    def get(self, name: str) -> str:
        """Return the secret value for ``name``, raising when absent."""
        value = os.environ.get(self._key(name))
        if value is None:
            raise SecretResolutionError(f"Secret '{name}' is not set in the environment.")
        return value

    def has(self, name: str) -> bool:
        """Return ``True`` when a secret named ``name`` is available."""
        return self._key(name) in os.environ

    def set(self, name: str, value: str) -> None:
        """Store the secret ``value`` under ``name``."""
        os.environ[self._key(name)] = value


class InMemorySecrets(SecretsPort):
    """Secrets held in process memory (tests and development only)."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get(self, name: str) -> str:
        """Return the secret value for ``name``, raising when absent."""
        value = self._store.get(name)
        if value is None:
            raise SecretResolutionError(f"Secret '{name}' is not set.")
        return value

    def has(self, name: str) -> bool:
        """Return ``True`` when a secret named ``name`` is available."""
        return name in self._store

    def set(self, name: str, value: str) -> None:
        """Store the secret ``value`` under ``name``."""
        self._store[name] = value
