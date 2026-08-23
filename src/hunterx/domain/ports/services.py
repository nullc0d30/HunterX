# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Service ports: secrets, sandbox, AI, telemetry and registries."""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.plugins import PluginDescriptor
from hunterx.domain.tools import ToolDescriptor


class SecretsPort(abc.ABC):
    """Secret resolution contract (env, vault, keyring, ...)."""

    @abc.abstractmethod
    def get(self, name: str) -> str:
        """Return the secret value for ``name``, raising when absent."""

    @abc.abstractmethod
    def has(self, name: str) -> bool:
        """Return ``True`` when a secret named ``name`` is available."""

    @abc.abstractmethod
    def set(self, name: str, value: str) -> None:
        """Store the secret ``value`` under ``name``."""


class SandboxPort(abc.ABC):
    """Isolation contract for executing untrusted plugin/tool code."""

    @abc.abstractmethod
    def run(self, code: str, *, timeout_seconds: float = 30.0, limits: dict[str, Any] | None = None) -> str:
        """Execute ``code`` in isolation and return its captured output."""

    @abc.abstractmethod
    def check(self) -> bool:
        """Return ``True`` when the sandbox backend is operational."""


class AIPort(abc.ABC):
    """AI model interaction contract (LLM completions, embeddings)."""

    @abc.abstractmethod
    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        """Return a completion for ``prompt`` from the configured model."""

    @abc.abstractmethod
    def embed(self, text: str) -> list[float]:
        """Return the embedding vector for ``text``."""

    @abc.abstractmethod
    def check(self) -> bool:
        """Return ``True`` when the provider is reachable and the model is available.

        This performs a lightweight health check (e.g., listing available models)
        to validate connectivity and model availability without consuming a full
        chat completion.
        """


class TelemetryPort(abc.ABC):
    """Metrics, tracing and logging export contract."""

    @abc.abstractmethod
    def record_metric(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Record a numeric metric (count, gauge, histogram)."""

    @abc.abstractmethod
    def log(self, level: str, message: str, *, fields: dict[str, Any] | None = None) -> None:
        """Emit a structured log entry at ``level``."""


class PluginRegistryPort(abc.ABC):
    """Registry contract for installed plugins."""

    @abc.abstractmethod
    def register(self, descriptor: PluginDescriptor) -> None:
        """Register a plugin descriptor, replacing any same-name entry."""

    @abc.abstractmethod
    def unregister(self, name: str) -> None:
        """Remove the plugin descriptor named ``name``."""

    @abc.abstractmethod
    def get(self, name: str) -> PluginDescriptor | None:
        """Return the plugin descriptor by name, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self) -> list[PluginDescriptor]:
        """Return all registered plugin descriptors."""


class ToolRegistryPort(abc.ABC):
    """Registry contract for installed tools/adapters."""

    @abc.abstractmethod
    def register(self, descriptor: ToolDescriptor) -> None:
        """Register a tool descriptor, replacing any same-name entry."""

    @abc.abstractmethod
    def unregister(self, name: str) -> None:
        """Remove the tool descriptor named ``name``."""

    @abc.abstractmethod
    def get(self, name: str) -> ToolDescriptor | None:
        """Return the tool descriptor by name, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self) -> list[ToolDescriptor]:
        """Return all registered tool descriptors."""
