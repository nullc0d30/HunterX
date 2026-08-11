# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Typed configuration settings.

Settings are validated with pydantic and populated from environment variables
prefixed with ``HUNTERX_`` plus optional YAML profiles. Secrets are never
stored here — they live in the secrets layer (``hunterx.security``).
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field


class DatabaseSettings(BaseModel):
    """Database connection settings."""

    url: str = Field(
        default="sqlite:///hunterx.db",
        description="SQLAlchemy database URL.",
    )
    echo: bool = Field(default=False, description="Emit SQL statements to logs.")
    pool_size: int = Field(default=10, ge=1)
    pool_timeout: int = Field(default=30, ge=1)


class CacheSettings(BaseModel):
    """Cache backend settings."""

    backend: str = Field(default="memory", description="memory | redis | null")
    url: str = Field(default="", description="Redis URL when backend=redis.")
    ttl_seconds: int = Field(default=300, ge=1)


class QueueSettings(BaseModel):
    """Work-queue backend settings."""

    backend: str = Field(default="memory", description="memory | redis | null")
    url: str = Field(default="", description="Redis URL when backend=redis.")
    prefetch: int = Field(default=8, ge=1)


class SecuritySettings(BaseModel):
    """Security-related settings (non-secret)."""

    sandbox_enabled: bool = Field(default=True, description="Run plugins/tools in an isolated sandbox.")
    sandbox_timeout_seconds: float = Field(default=30.0, gt=0.0)


class ApiSettings(BaseModel):
    """REST API server settings.

    Authentication is opt-in: set ``auth_enabled`` (or ``api_key``) to require
    a valid ``X-API-Key`` on every request. ``api_key`` grants full (admin)
    access; ``read_only_key`` grants read-only access when configured.
    """

    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8080, ge=1, le=65535)
    auth_enabled: bool = Field(default=False, description="Require an API key on every request.")
    api_key: str = Field(default="", description="Admin API key; when set, authentication is enforced.")
    read_only_key: str = Field(default="", description="Optional read-only API key.")


class Settings(BaseModel):
    """Top-level typed configuration.

    Environment variables are mapped automatically: ``HUNTERX_APP_NAME`` maps
    to ``app_name``, and so on.
    """

    app_name: str = Field(default="HunterX", description="Application display name.")
    environment: str = Field(default="production", description="dev | staging | production.")
    log_level: str = Field(default="INFO", description="Root logging level.")
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)
    queue: QueueSettings = Field(default_factory=QueueSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    telemetry_enabled: bool = Field(default=True)


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Immutable resolved configuration handed to components at startup.

    This is the runtime-facing view; ``Settings`` is the load-time schema.
    """

    settings: Settings

    @property
    def app_name(self) -> str:
        """Return the application display name."""
        return self.settings.app_name

    @property
    def environment(self) -> str:
        """Return the deployment environment name."""
        return self.settings.environment

    @property
    def log_level(self) -> str:
        """Return the root logging level."""
        return self.settings.log_level
