# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Typed configuration settings.

Settings are validated with pydantic and populated from environment variables
prefixed with ``HUNTERX_`` plus optional YAML profiles. Secrets are never
stored here — they live in the secrets layer (``hunterx.security``).
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field, SecretStr


class DatabaseSettings(BaseModel):
    """Database connection settings.

    The default URL is a sentinel resolved at engine-creation time to
    ``<application root>/data/hunterx.db`` (see ``hunterx.config.paths``);
    set ``HUNTERX_DATABASE_URL`` to override explicitly.
    """

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


class AISettings(BaseModel):
    """AI provider configuration.

    ``provider`` and ``model`` are plain values; API keys are
    :class:`pydantic.SecretStr` so any repr / dump / log of the settings
    object masks them automatically. Keys are loaded from the environment
    (``HUNTERX_AI_OPENAI_KEY``, ``HUNTERX_AI_ANTHROPIC_KEY``,
    ``HUNTERX_AI_OPENROUTER_KEY``, ``HUNTERX_AI_GEMINI_KEY``,
    ``HUNTERX_AI_DEEPSEEK_KEY``, ``HUNTERX_AI_GROK_KEY``) or a ``.env`` file
    and are never hardcoded in source. An empty ``provider`` keeps the safe
    :class:`~hunterx.infrastructure.ai.NullAIClient` fallback in place.
    """

    provider: str = Field(default="", description="AI provider name (openai | anthropic | openrouter | gemini | deepseek | grok).")
    model: str = Field(default="", description="Default model identifier (e.g. deepseek/deepseek-chat).")
    openai_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="OpenAI API key (masked).")
    anthropic_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Anthropic API key (masked).")
    openrouter_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="OpenRouter API key (masked).")
    gemini_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Gemini API key (masked).")
    deepseek_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="DeepSeek API key (masked).")
    grok_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Grok API key (masked).")

    #: Provider name → key field name. Configuration knowledge only; provider
    #: HTTP behaviour lives in the infrastructure adapters.
    _PROVIDER_KEY_FIELDS: dict[str, str] = {
        "openai": "openai_key",
        "anthropic": "anthropic_key",
        "openrouter": "openrouter_key",
        "gemini": "gemini_key",
        "deepseek": "deepseek_key",
        "grok": "grok_key",
    }

    def api_key_for(self, provider: str) -> str:
        """Return the plaintext API key configured for ``provider`` (``""`` when absent).

        The returned value is only used to build the adapter; it is never
        serialized back into diagnostics.
        """
        field = self._PROVIDER_KEY_FIELDS.get((provider or "").strip().lower())
        if field is None:
            return ""
        value: SecretStr = getattr(self, field)
        return value.get_secret_value()


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
    ai: AISettings = Field(default_factory=AISettings)
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
