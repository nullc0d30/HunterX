# -*- coding: utf-8 -*-\n# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Typed configuration settings.

Settings are validated with pydantic and populated from environment variables
prefixed with ``HUNTERX_`` plus optional YAML profiles. Secrets are never
stored here — they live in the secrets layer (``hunterx.security``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

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
    ``HUNTERX_AI_DEEPSEEK_KEY``, ``HUNTERX_AI_GROK_KEY``,
    ``HUNTERX_AI_LMSTUDIO_KEY``, ``HUNTERX_AI_OLLAMA_KEY``,
    ``HUNTERX_AI_OPENAI_COMPATIBLE_KEY``) or a ``.env`` file
    and are never hardcoded in source. An empty ``provider`` keeps the safe
    :class:`~hunterx.infrastructure.ai.NullAIClient` fallback in place.

    For local/OpenAI-compatible providers (LM Studio, Ollama, generic), the
    ``base_url`` points to the provider's OpenAI-compatible endpoint
    (e.g. ``http://127.0.0.1:1234/v1`` for LM Studio,
    ``http://127.0.0.1:11434/v1`` for Ollama). When empty, the provider's
    default base URL is used.
    """

    provider: str = Field(default="", description="AI provider name (openai | anthropic | openrouter | gemini | deepseek | grok | lmstudio | ollama | openai_compatible).")
    model: str = Field(default="", description="Default model identifier (e.g. deepseek/deepseek-chat).")
    base_url: str = Field(default="", description="Custom base URL for OpenAI-compatible providers (e.g. http://127.0.0.1:1234/v1 for LM Studio, http://127.0.0.1:11434/v1 for Ollama). Empty uses provider default.")
    timeout: float = Field(default=120.0, gt=0.0, description="Per-request timeout in seconds.")
    openai_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="OpenAI API key (masked).")
    anthropic_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Anthropic API key (masked).")
    openrouter_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="OpenRouter API key (masked).")
    gemini_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Gemini API key (masked).")
    deepseek_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="DeepSeek API key (masked).")
    grok_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Grok API key (masked).")
    lmstudio_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="LM Studio API key (masked, usually empty for local).")
    ollama_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Ollama API key (masked, usually empty for local).")
    openai_compatible_key: SecretStr = Field(default_factory=lambda: SecretStr(""), description="Generic OpenAI-compatible API key (masked).")

    #: Provider name → key field name. Configuration knowledge only; provider
    #: HTTP behaviour lives in the infrastructure adapters.
    _PROVIDER_KEY_FIELDS: ClassVar[dict[str, str]] = {
        "openai": "openai_key",
        "anthropic": "anthropic_key",
        "openrouter": "openrouter_key",
        "gemini": "gemini_key",
        "deepseek": "deepseek_key",
        "grok": "grok_key",
        "lmstudio": "lmstudio_key",
        "ollama": "ollama_key",
        "openai_compatible": "openai_compatible_key",
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


class ResourceSettings(BaseModel):
    """Resource-governance settings (safe defaults prioritize host stability).

    These values drive the centralized :class:`hunterx.resource.ResourceGovernor`
    which manages the resource envelope of the whole mission process tree. The
    absolute HunterX RAM ceiling is 3 GB by default; the effective mission
    budget is derived from the runtime environment (bare-metal/VM/WSL/container),
    so HunterX stays safe on 4 GB / 2 CPU hosts and never relies on the OOM
    killer. All values are overridable via ``HUNTERX_RESOURCE_*`` env vars or a
    ``resource:`` YAML section.
    """

    memory_ceiling_mb: float = Field(
        default=3072.0,
        ge=256.0,
        description="Absolute upper HunterX RAM ceiling (MB). Never exceeded unless explicitly configured.",
    )
    host_headroom_ratio: float = Field(
        default=0.55, gt=0.0, le=0.95,
        description="Fraction of physical host RAM HunterX must never exceed (preserves host headroom).",
    )
    budget_ratio: float = Field(
        default=0.5, gt=0.0, le=0.9,
        description="Fraction of the effective environment memory limit used as the mission budget.",
    )
    memory_soft_ratio: float = Field(default=0.6, gt=0.0, lt=1.0, description="Enter CONSTRAINED at this pressure.")
    memory_high_ratio: float = Field(default=0.8, gt=0.0, lt=1.0, description="Enter DEGRADED at this pressure.")
    memory_hard_ratio: float = Field(default=0.92, gt=0.0, lt=1.0, description="Enter CRITICAL at this pressure.")
    system_emergency_ratio: float = Field(
        default=0.95, gt=0.0, lt=1.0,
        description="Host memory pressure that triggers EMERGENCY regardless of the HunterX process tree.",
    )
    cpu_budget_percent: float = Field(default=0.0, ge=0.0, le=800.0, description="Process-tree CPU budget percent (0 = auto).")
    max_tool_concurrency: int = Field(default=2, ge=1, description="Max simultaneously running external tools.")
    max_probe_concurrency: int = Field(default=4, ge=1, description="Max concurrent HTTP probes per capability task.")
    max_model_concurrency: int = Field(default=1, ge=1, description="Max concurrent model calls.")
    max_queue_depth: int = Field(default=500, ge=0, description="Max actionable pending assessment-queue tasks (0 = unbounded).")
    tool_timeout_s: float = Field(default=600.0, gt=0.0, description="Hard per-tool wall-clock deadline (seconds).")
    model_timeout_s: float = Field(default=120.0, gt=0.0, description="Hard per-model-call wall-clock deadline (seconds).")
    mission_deadline_s: float = Field(default=0.0, ge=0.0, description="Hard mission wall-clock deadline (0 = unlimited).")
    max_observations_in_memory: int = Field(default=1500, ge=1, description="Max observations retained in memory.")
    max_hypotheses_in_memory: int = Field(default=600, ge=1, description="Max hypotheses retained in memory.")
    max_decisions_in_memory: int = Field(default=1500, ge=1, description="Max decisions retained in memory.")
    max_evidence_in_memory: int = Field(default=2000, ge=1, description="Max evidence records retained in memory.")
    max_tool_executions_in_memory: int = Field(default=1500, ge=1, description="Max tool-execution records retained in memory.")
    max_trace_in_memory: int = Field(default=1200, ge=1, description="Max reasoning-trace entries retained in memory.")
    max_negative_evidence_in_memory: int = Field(default=800, ge=1, description="Max negative-evidence records retained in memory.")
    max_attack_paths_in_memory: int = Field(default=1500, ge=1, description="Max attack-path records retained in memory.")
    max_model_context_observations: int = Field(default=60, ge=1, description="Max observations fed into the model reasoning context.")
    max_model_context_findings: int = Field(default=20, ge=1, description="Max validated findings fed into the model reasoning context.")
    max_model_context_paths: int = Field(default=30, ge=1, description="Max adjacent attack paths fed into the model reasoning context.")
    max_model_context_disproven: int = Field(default=200, ge=1, description="Max disproven fingerprints retained in the model learning context.")
    max_replan_cycles: int = Field(default=12, ge=1, description="Max replan-driven scheduling rounds before the mission stops spawning new work.")
    max_probes_per_cycle: int = Field(default=12, ge=1, description="Max differential probes executed per mission cycle.")

    # -- byte-level in-memory bounds (resident memory, not just item counts) ---
    max_observation_content_bytes: int = Field(
        default=262144, ge=1,
        description="Max serialized bytes retained per observation content (larger tool output is summarized in memory; the durable copy is persisted).",
    )
    max_aggregate_state_bytes: int = Field(
        default=1073741824, ge=1,
        description="Max total serialized bytes of the in-memory mission aggregate (oldest observations are evicted beyond this).",
    )
    max_model_context_bytes: int = Field(
        default=1048576, ge=1,
        description="Max serialized bytes of the model reasoning context fed to the model.",
    )
    max_services_in_memory: int = Field(default=200, ge=1, description="Max service entries retained in the in-memory target model (a single port scan can add hundreds).")
    max_assets_in_memory: int = Field(default=1000, ge=1, description="Max asset entries retained in the in-memory target model.")
    max_technologies_in_memory: int = Field(default=500, ge=1, description="Max technology entries retained in the in-memory target model.")

    # -- runtime memory instrumentation ------------------------------------------
    telemetry_file: str = Field(
        default="",
        description="Path for append-only JSON-lines mission memory telemetry (empty = disabled).",
    )
    telemetry_tracemalloc: bool = Field(
        default=False,
        description="Enable Python-heap tracing via tracemalloc for the memory telemetry (adds overhead).",
    )
    telemetry_interval_s: float = Field(default=5.0, gt=0.0, description="Throttle interval for [RESOURCE] telemetry logs.")
    watchdog_interval_s: float = Field(
        default=1.0, ge=0.0,
        description="Background governor sampling interval in seconds (0 disables the watchdog thread).",
    )


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
    resource: ResourceSettings = Field(default_factory=ResourceSettings)
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

