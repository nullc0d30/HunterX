# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI provider factory.

Composition helper that maps :class:`~hunterx.config.settings.AISettings` to
a concrete :class:`~hunterx.domain.ports.services.AIPort` adapter. It only
decides *which* adapter to build; provider-specific HTTP behaviour lives in the
adapter modules. No global mutable provider state is used — the composition
root (``hunterx.platform.assembler``) builds the client and injects it.

Responsibilities:
- Select the AI adapter from settings (fallback, known, unknown, missing key).
- Raise controlled configuration errors that never include secret material.

Dependencies:
- ``hunterx.config`` (settings), ``hunterx.domain`` (exceptions and ports),
  and the adapter modules in this package.

Extension points:
- Add new adapters to ``_ADAPTERS`` and their keys to ``_KNOWN_PROVIDERS``.
"""

from __future__ import annotations

from typing import Any

from hunterx.config.settings import AISettings
from hunterx.domain.exceptions import ConfigurationError
from hunterx.domain.ports.services import AIPort
from hunterx.infrastructure.ai.null import NullAIClient
from hunterx.infrastructure.ai.openrouter import OpenRouterClient
from hunterx.infrastructure.ai.providers import (
    AnthropicClient,
    DeepSeekClient,
    GeminiClient,
    LMStudioClient,
    OllamaClient,
    OpenAIClient,
    OpenAICompatibleGenericClient,
    XAIClient,
)

#: Providers whose API key is accepted by :class:`AISettings`.
_KNOWN_PROVIDERS: frozenset[str] = frozenset(
    {"openai", "anthropic", "openrouter", "gemini", "deepseek", "grok", "lmstudio", "ollama", "openai_compatible"}
)

#: Providers with a concrete adapter implemented in the infrastructure layer.
#: OpenAI, DeepSeek, OpenRouter, LM Studio, Ollama, and xAI/Grok share the
#: OpenAI-compatible transport; Anthropic and Gemini use their own protocol
#: adapters.
_ADAPTERS: dict[str, type[Any]] = {
    "openai": OpenAIClient,
    "anthropic": AnthropicClient,
    "deepseek": DeepSeekClient,
    "openrouter": OpenRouterClient,
    "gemini": GeminiClient,
    "grok": XAIClient,
    "lmstudio": LMStudioClient,
    "ollama": OllamaClient,
    "openai_compatible": OpenAICompatibleGenericClient,
}

#: Providers that use the OpenAI-compatible transport and support base_url override.
_OPENAI_COMPATIBLE_PROVIDERS: frozenset[str] = frozenset(
    {"openai", "deepseek", "openrouter", "grok", "lmstudio", "ollama", "openai_compatible"}
)


def build_ai_client(settings: AISettings) -> AIPort:
    """Build the AI client selected by ``settings``.

    - No provider configured → :class:`NullAIClient` (safe fallback; HunterX
      keeps running without any AI key).
    - Unknown provider → :class:`ConfigurationError`.
    - Known provider without an adapter yet → :class:`ConfigurationError`.

    Error messages reference provider names and environment variable names only
    and never include secret material.
    """
    provider = (settings.provider or "").strip().lower()
    if not provider:
        return NullAIClient()

    if provider not in _KNOWN_PROVIDERS:
        raise ConfigurationError(
            f"Unknown AI provider '{provider}'. Supported providers: "
            f"{', '.join(sorted(_KNOWN_PROVIDERS))}."
        )

    # For local providers (lmstudio, ollama), API key is optional.
    # For openai_compatible, it's required if the endpoint needs it.
    api_key = settings.api_key_for(provider)
    if not api_key and provider not in {"lmstudio", "ollama"}:
        raise ConfigurationError(
            f"AI provider '{provider}' is configured but no API key is set. "
            f"Set the HUNTERX_AI_{provider.upper()}_KEY environment variable "
            f"(see .env.example)."
        )

    adapter = _ADAPTERS.get(provider)
    if adapter is None:
        raise ConfigurationError(
            f"AI provider '{provider}' is recognized but no adapter is "
            "implemented yet; configure a supported provider instead."
        )

    # Pass base_url and timeout for OpenAI-compatible providers
    if provider in _OPENAI_COMPATIBLE_PROVIDERS:
        client: AIPort = adapter(
            api_key=api_key,
            model=settings.model or None,
            base_url=settings.base_url or None,
            timeout=settings.timeout,
        )
    else:
        client = adapter(api_key=api_key, model=settings.model or None)
    return client
