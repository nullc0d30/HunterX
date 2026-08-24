# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI adapters.

Concrete providers implement :class:`~hunterx.domain.ports.services.AIPort`:

- :class:`NullAIClient` - safe fallback when no provider is configured.
- :class:`OpenAIClient`, :class:`DeepSeekClient`, :class:`OpenRouterClient`,
  :class:`XAIClient` - OpenAI-compatible chat-completions providers sharing a
  common transport.
- :class:`AnthropicClient`, :class:`GeminiClient` - protocol-specific adapters.

The :func:`build_ai_client` factory maps :class:`AISettings` to the right
adapter; the composition root injects the result through the platform.

Responsibilities:
- Provide every concrete ``AIPort`` implementation.
- Select the adapter from typed settings without global mutable state.

Dependencies:
- ``hunterx.domain`` (ports and exceptions), ``hunterx.config`` (settings),
  ``hunterx.shared`` (masking), and optionally ``httpx`` (the ``ai`` extra).

Extension points:
- Register new providers in :mod:`hunterx.infrastructure.ai.factory`.
"""

from __future__ import annotations

from hunterx.infrastructure.ai.factory import build_ai_client
from hunterx.infrastructure.ai.null import NullAIClient
from hunterx.infrastructure.ai.openrouter import OpenRouterClient
from hunterx.infrastructure.ai.provider_manager import ProviderConfig, ProviderManager
from hunterx.infrastructure.ai.providers import (
    AnthropicClient,
    DeepSeekClient,
    GeminiClient,
    LMStudioClient,
    OllamaClient,
    OpenAIClient,
    OpenAICompatibleClient,
    OpenAICompatibleGenericClient,
    XAIClient,
)

__all__ = [
    "AnthropicClient",
    "DeepSeekClient",
    "GeminiClient",
    "LMStudioClient",
    "NullAIClient",
    "OllamaClient",
    "OpenAIClient",
    "OpenAICompatibleClient",
    "OpenAICompatibleGenericClient",
    "OpenRouterClient",
    "ProviderConfig",
    "ProviderManager",
    "XAIClient",
    "build_ai_client",
]