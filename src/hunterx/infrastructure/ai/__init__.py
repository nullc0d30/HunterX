# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI adapters.

Concrete providers implement :class:`~hunterx.domain.ports.services.AIPort`:.
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
