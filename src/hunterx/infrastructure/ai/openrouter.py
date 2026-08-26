# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""OpenRouter AI provider adapter.

OpenRouter exposes the OpenAI-compatible ``/chat/completions`` and
``/embeddings`` APIs, so it shares the common transport in
:mod:`hunterx.infrastructure.ai.providers` and only declares its identity,
endpoint and default model. ``httpx`` is imported lazily so the base install
(without the ``ai`` extra) stays fully functional until a real provider is
actually selected.

Implements :class:`~hunterx.domain.ports.services.AIPort`.
"""

from __future__ import annotations

from typing import Any

from hunterx.infrastructure.ai.providers import OpenAICompatibleClient

#: OpenRouter REST API base URL.
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
#: Fallback model when ``HUNTERX_AI_MODEL`` is not set. A free-tier model by
#: default: an unset model must never silently route to a paid deployment and
#: surface as ``HTTP 402 payment required`` mid-mission.
DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b:free"


class OpenRouterClient(OpenAICompatibleClient):
    """LLM completion and embedding client backed by OpenRouter.

    Args:
        api_key: OpenRouter API key (never logged or serialized).
        model: default model identifier; falls back to the configured
            free-tier default (:data:`DEFAULT_MODEL`).
        base_url: OpenRouter API base URL (overridable for tests/proxies).
        http_client: optional injected HTTP client for tests; when omitted a
            lazy ``httpx.Client`` is used.
        timeout: per-request timeout in seconds.

    """

    provider = "openrouter"
    base_url = DEFAULT_BASE_URL
    default_model = DEFAULT_MODEL

    def __init__(
        self,
        *,
        api_key: str,
        model: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        http_client: Any | None = None,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(
            api_key=api_key,
            model=model,
            base_url=base_url,
            http_client=http_client,
            timeout=timeout,
        )


__all__ = ["OpenRouterClient", "DEFAULT_BASE_URL", "DEFAULT_MODEL"]
