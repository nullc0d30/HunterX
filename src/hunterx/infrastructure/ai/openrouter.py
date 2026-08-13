# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""OpenRouter AI provider adapter.

Implements :class:`~hunterx.domain.ports.services.AIPort` against the
OpenRouter chat-completions and embeddings APIs. ``httpx`` is imported lazily
so the base install (without the ``ai`` extra) stays fully functional until a
real provider is actually selected.

Responsibilities:
- Send chat completions and embedding requests to OpenRouter.
- Keep the API key out of reprs, logs and exceptions.

Dependencies:
- ``hunterx.domain`` (ports and exceptions), ``hunterx.shared`` (masking),
  and optionally ``httpx`` (the ``ai`` extra).
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.exceptions import OperationError
from hunterx.domain.ports.services import AIPort
from hunterx.shared.masking import mask_value

#: OpenRouter REST API base URL.
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
#: Fallback model when ``HUNTERX_AI_MODEL`` is not set.
DEFAULT_MODEL = "deepseek/deepseek-chat"


class OpenRouterClient(AIPort):
    """LLM completion and embedding client backed by OpenRouter.

    Args:
        api_key: OpenRouter API key (never logged or serialized).
        model: default model identifier; falls back to ``deepseek/deepseek-chat``.
        base_url: OpenRouter API base URL (overridable for tests/proxies).
        http_client: optional injected HTTP client for tests; when omitted a
            lazy ``httpx.Client`` is used.
        timeout: per-request timeout in seconds.

    """

    def __init__(
        self,
        *,
        api_key: str,
        model: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        http_client: Any | None = None,
        timeout: float = 120.0,
    ) -> None:
        self._api_key = api_key
        self._model = model or DEFAULT_MODEL
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._injected_client = http_client
        self._client: Any | None = None

    def _http(self) -> Any:
        """Return the HTTP client, constructing a real ``httpx`` client lazily."""
        if self._injected_client is not None:
            return self._injected_client
        if self._client is None:
            try:
                import httpx
            except ImportError as exc:  # pragma: no cover - optional extra
                raise OperationError(
                    "The OpenRouter AI provider requires the 'ai' extra (httpx). "
                    "Install it with: pip install 'hunterxsec[ai]'."
                ) from exc
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        """Return a chat completion for ``prompt`` from the configured model."""
        payload = {
            "model": model or self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        data = self._post("/chat/completions", payload)
        try:
            content: str = data["choices"][0]["message"]["content"]
            return content
        except (KeyError, IndexError, TypeError) as exc:
            raise OperationError("OpenRouter returned an unexpected completion payload.") from exc

    def embed(self, text: str) -> list[float]:
        """Return the embedding vector for ``text`` via OpenRouter embeddings."""
        data = self._post("/embeddings", {"model": "text-embedding-3-small", "input": text})
        try:
            return list(data["data"][0]["embedding"])
        except (KeyError, IndexError, TypeError) as exc:
            raise OperationError("OpenRouter returned an unexpected embedding payload.") from exc

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST ``payload`` to ``path`` with the bearer key; return JSON body."""
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        response = self._http().post(f"{self._base_url}{path}", json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
        assert isinstance(body, dict)  # nosec B101  # shape is validated by callers
        return body

    def check(self) -> bool:
        """Return ``True`` so the health probe reports the adapter as configured."""
        return True

    def __repr__(self) -> str:
        """Diagnostic view that never exposes the API key."""
        return (
            f"OpenRouterClient(model={self._model!r}, "
            f"api_key={mask_value(self._api_key, reveal_head=0, reveal_tail=0)!r})"
        )
