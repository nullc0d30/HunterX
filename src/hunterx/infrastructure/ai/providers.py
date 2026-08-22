# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Multi-provider AI adapters (generic provider abstraction).

One shared transport for the OpenAI-compatible chat-completions providers
(OpenAI, DeepSeek, OpenRouter, xAI/Grok) plus protocol-specific adapters for
Anthropic (``/v1/messages``) and Gemini (``generateContent``). Every adapter
implements :class:`~hunterx.domain.ports.services.AIPort`, resolves its own
API base URL, authenticates with its provider-specific credential, normalizes
the response to plain content, and never leaks the API key into reprs, logs or
errors.

Callers depend only on ``AIPort``; provider identity is exposed as read-only
``provider`` / ``model`` attributes for verification and diagnostics.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.exceptions import OperationError
from hunterx.domain.ports.services import AIPort
from hunterx.shared.masking import mask_value

#: Default completion size cap used by protocols that require ``max_tokens``.
_DEFAULT_MAX_TOKENS = 1024
#: Default embedding model for the OpenAI-compatible providers.
_DEFAULT_EMBED_MODEL = "text-embedding-3-small"

#: Anthropic REST API version header required by the messages API.
_ANTHROPIC_VERSION = "2023-06-01"


def _bounded_excerpt(exc: Exception, limit: int = 200) -> str:
    text = str(exc)
    return text[:limit] if text else exc.__class__.__name__


class OpenAICompatibleClient(AIPort):
    """Shared OpenAI-style ``/chat/completions`` transport.

    Provider subclasses only declare ``provider`` and ``base_url``; request
    construction, authentication, response normalization, error mapping and
    secret masking are inherited so no provider duplicates this behavior.
    """

    #: Canonical provider name (set by subclasses).
    provider = "openai-compatible"
    #: REST API base URL (set by subclasses).
    base_url = "https://api.openai.com/v1"
    #: Default model when none is configured (may be overridden per subclass).
    default_model = "gpt-4o-mini"

    def __init__(
        self,
        *,
        api_key: str,
        model: str | None = None,
        base_url: str = "",
        embed_model: str = _DEFAULT_EMBED_MODEL,
        http_client: Any | None = None,
        timeout: float = 120.0,
    ) -> None:
        self._api_key = api_key
        self._model = model or self.default_model
        self._embed_model = embed_model
        self._base_url = (base_url or self.base_url).rstrip("/")
        self._timeout = timeout
        self._injected_client = http_client
        self._client: Any | None = None

    # -- AIPort --------------------------------------------------------------

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        """Return a chat completion for ``prompt`` from the selected model."""
        payload = {
            "model": model or self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        data = self._post("/chat/completions", payload)
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise OperationError(f"{self.provider} returned an unexpected completion payload.") from exc

    def embed(self, text: str) -> list[float]:
        """Return the embedding vector for ``text``."""
        data = self._post("/embeddings", {"model": self._embed_model, "input": text})
        try:
            return list(data["data"][0]["embedding"])
        except (KeyError, IndexError, TypeError) as exc:
            raise OperationError(f"{self.provider} returned an unexpected embedding payload.") from exc

    # -- provider hooks ------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Return the provider-specific authentication headers."""
        return {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST ``payload`` to ``path`` and return the JSON body (error-mapped)."""
        headers = self._auth_headers()
        try:
            response = self._http().post(f"{self._base_url}{path}", json=payload, headers=headers)
        except TimeoutError as exc:
            raise OperationError(f"{self.provider}: request timed out after {self._timeout}s") from exc
        except OSError as exc:
            raise OperationError(f"{self.provider}: network failure reaching the API ({_bounded_excerpt(exc)})") from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status >= 400:
            error = _error_for_status(self.provider, status)
            if status == 429:
                # Honor Retry-After when the provider supplies it so the
                # scheduler can respect the server's cooldown instead of
                # retrying immediately (free-tier models enforce strict limits).
                retry_after = _retry_after_seconds(getattr(response, "headers", None))
                if retry_after:
                    error.retry_after = retry_after  # type: ignore[attr-defined]
            raise error
        try:
            body = response.json()
        except (ValueError, TypeError) as exc:
            raise OperationError(f"{self.provider}: malformed (non-JSON) provider response") from exc
        if not isinstance(body, dict):
            raise OperationError(f"{self.provider}: malformed provider response (expected a JSON object)")
        return body

    def _http(self) -> Any:
        """Return the HTTP client, constructing a real ``httpx`` client lazily."""
        if self._injected_client is not None:
            return self._injected_client
        if self._client is None:
            try:
                import httpx
            except ImportError as exc:  # pragma: no cover - optional extra
                raise OperationError(
                    f"The {self.provider} AI provider requires the 'ai' extra (httpx). "
                    "Install it with: pip install 'hunterxsec[ai]'."
                ) from exc
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def check(self) -> bool:
        """Return ``True`` so the health probe reports the adapter as configured."""
        return True

    # -- identity / diagnostics ----------------------------------------------

    @property
    def model(self) -> str:
        """Return the effective default model identifier."""
        return self._model

    def __repr__(self) -> str:
        """Diagnostic view that never exposes the API key."""
        return (
            f"{self.__class__.__name__}(provider={self.provider!r}, model={self._model!r}, "
            f"api_key={mask_value(self._api_key, reveal_head=0, reveal_tail=0)!r})"
        )


class OpenAIClient(OpenAICompatibleClient):
    """OpenAI chat-completions provider (``https://api.openai.com/v1``)."""

    provider = "openai"
    base_url = "https://api.openai.com/v1"
    default_model = "gpt-4o-mini"


class DeepSeekClient(OpenAICompatibleClient):
    """DeepSeek chat-completions provider (``https://api.deepseek.com/v1``)."""

    provider = "deepseek"
    base_url = "https://api.deepseek.com/v1"
    default_model = "deepseek-chat"


class XAIClient(OpenAICompatibleClient):
    """xAI (Grok) chat-completions provider (``https://api.x.ai/v1``).

    The configured provider identifier is ``grok`` (matching
    ``HUNTERX_AI_GROK_KEY`` / ``AISettings``); the API vendor is xAI.
    """

    provider = "grok"
    base_url = "https://api.x.ai/v1"
    default_model = "grok-2-latest"


class AnthropicClient(AIPort):
    """Anthropic ``/v1/messages`` adapter (different request/response shape).

    Anthropic uses ``x-api-key`` (no ``Bearer``), requires ``max_tokens`` and
    ``anthropic-version``, and returns ``content[].text`` blocks.
    """

    provider = "anthropic"
    base_url = "https://api.anthropic.com/v1"
    default_model = "claude-3-5-sonnet-latest"

    def __init__(
        self,
        *,
        api_key: str,
        model: str | None = None,
        base_url: str = "",
        http_client: Any | None = None,
        timeout: float = 120.0,
    ) -> None:
        self._api_key = api_key
        self._model = model or self.default_model
        self._base_url = (base_url or self.base_url).rstrip("/")
        self._timeout = timeout
        self._injected_client = http_client
        self._client: Any | None = None

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        """Return a chat completion for ``prompt`` via the messages API."""
        payload = {
            "model": model or self._model,
            "max_tokens": _DEFAULT_MAX_TOKENS,
            "system": "You are an advisory security-assessment planner.",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }
        data = self._post("/messages", payload, headers=headers)
        try:
            blocks = data["content"]
            text = "".join(
                str(block.get("text", ""))
                for block in blocks
                if isinstance(block, dict) and block.get("type") == "text"
            )
            return text
        except (KeyError, TypeError) as exc:
            raise OperationError("anthropic returned an unexpected completion payload.") from exc

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        """Anthropic does not offer an embeddings API — fail truthfully."""
        raise OperationError("anthropic does not offer an embeddings API")

    def _post(self, path: str, payload: dict[str, Any], *, headers: dict[str, str]) -> dict[str, Any]:
        try:
            response = self._http().post(f"{self._base_url}{path}", json=payload, headers=headers)
        except TimeoutError as exc:
            raise OperationError(f"{self.provider}: request timed out after {self._timeout}s") from exc
        except OSError as exc:
            raise OperationError(f"{self.provider}: network failure reaching the API ({_bounded_excerpt(exc)})") from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status >= 400:
            error = _error_for_status(self.provider, status)
            if status == 429:
                # Honor Retry-After when the provider supplies it so the
                # scheduler can respect the server's cooldown instead of
                # retrying immediately (free-tier models enforce strict limits).
                retry_after = _retry_after_seconds(getattr(response, "headers", None))
                if retry_after:
                    error.retry_after = retry_after  # type: ignore[attr-defined]
            raise error
        try:
            body = response.json()
        except (ValueError, TypeError) as exc:
            raise OperationError(f"{self.provider}: malformed (non-JSON) provider response") from exc
        if not isinstance(body, dict):
            raise OperationError(f"{self.provider}: malformed provider response (expected a JSON object)")
        return body

    def _http(self) -> Any:
        if self._injected_client is not None:
            return self._injected_client
        if self._client is None:
            try:
                import httpx
            except ImportError as exc:  # pragma: no cover - optional extra
                raise OperationError(
                    "The anthropic AI provider requires the 'ai' extra (httpx). "
                    "Install it with: pip install 'hunterxsec[ai]'."
                ) from exc
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def check(self) -> bool:
        """Return ``True`` when the Anthropic adapter is ready."""
        return True

    @property
    def model(self) -> str:
        """Return the configured model identifier."""
        return self._model

    def __repr__(self) -> str:
        return (
            f"AnthropicClient(provider={self.provider!r}, model={self._model!r}, "
            f"api_key={mask_value(self._api_key, reveal_head=0, reveal_tail=0)!r})"
        )


class GeminiClient(AIPort):
    """Google Gemini ``generateContent`` REST adapter.

    The model is part of the URL path; authentication uses the ``x-goog-api-key``
    header. Response content is in ``candidates[].content.parts[].text``.
    """

    provider = "gemini"
    base_url = "https://generativelanguage.googleapis.com/v1beta"
    default_model = "gemini-1.5-flash"

    def __init__(
        self,
        *,
        api_key: str,
        model: str | None = None,
        base_url: str = "",
        http_client: Any | None = None,
        timeout: float = 120.0,
    ) -> None:
        self._api_key = api_key
        self._model = model or self.default_model
        self._base_url = (base_url or self.base_url).rstrip("/")
        self._timeout = timeout
        self._injected_client = http_client
        self._client: Any | None = None

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        """Return a chat completion for ``prompt`` via generateContent."""
        selected = model or self._model
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature},
        }
        data = self._post(f"/models/{selected}:generateContent", payload)
        try:
            parts = data["candidates"][0]["content"]["parts"]
            text = "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))
            return text
        except (KeyError, IndexError, TypeError) as exc:
            raise OperationError("gemini returned an unexpected completion payload.") from exc

    def embed(self, text: str) -> list[float]:
        """Return the embedding vector for ``text`` via embedContent."""
        data = self._post(f"/models/{self._model}:embedContent", {"content": {"parts": [{"text": text}]}})
        try:
            return list(data["embedding"]["values"])
        except (KeyError, TypeError) as exc:
            raise OperationError("gemini returned an unexpected embedding payload.") from exc

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"x-goog-api-key": self._api_key, "Content-Type": "application/json"}
        try:
            response = self._http().post(f"{self._base_url}{path}", json=payload, headers=headers)
        except TimeoutError as exc:
            raise OperationError(f"{self.provider}: request timed out after {self._timeout}s") from exc
        except OSError as exc:
            raise OperationError(f"{self.provider}: network failure reaching the API ({_bounded_excerpt(exc)})") from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status >= 400:
            error = _error_for_status(self.provider, status)
            if status == 429:
                # Honor Retry-After when the provider supplies it so the
                # scheduler can respect the server's cooldown instead of
                # retrying immediately (free-tier models enforce strict limits).
                retry_after = _retry_after_seconds(getattr(response, "headers", None))
                if retry_after:
                    error.retry_after = retry_after  # type: ignore[attr-defined]
            raise error
        try:
            body = response.json()
        except (ValueError, TypeError) as exc:
            raise OperationError(f"{self.provider}: malformed (non-JSON) provider response") from exc
        if not isinstance(body, dict):
            raise OperationError(f"{self.provider}: malformed provider response (expected a JSON object)")
        return body

    def _http(self) -> Any:
        if self._injected_client is not None:
            return self._injected_client
        if self._client is None:
            try:
                import httpx
            except ImportError as exc:  # pragma: no cover - optional extra
                raise OperationError(
                    "The gemini AI provider requires the 'ai' extra (httpx). "
                    "Install it with: pip install 'hunterxsec[ai]'."
                ) from exc
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def check(self) -> bool:
        """Return ``True`` when the Gemini adapter is ready."""
        return True

    @property
    def model(self) -> str:
        """Return the configured model identifier."""
        return self._model

    def __repr__(self) -> str:
        return (
            f"GeminiClient(provider={self.provider!r}, model={self._model!r}, "
            f"api_key={mask_value(self._api_key, reveal_head=0, reveal_tail=0)!r})"
        )


def _error_for_status(provider: str, status: int) -> OperationError:
    """Map an HTTP status to a truthful, provider-labelled error (no secrets)."""
    if status in (401, 403):
        return OperationError(
            f"{provider}: authentication failed (HTTP {status}) — invalid or missing API key"
        )
    if status == 402:
        return OperationError(
            f"{provider}: payment required (HTTP 402) — the account has no credits for the selected model"
        )
    if status == 404:
        return OperationError(
            f"{provider}: invalid model or API endpoint (HTTP {status})"
        )
    if status == 429:
        return OperationError(
            f"{provider}: rate limited (HTTP {status}) — retry later"
        )
    if status >= 500:
        return OperationError(
            f"{provider}: provider unavailable (HTTP {status})"
        )
    return OperationError(f"{provider}: provider request failed (HTTP {status})")


def _retry_after_seconds(headers: Any) -> float:
    """Return the ``Retry-After`` duration in seconds (``0`` when absent/invalid).

    ``Retry-After`` may be an HTTP-date or a number of seconds; providers
    (notably OpenRouter free-tier models) use seconds. The value is bounded so
    an absurd header can never cause an unbounded scheduler stall.
    """
    if not headers:
        return 0.0
    value = headers.get("Retry-After") or headers.get("retry-after")
    if value is None:
        return 0.0
    try:
        seconds = float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0
    if not seconds > 0:
        return 0.0
    return min(seconds, 300.0)


__all__ = [
    "AnthropicClient",
    "DeepSeekClient",
    "GeminiClient",
    "OpenAIClient",
    "OpenAICompatibleClient",
    "XAIClient",
]
