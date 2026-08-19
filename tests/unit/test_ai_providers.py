# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Multi-provider AI routing tests (mocked HTTP; no real API keys required).

Covers provider/model selection, per-provider endpoints + authentication,
response normalization, truthful error semantics, secret masking, and the
no-silent-fallback guarantees. Every request is served by an injected fake
HTTP client so the regression suite needs no credentials.
"""

from __future__ import annotations

import pytest

from hunterx.config.settings import AISettings
from hunterx.domain.exceptions import ConfigurationError, OperationError
from hunterx.infrastructure.ai import (
    AnthropicClient,
    DeepSeekClient,
    GeminiClient,
    OpenAIClient,
    OpenRouterClient,
    XAIClient,
    build_ai_client,
)


class _FakeResponse:
    def __init__(self, payload: object, *, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> object:
        return self._payload


class _FakeClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def post(self, url: str, *, json: object, headers: dict[str, str]) -> _FakeResponse:
        self.requests.append({"url": url, "json": json, "headers": headers})
        return self._responses.pop(0) if self._responses else _FakeResponse({})


def _build(provider: str, *, model: str = "", key: str = "sk-test-key"):
    client = build_ai_client(
        AISettings(provider=provider, model=model, **{f"{provider}_key": key})
        if provider != "grok"
        else AISettings(provider=provider, model=model, grok_key=key)
    )
    fake = _FakeClient([_FakeResponse({"choices": [{"message": {"content": "hi"}}]})])
    client._injected_client = fake  # noqa: SLF001
    return client, fake


def _openai_response(text: str = "hi") -> dict:
    return {"choices": [{"message": {"content": text}}]}


def _anthropic_response(text: str = "hi") -> dict:
    return {"content": [{"type": "text", "text": text}]}


def _gemini_response(text: str = "hi") -> dict:
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


# ---------------------------------------------------------------------------
# Provider routing: each provider reaches its OWN endpoint + auth
# ---------------------------------------------------------------------------


class TestProviderRouting:
    @pytest.mark.parametrize(
        "provider,client_cls,base_url",
        [
            ("openai", OpenAIClient, "https://api.openai.com/v1"),
            ("deepseek", DeepSeekClient, "https://api.deepseek.com/v1"),
            ("openrouter", OpenRouterClient, "https://openrouter.ai/api/v1"),
            ("grok", XAIClient, "https://api.x.ai/v1"),
        ],
    )
    def test_openai_compatible_providers_hit_own_endpoint(
        self, provider: str, client_cls: type, base_url: str
    ) -> None:
        client, fake = _build(provider, model="m1")
        assert isinstance(client, client_cls)
        assert client.complete("hello") == "hi"
        req = fake.requests[0]
        assert req["url"] == f"{base_url}/chat/completions"
        assert req["json"]["model"] == "m1"
        assert req["headers"]["Authorization"] == "Bearer sk-test-key"
        assert req["json"]["messages"] == [{"role": "user", "content": "hello"}]

    def test_openai_never_routes_through_openrouter(self) -> None:
        client, fake = _build("openai", model="gpt-4o-mini")
        client.complete("p")
        assert fake.requests[0]["url"].startswith("https://api.openai.com/")

    def test_deepseek_never_routes_through_openrouter(self) -> None:
        client, fake = _build("deepseek", model="deepseek-chat")
        client.complete("p")
        assert fake.requests[0]["url"].startswith("https://api.deepseek.com/")

    def test_grok_never_routes_through_openrouter(self) -> None:
        client, fake = _build("grok", model="grok-2")
        client.complete("p")
        assert fake.requests[0]["url"].startswith("https://api.x.ai/")

    def test_openrouter_does_route_to_openrouter(self) -> None:
        client, fake = _build("openrouter", model="deepseek/deepseek-chat")
        client.complete("p")
        assert fake.requests[0]["url"].startswith("https://openrouter.ai/")

    def test_anthropic_uses_messages_api_and_x_api_key(self) -> None:
        client = AnthropicClient(api_key="sk-ant", model="claude-x")
        fake = _FakeClient([_FakeResponse(_anthropic_response("hello claude"))])
        client._injected_client = fake  # noqa: SLF001
        assert client.complete("hi") == "hello claude"
        req = fake.requests[0]
        assert req["url"] == "https://api.anthropic.com/v1/messages"
        assert req["json"]["model"] == "claude-x"
        assert req["json"]["messages"] == [{"role": "user", "content": "hi"}]
        assert req["headers"]["x-api-key"] == "sk-ant"
        assert "anthropic-version" in req["headers"]
        assert "Authorization" not in req["headers"]

    def test_gemini_uses_generate_content_and_goog_key(self) -> None:
        client = GeminiClient(api_key="sk-gem", model="gemini-x")
        fake = _FakeClient([_FakeResponse(_gemini_response("hello gemini"))])
        client._injected_client = fake  # noqa: SLF001
        assert client.complete("hi") == "hello gemini"
        req = fake.requests[0]
        assert req["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-x:generateContent"
        assert req["json"]["contents"] == [{"role": "user", "parts": [{"text": "hi"}]}]
        assert req["headers"]["x-goog-api-key"] == "sk-gem"
        assert "Authorization" not in req["headers"]

    def test_each_provider_respects_custom_base_url(self) -> None:
        fake = _FakeClient([_FakeResponse(_openai_response())])
        client = OpenAIClient(api_key="k", model="m", base_url="https://proxy.example/v1")
        client._injected_client = fake  # noqa: SLF001
        client.complete("p")
        assert fake.requests[0]["url"].startswith("https://proxy.example/v1")


# ---------------------------------------------------------------------------
# Model routing: the configured model is passed through, never rewritten
# ---------------------------------------------------------------------------


class TestModelRouting:
    @pytest.mark.parametrize("provider", ["openai", "deepseek", "openrouter", "grok"])
    def test_model_is_passed_verbatim(self, provider: str) -> None:
        client, fake = _build(provider, model="custom/vendor-model-42")
        client.complete("p")
        assert fake.requests[0]["json"]["model"] == "custom/vendor-model-42"

    def test_model_override_on_call_wins(self) -> None:
        client, fake = _build("openai", model="default-model")
        client.complete("p", model="per-call-model")
        assert fake.requests[0]["json"]["model"] == "per-call-model"

    def test_invalid_model_is_reported_not_rewritten(self) -> None:
        client, fake = _build("openai", model="does-not-exist-xyz")
        fake._responses = [_FakeResponse({}, status=404)]
        with pytest.raises(OperationError, match="invalid model"):
            client.complete("p")
        assert fake.requests[0]["json"]["model"] == "does-not-exist-xyz"


# ---------------------------------------------------------------------------
# Error semantics + no silent fallback
# ---------------------------------------------------------------------------


class TestErrorSemantics:
    @pytest.mark.parametrize(
        "status,needle",
        [
            (401, "authentication failed"),
            (403, "authentication failed"),
            (404, "invalid model"),
            (429, "rate limited"),
            (502, "provider unavailable"),
            (500, "provider unavailable"),
        ],
    )
    def test_http_errors_are_truthful_and_distinguished(self, status: int, needle: str) -> None:
        client, fake = _build("openai", model="m")
        fake._responses = [_FakeResponse({}, status=status)]
        with pytest.raises(OperationError) as excinfo:
            client.complete("p")
        assert needle in str(excinfo.value)
        assert "sk-test-key" not in str(excinfo.value)

    def test_unknown_provider_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="Unknown AI provider"):
            build_ai_client(AISettings(provider="skynet", openai_key="sk-x"))

    def test_missing_key_raises_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError, match="no API key"):
            build_ai_client(AISettings(provider="openai"))

    def test_no_silent_provider_fallback(self) -> None:
        # A provider without a key must never silently fall back to another.
        with pytest.raises(ConfigurationError):
            build_ai_client(AISettings(provider="deepseek", openai_key="sk-openai-key"))
        # Unknown providers are never coerced to a default provider.
        with pytest.raises(ConfigurationError):
            build_ai_client(AISettings(provider="watson", openai_key="sk-x"))

    def test_malformed_response_is_reported(self) -> None:
        client, fake = _build("openai", model="m")
        fake._responses = [_FakeResponse({"unexpected": True})]
        with pytest.raises(OperationError, match="unexpected completion payload"):
            client.complete("p")

    def test_non_json_response_is_reported(self) -> None:
        client, fake = _build("openai", model="m")
        fake._responses = [_FakeResponse([1, 2, 3])]
        with pytest.raises(OperationError, match="malformed"):
            client.complete("p")

    def test_anthropic_embed_is_truthful_unsupported(self) -> None:
        client = AnthropicClient(api_key="sk-ant", model="m")
        with pytest.raises(OperationError, match="does not offer an embeddings API"):
            client.embed("text")


# ---------------------------------------------------------------------------
# Response normalization
# ---------------------------------------------------------------------------


class TestResponseNormalization:
    def test_content_is_normalized_across_providers(self) -> None:
        cases = [
            ("openai", _openai_response("openai says hi"), "openai says hi"),
            ("deepseek", _openai_response("deepseek says hi"), "deepseek says hi"),
            ("openrouter", _openai_response("or says hi"), "or says hi"),
            ("grok", _openai_response("grok says hi"), "grok says hi"),
        ]
        for provider, payload, expected in cases:
            client, fake = _build(provider, model="m")
            fake._responses = [_FakeResponse(payload)]
            assert client.complete("p") == expected

    def test_anthropic_text_blocks_are_concatenated(self) -> None:
        client = AnthropicClient(api_key="k", model="m")
        fake = _FakeClient(
            [_FakeResponse({"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]})]
        )
        client._injected_client = fake  # noqa: SLF001
        assert client.complete("p") == "ab"

    def test_gemini_parts_are_concatenated(self) -> None:
        client = GeminiClient(api_key="k", model="m")
        fake = _FakeClient(
            [_FakeResponse({"candidates": [{"content": {"parts": [{"text": "x"}, {"text": "y"}]}}]})]
        )
        client._injected_client = fake  # noqa: SLF001
        assert client.complete("p") == "xy"

    def test_provider_identity_is_exposed(self) -> None:
        for provider, cls in [
            ("openai", OpenAIClient),
            ("anthropic", AnthropicClient),
            ("deepseek", DeepSeekClient),
            ("openrouter", OpenRouterClient),
            ("gemini", GeminiClient),
            ("grok", XAIClient),
        ]:
            client = build_ai_client(
                AISettings(provider=provider, **{f"{provider}_key": "sk-x"})
                if provider != "grok"
                else AISettings(provider="grok", grok_key="sk-x")
            )
            assert isinstance(client, cls)
            assert client.provider == provider


# ---------------------------------------------------------------------------
# Secret masking
# ---------------------------------------------------------------------------


class TestSecretMasking:
    @pytest.mark.parametrize("provider", ["openai", "anthropic", "deepseek", "openrouter", "gemini", "grok"])
    def test_repr_masks_the_key_for_every_provider(self, provider: str) -> None:
        client = build_ai_client(
            AISettings(provider=provider, **{f"{provider}_key": "sk-super-secret-value"})
            if provider != "grok"
            else AISettings(provider="grok", grok_key="sk-super-secret-value")
        )
        rendered = repr(client)
        assert "sk-super-secret-value" not in rendered

    def test_auth_header_is_the_only_key_location(self) -> None:
        client, fake = _build("openai", model="m")
        client.complete("p")
        req = fake.requests[0]
        assert req["headers"]["Authorization"] == "Bearer sk-test-key"
        assert "sk-test-key" not in str(req["json"])

    def test_configuration_errors_never_include_the_key(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            build_ai_client(AISettings(provider="openai"))
        assert "sk-" not in str(excinfo.value)