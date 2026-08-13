# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the OpenRouter AI provider adapter.

All HTTP traffic is served by an injected fake client; no real API calls are
made during tests.
"""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import OperationError
from hunterx.infrastructure.ai import OpenRouterClient


class _FakeResponse:
    def __init__(self, payload: object, *, status: int = 200) -> None:
        self._payload = payload
        self._status = status

    def raise_for_status(self) -> None:
        if self._status >= 400:
            raise RuntimeError(f"HTTP {self._status}")

    def json(self) -> object:
        return self._payload


class _FakeClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def post(self, url: str, *, json: object, headers: dict[str, str]) -> _FakeResponse:
        self.requests.append({"url": url, "json": json, "headers": headers})
        if not self._responses:
            raise AssertionError("no response queued for the fake HTTP client")
        return self._responses.pop(0)


def _client(*responses: _FakeResponse, model: str | None = None) -> tuple[OpenRouterClient, _FakeClient]:
    fake = _FakeClient(list(responses))
    client = OpenRouterClient(api_key="sk-test-key", model=model, http_client=fake)
    return client, fake


class TestComplete:
    def test_complete_returns_message_content(self) -> None:
        client, fake = _client(_FakeResponse({"choices": [{"message": {"content": "hello world"}}]}))
        assert client.complete("say hi") == "hello world"
        assert fake.requests[0]["url"] == "https://openrouter.ai/api/v1/chat/completions"
        payload = fake.requests[0]["json"]
        assert payload["model"] == "deepseek/deepseek-chat"
        assert payload["messages"] == [{"role": "user", "content": "say hi"}]

    def test_complete_uses_default_model_when_configured(self) -> None:
        client, fake = _client(
            _FakeResponse({"choices": [{"message": {"content": "ok"}}]}),
            model="deepseek/deepseek-chat",
        )
        client.complete("p")
        assert fake.requests[0]["json"]["model"] == "deepseek/deepseek-chat"

    def test_complete_model_override_wins(self) -> None:
        client, fake = _client(_FakeResponse({"choices": [{"message": {"content": "ok"}}]}))
        client.complete("p", model="custom/model")
        assert fake.requests[0]["json"]["model"] == "custom/model"

    def test_complete_sends_bearer_key_but_only_in_header(self) -> None:
        client, fake = _client(_FakeResponse({"choices": [{"message": {"content": "ok"}}]}))
        client.complete("p")
        headers = fake.requests[0]["headers"]
        assert headers["Authorization"] == "Bearer sk-test-key"
        assert "sk-test-key" not in str(fake.requests[0]["json"])

    def test_complete_unexpected_payload_raises_operation_error(self) -> None:
        client, _ = _client(_FakeResponse({"unexpected": True}))
        with pytest.raises(OperationError):
            client.complete("p")


class TestEmbed:
    def test_embed_returns_vector(self) -> None:
        client, fake = _client(_FakeResponse({"data": [{"embedding": [0.1, 0.2, 0.3]}]}))
        assert client.embed("text") == [0.1, 0.2, 0.3]
        assert fake.requests[0]["url"] == "https://openrouter.ai/api/v1/embeddings"
        assert fake.requests[0]["json"]["input"] == "text"

    def test_embed_unexpected_payload_raises_operation_error(self) -> None:
        client, _ = _client(_FakeResponse({"data": []}))
        with pytest.raises(OperationError):
            client.embed("text")


class TestSecurity:
    def test_repr_masks_api_key(self) -> None:
        client, _ = _client(_FakeResponse({"choices": [{"message": {"content": ""}}]}))
        rendered = repr(client)
        assert "sk-test-key" not in rendered
        assert "api_key" in rendered

    def test_http_errors_propagate_without_key(self) -> None:
        client, _ = _client(_FakeResponse({}, status=401))
        with pytest.raises(RuntimeError) as excinfo:
            client.complete("p")
        assert "sk-test-key" not in str(excinfo.value)


class TestHealth:
    def test_check_returns_true(self) -> None:
        client, _ = _client(_FakeResponse({"choices": [{"message": {"content": ""}}]}))
        assert client.check() is True
