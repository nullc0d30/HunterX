# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the AI provider factory (provider selection + fallbacks)."""

from __future__ import annotations

import pytest

from hunterx.config.settings import AISettings, Settings
from hunterx.domain.exceptions import ConfigurationError
from hunterx.infrastructure.ai import NullAIClient, OpenRouterClient, build_ai_client


class TestProviderSelection:
    def test_no_provider_returns_null_client(self) -> None:
        client = build_ai_client(Settings().ai)
        assert isinstance(client, NullAIClient)

    def test_blank_provider_returns_null_client(self) -> None:
        client = build_ai_client(AISettings(provider="   "))
        assert isinstance(client, NullAIClient)

    def test_openrouter_returns_openrouter_client(self) -> None:
        client = build_ai_client(AISettings(provider="openrouter", openrouter_key="sk-or-1"))
        assert isinstance(client, OpenRouterClient)

    def test_provider_matching_is_case_insensitive(self) -> None:
        client = build_ai_client(AISettings(provider="OpenRouter", openrouter_key="sk-or-1"))
        assert isinstance(client, OpenRouterClient)

    def test_model_is_passed_to_adapter(self) -> None:
        client = build_ai_client(
            AISettings(provider="openrouter", model="deepseek/deepseek-chat", openrouter_key="sk-or-1")
        )
        assert isinstance(client, OpenRouterClient)
        assert client._model == "deepseek/deepseek-chat"  # noqa: SLF001


class TestProviderErrors:
    def test_unknown_provider_raises_controlled_error(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            build_ai_client(AISettings(provider="skynet", openai_key="sk-anything"))
        message = str(excinfo.value)
        assert "skynet" in message
        assert "sk-anything" not in message

    def test_recognized_provider_without_key_raises_controlled_error(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            build_ai_client(AISettings(provider="openrouter"))
        message = str(excinfo.value)
        assert "openrouter" in message
        assert "HUNTERX_AI_OPENROUTER_KEY" in message

    @pytest.mark.parametrize(
        "provider,key_field,key",
        [
            ("openai", "openai_key", "sk-openai-1"),
            ("anthropic", "anthropic_key", "sk-anthropic-1"),
            ("deepseek", "deepseek_key", "sk-deepseek-1"),
            ("openrouter", "openrouter_key", "sk-openrouter-1"),
            ("gemini", "gemini_key", "sk-gemini-1"),
            ("grok", "grok_key", "sk-grok-1"),
        ],
    )
    def test_each_provider_builds_its_own_adapter(self, provider: str, key_field: str, key: str) -> None:
        from hunterx.infrastructure.ai import (
            AnthropicClient,
            DeepSeekClient,
            GeminiClient,
            OpenAIClient,
            OpenRouterClient,
            XAIClient,
        )

        client = build_ai_client(AISettings(provider=provider, **{key_field: key}))
        expected = {
            "openai": OpenAIClient,
            "anthropic": AnthropicClient,
            "deepseek": DeepSeekClient,
            "openrouter": OpenRouterClient,
            "gemini": GeminiClient,
            "grok": XAIClient,
        }[provider]
        assert isinstance(client, expected)
        assert client.provider == provider
        assert key not in repr(client)

    def test_model_is_passed_to_every_provider(self) -> None:
        from hunterx.infrastructure.ai import DeepSeekClient

        client = build_ai_client(
            AISettings(provider="deepseek", model="deepseek-coder", deepseek_key="sk-ds-1")
        )
        assert isinstance(client, DeepSeekClient)
        assert client.model == "deepseek-coder"


class TestFactoryNoGlobalState:
    def test_two_calls_produce_independent_clients(self) -> None:
        first = build_ai_client(AISettings(provider="openrouter", openrouter_key="sk-a"))
        second = build_ai_client(AISettings(provider="openrouter", openrouter_key="sk-b"))
        assert first is not second
        assert isinstance(first, OpenRouterClient)
        assert isinstance(second, OpenRouterClient)
