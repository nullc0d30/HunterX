# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration: external AI configuration → platform composition.

Verifies the full path from ``.env``/environment through ``AISettings`` and
the provider factory into the composed platform. No real API calls are made.
"""

from __future__ import annotations

import pytest

from hunterx.config.loader import load_default_settings
from hunterx.config.settings import AISettings, Settings
from hunterx.domain.ports.services import AIPort
from hunterx.infrastructure.ai import NullAIClient, OpenRouterClient
from hunterx.platform import build_platform


class TestPlatformAiWiring:
    def test_default_platform_uses_null_client(self) -> None:
        platform = build_platform(Settings())
        assert isinstance(platform.ai, NullAIClient)
        assert isinstance(platform.resolve(AIPort), NullAIClient)
        assert platform.resolve(AIPort) is platform.ai

    def test_openrouter_settings_select_openrouter_client(self) -> None:
        settings = Settings(
            ai=AISettings(
                provider="openrouter",
                model="deepseek/deepseek-chat",
                openrouter_key="sk-platform-secret",
            )
        )
        platform = build_platform(settings)
        assert isinstance(platform.ai, OpenRouterClient)
        assert platform.resolve(AIPort) is platform.ai
        assert "sk-platform-secret" not in repr(platform.ai)

    def test_openrouter_client_does_not_make_network_calls_at_composition(self) -> None:
        settings = Settings(ai=AISettings(provider="openrouter", openrouter_key="sk-x"))
        platform = build_platform(settings)
        assert isinstance(platform.ai, OpenRouterClient)


class TestEndToEndEnvironment:
    def test_env_values_flow_through_settings_to_factory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in (
            "HUNTERX_AI_PROVIDER",
            "HUNTERX_AI_MODEL",
            "HUNTERX_AI_OPENROUTER_KEY",
        ):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("HUNTERX_AI_PROVIDER", "openrouter")
        monkeypatch.setenv("HUNTERX_AI_MODEL", "deepseek/deepseek-chat")
        monkeypatch.setenv("HUNTERX_AI_OPENROUTER_KEY", "sk-env-flow")

        settings = load_default_settings()
        assert settings.ai.provider == "openrouter"
        assert settings.ai.model == "deepseek/deepseek-chat"

        platform = build_platform(settings)
        assert isinstance(platform.ai, OpenRouterClient)
        assert "sk-env-flow" not in repr(platform.ai)
