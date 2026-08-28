# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for external AI configuration (AISettings / .env / masking)."""

from __future__ import annotations

import os

import pytest

from hunterx.config.loader import load_default_settings, load_env_file
from hunterx.config.settings import AISettings, Settings

_AI_ENV_KEYS = (
    "HUNTERX_AI_PROVIDER",
    "HUNTERX_AI_MODEL",
    "HUNTERX_AI_OPENAI_KEY",
    "HUNTERX_AI_ANTHROPIC_KEY",
    "HUNTERX_AI_OPENROUTER_KEY",
    "HUNTERX_AI_GEMINI_KEY",
    "HUNTERX_AI_DEEPSEEK_KEY",
    "HUNTERX_AI_GROK_KEY",
)


def _unset_ai_env(monkeypatch: pytest.MonkeyPatch, tmp_path: object | None = None) -> None:
    """Clear AI configuration from BOTH the environment and .env discovery.

    Discovery intentionally searches the working directory (and install
    locations), so tests must opt out explicitly to stay hermetic and to
    guarantee real credentials never enter test state or assertion output.
    """
    for key in _AI_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HUNTERX_SKIP_ENV_FILE", "1")
    if tmp_path is not None:
        monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]


class TestAISettingsDefaults:
    def test_defaults_are_safe(self) -> None:
        settings = Settings()
        assert settings.ai.provider == ""
        assert settings.ai.model == ""
        assert settings.ai.api_key_for("openrouter") == ""
        assert settings.ai.api_key_for("openai") == ""

    def test_api_key_for_unknown_provider_returns_empty(self) -> None:
        assert AISettings().api_key_for("not-a-provider") == ""


class TestAISettingsFromEnvironment:
    def test_ai_settings_load_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _unset_ai_env(monkeypatch)
        monkeypatch.setenv("HUNTERX_AI_PROVIDER", "openrouter")
        monkeypatch.setenv("HUNTERX_AI_MODEL", "deepseek/deepseek-chat")
        monkeypatch.setenv("HUNTERX_AI_OPENROUTER_KEY", "sk-openrouter-123")
        settings = load_default_settings()
        assert settings.ai.provider == "openrouter"
        assert settings.ai.model == "deepseek/deepseek-chat"
        assert settings.ai.api_key_for("openrouter") == "sk-openrouter-123"

    def test_each_provider_key_env_var_is_mapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _unset_ai_env(monkeypatch)
        mapping = {
            "HUNTERX_AI_OPENAI_KEY": ("openai", "sk-openai-1"),
            "HUNTERX_AI_ANTHROPIC_KEY": ("anthropic", "sk-anthropic-1"),
            "HUNTERX_AI_OPENROUTER_KEY": ("openrouter", "sk-openrouter-1"),
            "HUNTERX_AI_GEMINI_KEY": ("gemini", "sk-gemini-1"),
            "HUNTERX_AI_DEEPSEEK_KEY": ("deepseek", "sk-deepseek-1"),
            "HUNTERX_AI_GROK_KEY": ("grok", "sk-grok-1"),
        }
        for env_key, (_provider, _) in mapping.items():
            monkeypatch.setenv(env_key, "sk-x")
        settings = load_default_settings()
        for env_key, (provider, _) in mapping.items():
            assert settings.ai.api_key_for(provider) == "sk-x", env_key

    def test_missing_keys_are_handled_safely(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
        _unset_ai_env(monkeypatch, tmp_path)
        monkeypatch.setenv("HUNTERX_AI_PROVIDER", "openrouter")
        settings = load_default_settings()
        assert settings.ai.api_key_for("openrouter") == ""

    def test_missing_provider_is_handled_safely(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
        _unset_ai_env(monkeypatch, tmp_path)
        monkeypatch.setenv("HUNTERX_AI_OPENROUTER_KEY", "sk-orphaned")
        settings = load_default_settings()
        assert settings.ai.provider == ""


class TestEnvFile:
    def test_env_file_loads_values(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
        _unset_ai_env(monkeypatch)
        env_file = tmp_path / ".env"
        env_file.write_text(
            "HUNTERX_AI_PROVIDER=openrouter\n"
            "HUNTERX_AI_MODEL=deepseek/deepseek-chat\n"
            "HUNTERX_AI_OPENROUTER_KEY=sk-from-env-file\n",
            encoding="utf-8",
        )
        load_env_file(env_file)
        assert os.environ.get("HUNTERX_AI_PROVIDER") == "openrouter"
        settings = load_default_settings()
        assert settings.ai.provider == "openrouter"
        assert settings.ai.model == "deepseek/deepseek-chat"
        assert settings.ai.api_key_for("openrouter") == "sk-from-env-file"

    def test_real_environment_wins_over_env_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
        _unset_ai_env(monkeypatch)
        monkeypatch.setenv("HUNTERX_AI_OPENROUTER_KEY", "sk-real-env")
        env_file = tmp_path / ".env"
        env_file.write_text("HUNTERX_AI_OPENROUTER_KEY=sk-file\n", encoding="utf-8")
        load_env_file(env_file)
        settings = load_default_settings()
        assert settings.ai.api_key_for("openrouter") == "sk-real-env"

    def test_env_file_missing_is_noop(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory) -> None:
        _unset_ai_env(monkeypatch)
        load_env_file(tmp_path / "does-not-exist.env")
        assert os.environ.get("HUNTERX_AI_PROVIDER") is None


class TestSecretMasking:
    def test_secrets_never_appear_in_settings_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _unset_ai_env(monkeypatch)
        monkeypatch.setenv("HUNTERX_AI_OPENROUTER_KEY", "sk-ultra-secret")
        settings = load_default_settings()
        assert "sk-ultra-secret" not in repr(settings)
        assert "sk-ultra-secret" not in settings.model_dump_json()
        assert "sk-ultra-secret" not in str(settings.model_dump(mode="json"))

    def test_settings_dump_masks_key_value(self) -> None:
        settings = Settings(ai=AISettings(openrouter_key="sk-visible-marker"))
        dumped = settings.model_dump(mode="json")
        assert dumped["ai"]["openrouter_key"] == "**********"
        assert "sk-visible-marker" not in str(dumped)

    def test_cli_config_output_is_masked(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        _unset_ai_env(monkeypatch)
        monkeypatch.setenv("HUNTERX_AI_OPENROUTER_KEY", "sk-cli-secret")
        from hunterx.cli.app import CliApplication
        from hunterx.cli.commands import register_default_commands

        app = CliApplication()
        register_default_commands(app)
        code = app.run(["config"])
        captured = capsys.readouterr().out
        assert code == 0
        assert "sk-cli-secret" not in captured
        assert "**********" in captured
