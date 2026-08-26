# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Configuration discovery + guided setup tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.config.guided_setup import validate_configuration
from hunterx.config.loader import discover_env_file, load_default_settings
from hunterx.infrastructure.ai.factory import build_ai_client
from hunterx.infrastructure.ai.null import NullAIClient


class TestEnvDiscovery:
    def test_explicit_env_file_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        env_file = tmp_path / "custom.env"
        env_file.write_text("HUNTERX_AI_PROVIDER=openai\n", encoding="utf-8")
        monkeypatch.setenv("HUNTERX_ENV_FILE", str(env_file))
        assert discover_env_file() == env_file

    def test_data_dir_env_file_discovered(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / ".env").write_text("HUNTERX_AI_MODEL=x\n", encoding="utf-8")
        monkeypatch.delenv("HUNTERX_ENV_FILE", raising=False)
        monkeypatch.setenv("HUNTERX_DATA_DIR", str(data_dir))
        monkeypatch.chdir(tmp_path)  # no cwd .env
        assert discover_env_file() == data_dir / ".env"

    def test_cwd_fallback(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("HUNTERX_ENV_FILE", raising=False)
        monkeypatch.delenv("HUNTERX_DATA_DIR", raising=False)
        (tmp_path / ".env").write_text("HUNTERX_AI_PROVIDER=ollama\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        assert discover_env_file() == tmp_path / ".env"

    def test_load_default_settings_reads_discovered_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("HUNTERX_AI_PROVIDER", raising=False)
        monkeypatch.delenv("HUNTERX_DATA_DIR", raising=False)
        (tmp_path / ".env").write_text(
            "HUNTERX_AI_PROVIDER=openai_compatible\nHUNTERX_AI_BASE_URL=http://127.0.0.1:9/v1\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        settings = load_default_settings()
        assert settings.ai.provider == "openai_compatible"
        assert settings.ai.base_url == "http://127.0.0.1:9/v1"


class TestNullClient:
    def test_null_client_instantiable_and_check_false(self) -> None:
        client = NullAIClient()
        assert client.check() is False


class TestFactory:
    def test_empty_provider_returns_null(self) -> None:
        from hunterx.config.settings import AISettings

        assert isinstance(build_ai_client(AISettings()), NullAIClient)

    def test_provider_without_key_raises_configuration_error(self) -> None:
        from hunterx.config.settings import AISettings
        from hunterx.domain.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError):
            build_ai_client(AISettings(provider="openai"))


class TestGuidedSetupValidation:
    def test_validate_rejects_unreachable_provider(self) -> None:
        ok, message = validate_configuration(
            "openai_compatible",
            "some-model",
            "http://127.0.0.1:9/v1",  # nothing listens here
            "key",
            timeout=2.0,
        )
        assert ok is False
        assert message

    def test_non_interactive_guidance_is_actionable(self, capsys: pytest.CaptureFixture[str]) -> None:
        from hunterx.config.guided_setup import run_guided_configuration

        rc = run_guided_configuration(interactive=False)
        captured = capsys.readouterr().out
        assert rc == 1
        assert "HUNTERX_AI_PROVIDER" in captured
        assert "will NOT silently" in captured
