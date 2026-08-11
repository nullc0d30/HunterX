# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the configuration manager."""

from __future__ import annotations

import pytest

from hunterx.config.loader import ConfigurationManager, load_default_settings
from hunterx.config.settings import Settings


class TestConfigLoader:
    def test_load_default_settings(self) -> None:
        settings = load_default_settings()
        assert isinstance(settings, Settings)
        assert settings.app_name == "HunterX"
        assert settings.database.url.startswith("sqlite")
        assert settings.cache.backend == "memory"
        assert settings.queue.backend == "memory"

    def test_configuration_manager(self) -> None:
        manager = ConfigurationManager()
        assert manager.log_level() == "INFO"
        assert manager.settings.environment in {"production", "dev", "staging"}

    def test_masked_environment_snapshot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERX_TOKEN", "super-secret-value")
        manager = ConfigurationManager()
        snapshot = manager.masked_environment_snapshot()
        assert "super-secret-value" not in " ".join(snapshot.values())
        assert snapshot["HUNTERX_TOKEN"].startswith("s")

    def test_environment_overrides_are_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERX_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("HUNTERX_DATABASE_URL", "sqlite:///envtest.db")
        monkeypatch.setenv("HUNTERX_API_PORT", "9090")
        settings = load_default_settings()
        assert settings.log_level == "DEBUG"
        assert settings.database.url == "sqlite:///envtest.db"
        assert settings.api.port == 9090

    def test_unknown_environment_variables_are_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERX_TOKEN", "ignored")
        monkeypatch.setenv("HUNTERX_SECRET_API_KEY", "ignored")
        settings = load_default_settings()
        assert settings.app_name == "HunterX"

    def test_environment_override_wins_over_profile(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERX_LOG_LEVEL", "WARNING")
        settings = load_default_settings(env={"HUNTERX_LOG_LEVEL": "ERROR"})
        assert settings.log_level == "ERROR"
