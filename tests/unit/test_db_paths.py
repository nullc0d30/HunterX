# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the database-path / persistence behaviour.

Covers the database-path contract:

- the default database URL resolves to ``<application root>/data/hunterx.db``
  (never a CWD-relative ``./hunterx.db``);
- ``HUNTERX_DATA_DIR`` overrides the data directory;
- the ``data/`` directory is created automatically before SQLAlchemy opens the
  database;
- an explicitly configured ``HUNTERX_DATABASE_URL`` is honoured unchanged;
- ``:memory:`` databases are untouched;
- the API forces the SQL persistence layer (no silent in-memory fallback).
"""

from __future__ import annotations

import pathlib

import pytest

from hunterx.config.paths import (
    hunterx_data_dir,
    hunterx_root,
    resolve_database_url,
)
from hunterx.config.settings import DatabaseSettings
from hunterx.infrastructure.db.sql.factory import create_engine_from_settings

pytest.importorskip("sqlalchemy")


class TestDatabasePathResolution:
    def test_default_url_resolves_into_data_directory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("HUNTERX_DATA_DIR", raising=False)
        monkeypatch.delenv("HUNTERX_ROOT", raising=False)
        resolved = resolve_database_url("sqlite:///hunterx.db")
        db_path = pathlib.Path(resolved[len("sqlite:///"):])
        assert resolved.startswith("sqlite:////")
        assert db_path.parent == hunterx_root() / "data"
        assert db_path.name == "hunterx.db"

    def test_data_dir_is_derived_from_root(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("HUNTERX_DATA_DIR", raising=False)
        assert hunterx_data_dir() == hunterx_root() / "data"

    def test_env_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERX_DATA_DIR", "/tmp/hx-custom-data")
        assert hunterx_data_dir() == pathlib.Path("/tmp/hx-custom-data")

    def test_explicit_url_is_untouched(self) -> None:
        explicit = "sqlite:////custom/absolute/path/hunterx.db"
        assert resolve_database_url(explicit) == explicit

    def test_memory_url_is_untouched(self) -> None:
        assert resolve_database_url("sqlite:///:memory:") == "sqlite:///:memory:"

    def test_root_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERX_ROOT", "/srv/hunterx-app")
        monkeypatch.delenv("HUNTERX_DATA_DIR", raising=False)
        assert hunterx_root() == pathlib.Path("/srv/hunterx-app")
        assert hunterx_data_dir() == pathlib.Path("/srv/hunterx-app/data")


class TestDirectoryAutoCreation:
    def test_engine_creation_creates_data_directory(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_dir = tmp_path / "nested" / "data"
        monkeypatch.setenv("HUNTERX_DATA_DIR", str(data_dir))
        engine = create_engine_from_settings(DatabaseSettings(url="sqlite:///hunterx.db"))
        try:
            assert data_dir.is_dir(), "data/ must be created before the engine is built"
            engine.connect().close()
            assert (data_dir / "hunterx.db").is_file(), "SQLite file must be created on connect"
        finally:
            engine.dispose()

    def test_explicit_url_parent_dir_created(self, tmp_path: pathlib.Path) -> None:
        target = tmp_path / "a" / "b" / "custom.db"
        engine = create_engine_from_settings(DatabaseSettings(url=f"sqlite:///{target}"))
        try:
            assert target.parent.is_dir()
            engine.connect().close()
            assert target.is_file()
        finally:
            engine.dispose()

    def test_memory_engine_creates_no_directory(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERX_DATA_DIR", str(tmp_path / "should-not-exist"))
        engine = create_engine_from_settings(DatabaseSettings(url="sqlite:///:memory:"))
        engine.dispose()
        assert not (tmp_path / "should-not-exist").exists()


class TestAPIPersistence:
    def test_create_app_forces_sql_persistence(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
        pytest.importorskip("fastapi")
        data_dir = tmp_path / "hx-api-data"
        monkeypatch.setenv("HUNTERX_DATA_DIR", str(data_dir))

        from hunterx.api.app import create_app

        app = create_app()
        platform = app.state.platform
        assert "session_factory" in platform.repositories
        assert data_dir.is_dir()
        assert (data_dir / "hunterx.db").is_file()
