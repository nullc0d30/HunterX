# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for the data-isolation security certification suite."""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from hunterx.config.settings import DatabaseSettings, Settings
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.platform import build_platform


@pytest.fixture()
def session_factory() -> SessionFactory:
    factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
    factory.create_all()
    try:
        yield factory
    finally:
        factory.dispose()


@pytest.fixture()
def sql_factory(session_factory: SessionFactory) -> SqlTidbRepositoryFactory:
    return SqlTidbRepositoryFactory(session_factory)


@pytest.fixture()
def memory_factory() -> InMemoryTidbRepositoryFactory:
    return InMemoryTidbRepositoryFactory()


@pytest.fixture(params=["sql", "memory"])
def factory(request, sql_factory, memory_factory):
    return sql_factory if request.param == "sql" else memory_factory


@pytest.fixture(scope="module")
def platform():
    platform = build_platform(Settings(database=DatabaseSettings(url="sqlite:///:memory:")))
    try:
        yield platform
    finally:
        session_factory = platform.repositories.get("session_factory")
        if session_factory is not None:
            session_factory.dispose()


@pytest.fixture(scope="module")
def client(platform):
    from fastapi.testclient import TestClient

    from hunterx.api.app import create_app

    app = create_app(platform=platform)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def tenant_id() -> str:
    return "tenant-cert"
