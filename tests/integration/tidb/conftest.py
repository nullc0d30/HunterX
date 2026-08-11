# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for the TIDB persistence certification suite.

Provides both SQL-backed and in-memory TIDB repository factories over the same
port so the certification tests can exercise equivalent semantics on both
backends (Sprint 034.3 — persistence & data-isolation certification).
"""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from hunterx.config.settings import DatabaseSettings
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory


@pytest.fixture()
def session_factory() -> SessionFactory:
    """A disposable SQL session factory over in-memory SQLite."""
    factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
    factory.create_all()
    try:
        yield factory
    finally:
        factory.dispose()


@pytest.fixture()
def sql_factory(session_factory: SessionFactory) -> SqlTidbRepositoryFactory:
    """SQL TIDB repository factory bound to the disposable schema."""
    return SqlTidbRepositoryFactory(session_factory)


@pytest.fixture()
def memory_factory() -> InMemoryTidbRepositoryFactory:
    """In-memory TIDB repository factory."""
    return InMemoryTidbRepositoryFactory()


@pytest.fixture(params=["sql", "memory"])
def backend_factory(request, sql_factory, memory_factory):
    """Parametrized factory that resolves to SQL or in-memory per test run."""
    return sql_factory if request.param == "sql" else memory_factory
