# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for the persistence performance certification suite."""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from hunterx.config.settings import DatabaseSettings
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory


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
