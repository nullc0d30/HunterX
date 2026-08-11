# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: SQLAlchemy repositories against an in-memory SQLite DB."""

from __future__ import annotations

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.infrastructure.db.sql.repositories import (
    SqlFindingRepository,
    SqlMissionRepository,
)

sqlalchemy = pytest.importorskip("sqlalchemy")


@pytest.fixture
def session_factory() -> SessionFactory:
    """A fresh in-memory SQLite session factory with tables created."""
    factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
    factory.create_all()
    yield factory
    factory.dispose()


class TestSqlMissionRepository:
    def test_save_and_get_roundtrip(self, session_factory: SessionFactory) -> None:
        from hunterx.domain.entities import Mission

        repository = SqlMissionRepository(session_factory)
        mission = Mission(name="web", workflow="smoke", targets=["example.com"])
        repository.save(mission)

        loaded = repository.get(mission.mission_id)
        assert loaded is not None
        assert loaded.name == "web"
        assert loaded.targets == ["example.com"]

    def test_list_by_status(self, session_factory: SessionFactory) -> None:
        from hunterx.domain.entities import Mission

        repository = SqlMissionRepository(session_factory)
        repository.save(Mission(name="a", workflow="w", targets=["x"]))
        repository.save(Mission(name="b", workflow="w", targets=["y"]))
        pending = repository.list_by_status("pending")
        assert len(pending) == 2


class TestSqlFindingRepository:
    def test_save_and_deduplicate(self, session_factory: SessionFactory) -> None:
        from hunterx.domain.entities import Finding
        from hunterx.domain.value_objects import Severity

        repository = SqlFindingRepository(session_factory)
        first = Finding(title="XSS", severity=Severity.HIGH, target="a", tool="t")
        first.compute_content_hash()
        repository.save(first)
        assert repository.exists_by_content_hash(first.content_hash)

        second = Finding(title="XSS", severity=Severity.HIGH, target="a", tool="t")
        second.compute_content_hash()
        assert second.content_hash == first.content_hash
        assert repository.exists_by_content_hash(second.content_hash)
