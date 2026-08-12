# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: SessionFactory.create_all race-tolerance."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.infrastructure.db.sql.factory import SessionFactory

pytest.importorskip("sqlalchemy")


@pytest.fixture()
def factory() -> SessionFactory:
    return SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))


def _load_mod(metadata, operational_error):
    return {"Base": Mock(metadata=metadata), "OperationalError": operational_error}


def _operational_error(message: str):
    from sqlalchemy.exc import OperationalError

    return OperationalError("CREATE TABLE", {}, Exception(message))


def _mock_mod(factory: SessionFactory, metadata) -> patch:
    return patch(
        "hunterx.infrastructure.db.sql.factory._load_sqlalchemy",
        return_value={
            "Base": Mock(metadata=metadata),
            "OperationalError": _operational_error("").__class__,
        },
    )


def test_create_all_retries_on_already_exists(factory: SessionFactory) -> None:
    metadata = Mock()
    metadata.create_all.side_effect = [
        _operational_error("table hunterx_abilities already exists"),
        None,
    ]
    with patch.object(factory, "_engine", new=Mock()), _mock_mod(factory, metadata):
        factory.create_all()
    assert metadata.create_all.call_count == 2


def test_create_all_retries_on_locked(factory: SessionFactory) -> None:
    metadata = Mock()
    metadata.create_all.side_effect = [
        _operational_error("database is locked"),
        _operational_error("database is locked"),
        None,
    ]
    with patch.object(factory, "_engine", new=Mock()), _mock_mod(factory, metadata):
        factory.create_all()
    assert metadata.create_all.call_count == 3


def test_create_all_retries_on_schema_changed(factory: SessionFactory) -> None:
    metadata = Mock()
    metadata.create_all.side_effect = [
        _operational_error("(sqlite3.OperationalError) database schema has changed"),
        None,
    ]
    with patch.object(factory, "_engine", new=Mock()), _mock_mod(factory, metadata):
        factory.create_all()
    assert metadata.create_all.call_count == 2


def test_create_all_raises_non_transient(factory: SessionFactory) -> None:
    metadata = Mock()
    metadata.create_all.side_effect = _operational_error("disk I/O error")
    with patch.object(factory, "_engine", new=Mock()), _mock_mod(factory, metadata), pytest.raises(
        Exception, match="disk I/O error"
    ):
        factory.create_all()
    assert metadata.create_all.call_count == 1


def test_create_all_raises_after_exhausting_retries(factory: SessionFactory) -> None:
    metadata = Mock()
    metadata.create_all.side_effect = _operational_error("database is locked")
    with (
        patch.object(factory, "_engine", new=Mock()),
        _mock_mod(factory, metadata),
        pytest.raises(Exception, match="database is locked"),
        patch("hunterx.infrastructure.db.sql.factory.time.sleep"),
    ):
        factory.create_all()
    assert metadata.create_all.call_count == 25
