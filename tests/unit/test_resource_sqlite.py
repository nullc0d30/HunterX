# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Persistence tests: SQLite resource-safe configuration.

The file-backed SQLite engine must be opened with WAL journaling, a busy
timeout and concurrent-reader support so the autonomous mission (single writer,
many short sessions) never deadlocks on ``database is locked``.
"""

from __future__ import annotations

import os
import tempfile

from hunterx.config.settings import DatabaseSettings
from hunterx.infrastructure.db.sql.factory import create_engine_from_settings


def _fresh_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="hunterx-wal-test-")
    os.close(fd)
    os.remove(path)
    return path


def test_file_backed_sqlite_uses_wal_and_busy_timeout() -> None:
    path = _fresh_db()
    try:
        engine = create_engine_from_settings(DatabaseSettings(url=f"sqlite:///{path}"))
        with engine.connect() as connection:
            journal = connection.exec_driver_sql("PRAGMA journal_mode").scalar()
            busy_timeout = connection.exec_driver_sql("PRAGMA busy_timeout").scalar()
            foreign_keys = connection.exec_driver_sql("PRAGMA foreign_keys").scalar()
        engine.dispose()
        assert journal == "wal"
        assert busy_timeout == 30000
        assert foreign_keys == 1
    finally:
        for suffix in ("", "-wal", "-shm"):
            candidate = f"{path}{suffix}"
            if os.path.exists(candidate):
                os.remove(candidate)


def test_in_memory_sqlite_still_works() -> None:
    engine = create_engine_from_settings(DatabaseSettings(url="sqlite:///:memory:"))
    with engine.connect() as connection:
        value = connection.exec_driver_sql("SELECT 1").scalar()
    engine.dispose()
    assert value == 1


__all__ = []
