# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: Alembic migrations up and down against SQLite."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config

sqlalchemy = pytest.importorskip("sqlalchemy")


@pytest.fixture
def alembic_config(tmp_path) -> Config:
    from pathlib import Path

    import hunterx.infrastructure.db.sql.tidb_models  # noqa: F401

    repo_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(repo_root / "alembic.ini"))
    db_url = f"sqlite:///{tmp_path / 'migrate.db'}"
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_upgrade_creates_all_tables(alembic_config: Config) -> None:
    command.upgrade(alembic_config, "head")

    import sqlalchemy as sa

    from hunterx.infrastructure.db.sql.tidb_models import Base

    engine = sa.create_engine(alembic_config.get_main_option("sqlalchemy.url"))
    with engine.connect() as conn:
        tables = set(sa.inspect(conn).get_table_names())
    engine.dispose()

    expected = set(Base.metadata.tables)
    missing = expected - tables
    assert not missing, f"tables missing after upgrade: {sorted(missing)}"


def test_downgrade_drops_all_tables(alembic_config: Config) -> None:
    command.upgrade(alembic_config, "head")
    command.downgrade(alembic_config, "base")

    import sqlalchemy as sa

    engine = sa.create_engine(alembic_config.get_main_option("sqlalchemy.url"))
    with engine.connect() as conn:
        tables = set(sa.inspect(conn).get_table_names())
    engine.dispose()

    assert tables == {"alembic_version"}
