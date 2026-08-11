# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Alembic migration environment for the HunterX TIDB.

The target metadata is the shared declarative ``Base`` with every legacy and
TIDB model imported, so ``autogenerate`` covers the whole schema. The database
URL comes from ``HUNTERX_DB_URL`` when set, otherwise from the
``sqlalchemy.url`` value in ``alembic.ini``.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure the v7 package (src/) shadows the legacy v6 flat hunterx/ package
# regardless of the platform's path separator.
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
else:
    sys.path.remove(str(_SRC))
    sys.path.insert(0, str(_SRC))

# Importing the model packages registers every table with the shared metadata.
import hunterx.infrastructure.db.sql.models  # noqa: F401
import hunterx.infrastructure.db.sql.tidb_models  # noqa: F401
from hunterx.infrastructure.db.sql.factory import get_base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = get_base().metadata

env_url = os.environ.get("HUNTERX_DB_URL")
if env_url:
    config.set_main_option("sqlalchemy.url", env_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
