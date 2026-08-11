# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Migration validation (Sprint 034.3 §14, §15).

Fresh database → alembic upgrade head → schema inspection → data insertion →
alembic downgrade base → alembic upgrade again → alembic check (no drift).
"""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("alembic")

from pathlib import Path

from alembic import command
from alembic.config import Config

from hunterx.infrastructure.db.sql.factory import get_base

REPO_ROOT = Path(__file__).resolve().parents[3]


def _alembic_config(db_path: Path) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    import hunterx.infrastructure.db.sql.tidb_models  # noqa: F401  (register models)
    return cfg


@pytest.fixture(scope="module")
def db_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("tidb_migrations") / "migrate.db"


def _table_names(db_path: Path) -> set[str]:
    import sqlite3

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return {r[0] for r in rows}
    finally:
        con.close()


def test_fresh_upgrade_creates_full_schema(db_file: Path) -> None:
    db_file.unlink(missing_ok=True)
    command.upgrade(_alembic_config(db_file), "head")

    tables = _table_names(db_file)
    expected = set(get_base().metadata.tables)
    assert expected.issubset(tables)
    assert sum(1 for t in tables if t.startswith("tidb_")) == 401
    assert sum(1 for t in tables if t.startswith("hunterx_")) == 6


def test_schema_is_insertable_and_retrievable(db_file: Path) -> None:
    command.upgrade(_alembic_config(db_file), "head")
    import sqlite3

    con = sqlite3.connect(db_file)
    try:
        con.execute(
            "INSERT INTO tidb_intelligence_targets (id, created_at, updated_at, first_seen, last_seen, "
            "version, revision, schema_version, deleted_at, meta, target_id, mission_id, scope, identity, "
            "classification, criticality, kind, value, status, confidence, phase, tenant, "
            "intelligence_state, coverage_state) VALUES (?, ?, NULL, NULL, NULL, 1, 1, 1, NULL, '{}', "
            "'tgt-1', 'mis-1', 'prod', 'acme.com', 'web', 5, 'domain', 'acme.com', 'active', 0.9, "
            "'recon', 'tenant-1', '{}', '{}')",
            ("01JTESTTARGET000000000000A", "2026-08-10T00:00:00+00:00"),
        )
        con.commit()
        row = con.execute(
            "SELECT target_id, value, status FROM tidb_intelligence_targets WHERE id=?",
            ("01JTESTTARGET000000000000A",),
        ).fetchone()
        assert row == ("tgt-1", "acme.com", "active")
    finally:
        con.close()


def test_downgrade_base_empties_schema(db_file: Path) -> None:
    command.upgrade(_alembic_config(db_file), "head")
    command.downgrade(_alembic_config(db_file), "base")
    tables = _table_names(db_file)
    assert tables == {"alembic_version"}


def test_upgrade_again_restores_schema_and_rejects_drift(db_file: Path) -> None:
    command.upgrade(_alembic_config(db_file), "head")
    command.downgrade(_alembic_config(db_file), "base")
    command.upgrade(_alembic_config(db_file), "head")

    tables = _table_names(db_file)
    expected = set(get_base().metadata.tables)
    assert expected.issubset(tables)

    # Schema-drift validation: models and migrations must be in sync.
    command.check(_alembic_config(db_file))


def test_all_migrations_are_forward_only_table_creation(db_file: Path) -> None:
    """Every migration revision must be a pure create-table/create-index step.

    There are no data-mutating migrations (no ALTER/DROP columns), so existing
    data cannot be damaged by an upgrade (Sprint 034.3 §15).
    """
    import re

    versions_dir = REPO_ROOT / "alembic" / "versions"
    for path in versions_dir.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "op.add_column" not in text, f"{path.name} alters columns"
        assert "op.drop_column" not in text, f"{path.name} drops columns"
        assert "op.alter_column" not in text, f"{path.name} alters columns"
        assert "op.create_unique_constraint" not in text, f"{path.name} mutates constraints"
        assert re.search(r"\bop\.(create_table|create_index)\b", text) or "op.bulk_insert" in text


def test_migration_chain_is_linear(db_file: Path) -> None:
    import alembic.script as script_mod

    script = script_mod.ScriptDirectory.from_config(_alembic_config(db_file))
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head, got {heads}"
    revisions = {r.revision for r in script.walk_revisions()}
    assert "a3f5b7c9d1e3" in revisions
    assert len(revisions) == 21, f"expected 21 revisions, got {len(revisions)}"
