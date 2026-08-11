# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: TIDB versioning/audit listener."""

from __future__ import annotations

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.entities.tidb import Organization
from hunterx.infrastructure.db.sql.crud import SqlCrudRepository
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.infrastructure.db.sql.tidb_models import (
    AuditEventModel,
    AuditLogModel,
    ChangeHistoryModel,
    TimelineEventModel,
    VersionHistoryModel,
)
from hunterx.infrastructure.db.sql.versioning import install_versioning

sqlalchemy = pytest.importorskip("sqlalchemy")


@pytest.fixture
def session_factory() -> SessionFactory:
    factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
    factory.create_all()
    install_versioning(factory, actor="tester", source="pytest")
    yield factory
    factory.dispose()


@pytest.fixture
def repo(session_factory: SessionFactory) -> SqlCrudRepository:
    return SqlCrudRepository(session_factory, Organization)


def test_create_records_audit_and_version(session_factory: SessionFactory, repo: SqlCrudRepository) -> None:
    org = Organization(name="Acme")
    repo.save(org)
    with session_factory.session() as session:
        logs = session.query(AuditLogModel).all()
        assert len(logs) == 1
        assert logs[0].action == "create"
        assert logs[0].object_type == "organization"
        assert logs[0].object_id == org.id
        assert logs[0].actor == "tester"
        assert logs[0].after["name"] == "Acme"

        versions = session.query(VersionHistoryModel).all()
        assert len(versions) == 1
        assert versions[0].reason == "create"
        assert versions[0].recorded_version == org.version

        timeline = session.query(TimelineEventModel).all()
        assert len(timeline) == 1
        assert timeline[0].event_type == "organization.created"


def test_update_records_field_history(session_factory: SessionFactory, repo: SqlCrudRepository) -> None:
    org = Organization(name="Acme", industry="old")
    repo.save(org)
    org.touch()
    org.name = "Acme Corp"
    org.industry = "security"
    repo.save(org)

    with session_factory.session() as session:
        logs = session.query(AuditLogModel).order_by(AuditLogModel.created_at).all()
        assert len(logs) == 2
        update = logs[-1]
        assert update.action == "update"
        assert update.before["name"] == "Acme"
        assert update.after["name"] == "Acme Corp"

        changes = session.query(ChangeHistoryModel).all()
        changed_fields = {c.field_name for c in changes}
        assert "name" in changed_fields
        assert "industry" in changed_fields

        versions = session.query(VersionHistoryModel).all()
        assert len(versions) == 2
        assert versions[-1].reason == "update"


def test_soft_delete_records_delete_action(session_factory: SessionFactory, repo: SqlCrudRepository) -> None:
    org = Organization(name="Secret")
    repo.save(org)
    repo.soft_delete(org.id)

    with session_factory.session() as session:
        logs = session.query(AuditLogModel).order_by(AuditLogModel.created_at).all()
        delete = logs[-1]
        assert delete.action == "delete"
        assert delete.before["deleted_at"] is None
        assert delete.after["deleted_at"] is not None
        timeline = session.query(TimelineEventModel).all()
        assert timeline[-1].event_type == "organization.updated"


def test_hard_delete_records_delete(session_factory: SessionFactory, repo: SqlCrudRepository) -> None:
    org = Organization(name="Temp")
    repo.save(org)
    repo.delete(org.id)

    with session_factory.session() as session:
        logs = session.query(AuditLogModel).order_by(AuditLogModel.created_at).all()
        assert len(logs) == 2
        assert logs[-1].action == "delete"
        assert logs[-1].after is None
        assert logs[-1].before["name"] == "Temp"


def test_audit_rows_are_not_themselves_versioned(session_factory: SessionFactory, repo: SqlCrudRepository) -> None:
    org = Organization(name="One")
    repo.save(org)
    org.touch()
    repo.save(org)

    with session_factory.session() as session:
        assert session.query(AuditLogModel).count() == 2
        assert session.query(AuditEventModel).count() == 0
        assert session.query(VersionHistoryModel).count() == 2


def test_without_listener_no_audit_written() -> None:
    factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
    factory.create_all()
    repo = SqlCrudRepository(factory, Organization)
    repo.save(Organization(name="Silent"))
    with factory.session() as session:
        assert session.query(AuditLogModel).count() == 0
    factory.dispose()
