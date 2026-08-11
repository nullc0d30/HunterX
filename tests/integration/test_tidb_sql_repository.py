# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: SQL-backed TIDB CRUD repository against SQLite."""

from __future__ import annotations

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.entities.tidb import (
    URL,
    Domain,
    Organization,
    Port,
    PortState,
    Program,
    ProgramStatus,
    Service,
    ServiceState,
)
from hunterx.domain.exceptions import NotFoundError
from hunterx.infrastructure.db.sql.crud import SqlCrudRepository, SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory

sqlalchemy = pytest.importorskip("sqlalchemy")


@pytest.fixture
def session_factory() -> SessionFactory:
    factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
    factory.create_all()
    yield factory
    factory.dispose()


@pytest.fixture
def repo(session_factory: SessionFactory) -> SqlCrudRepository:
    return SqlCrudRepository(session_factory, Organization)


def test_save_and_get_roundtrip(repo: SqlCrudRepository) -> None:
    org = Organization(name="Acme", industry="security", meta={"env": "prod"})
    repo.save(org)
    loaded = repo.get(org.id)
    assert loaded is not None
    assert loaded.name == "Acme"
    assert loaded.meta == {"env": "prod"}


def test_upsert_updates_row(repo: SqlCrudRepository) -> None:
    org = Organization(name="Before")
    repo.save(org)
    org.name = "After"
    repo.save(org)
    assert repo.count() == 1
    assert repo.get(org.id).name == "After"


def test_soft_delete_hides_and_restores(repo: SqlCrudRepository) -> None:
    org = Organization(name="Secret")
    repo.save(org)
    repo.soft_delete(org.id)
    assert repo.count() == 0
    assert repo.get(org.id) is None
    assert repo.get(org.id, include_deleted=True) is not None
    assert repo.count(include_deleted=True) == 1


def test_hard_delete(repo: SqlCrudRepository) -> None:
    org = Organization(name="Temp")
    repo.save(org)
    repo.delete(org.id)
    assert repo.count() == 0
    assert repo.count(include_deleted=True) == 0
    with pytest.raises(NotFoundError):
        repo.delete(org.id)


def test_get_or_raise(repo: SqlCrudRepository) -> None:
    with pytest.raises(NotFoundError):
        repo.get_or_raise("missing")


def test_save_many_bulk(repo: SqlCrudRepository) -> None:
    orgs = [Organization(name=f"org-{i}") for i in range(20)]
    assert repo.save_many(orgs) == 20
    assert repo.count() == 20


def test_list_pagination_and_ordering(repo: SqlCrudRepository) -> None:
    orgs = [Organization(name=f"org-{i:02d}") for i in range(10)]
    repo.save_many(orgs)
    page = repo.list(limit=3, offset=2, order_by="name", descending=False)
    assert [e.name for e in page] == ["org-02", "org-03", "org-04"]


def test_list_by_field(session_factory: SessionFactory) -> None:
    repo = SqlCrudRepository(session_factory, Organization)
    repo.save_many(
        [
            Organization(name="a", industry="security"),
            Organization(name="b", industry="finance"),
            Organization(name="c", industry="security"),
        ]
    )
    matches = repo.list_by("industry", "security")
    assert {e.name for e in matches} == {"a", "c"}


def test_stream_batches(session_factory: SessionFactory) -> None:
    repo = SqlCrudRepository(session_factory, URL)
    repo.save_many([URL(url=f"https://example.com/{i}") for i in range(2500)])
    streamed = list(repo.stream(batch_size=500))
    assert len(streamed) == 2500
    assert repo.count() == 2500


def test_enum_columns_roundtrip(session_factory: SessionFactory) -> None:
    repo = SqlCrudRepository(session_factory, Program)
    prog = Program(organization_id="org", name="scope", status=ProgramStatus.ACTIVE)
    repo.save(prog)
    assert repo.get(prog.id).status is ProgramStatus.ACTIVE


def test_port_and_service_roundtrip(session_factory: SessionFactory) -> None:
    port_repo = SqlCrudRepository(session_factory, Port)
    service_repo = SqlCrudRepository(session_factory, Service)
    port = Port(ip_address_id="ip-1", number=8080, state=PortState.OPEN)
    port_repo.save(port)
    service = Service(port_id=port.id, name="http", state=ServiceState.UP)
    service_repo.save(service)
    assert port_repo.get(port.id).state is PortState.OPEN
    assert service_repo.get(service.id).state is ServiceState.UP


def test_factory_builds_all_entities(session_factory: SessionFactory) -> None:
    factory = SqlTidbRepositoryFactory(session_factory)
    org_repo = factory.repository_for(Organization)
    domain_repo = factory.repository_for(Domain)
    assert isinstance(org_repo, SqlCrudRepository)
    assert isinstance(domain_repo, SqlCrudRepository)
    assert factory.repository_for(Organization) is org_repo
    assert Program in factory.available_entities


def test_invalid_order_by_column(repo: SqlCrudRepository) -> None:
    with pytest.raises(ValueError):
        repo.list(order_by="does_not_exist")


def test_invalid_list_by_column(repo: SqlCrudRepository) -> None:
    with pytest.raises(ValueError):
        repo.list_by("does_not_exist", 1)
