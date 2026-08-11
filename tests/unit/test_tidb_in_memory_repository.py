# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the in-memory TIDB CRUD repository."""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import Organization, Port, PortState, Program, ProgramStatus
from hunterx.domain.exceptions import NotFoundError
from hunterx.infrastructure.db.sql.memory import InMemoryCrudRepository, InMemoryTidbRepositoryFactory

sqlalchemy = pytest.importorskip("sqlalchemy")


@pytest.fixture
def repo() -> InMemoryCrudRepository:
    return InMemoryCrudRepository(Organization)


def test_save_and_get_roundtrip(repo: InMemoryCrudRepository) -> None:
    org = Organization(name="Acme")
    repo.save(org)
    assert repo.get(org.id).name == "Acme"


def test_get_returns_none_when_absent(repo: InMemoryCrudRepository) -> None:
    assert repo.get("missing") is None
    with pytest.raises(NotFoundError):
        repo.get_or_raise("missing")


def test_save_many_and_count(repo: InMemoryCrudRepository) -> None:
    entities = [Organization(name=f"org-{i}") for i in range(5)]
    assert repo.save_many(entities) == 5
    assert repo.count() == 5


def test_upsert_overwrites(repo: InMemoryCrudRepository) -> None:
    org = Organization(name="Before")
    repo.save(org)
    org.name = "After"
    repo.save(org)
    assert repo.count() == 1
    assert repo.get(org.id).name == "After"


def test_soft_delete_hides_entity(repo: InMemoryCrudRepository) -> None:
    org = Organization(name="Secret")
    repo.save(org)
    repo.soft_delete(org.id)
    assert repo.count() == 0
    assert repo.get(org.id) is None
    assert repo.get(org.id, include_deleted=True) is not None
    assert repo.count(include_deleted=True) == 1


def test_hard_delete_removes_entity(repo: InMemoryCrudRepository) -> None:
    org = Organization(name="Temp")
    repo.save(org)
    repo.delete(org.id)
    assert repo.count() == 0
    assert repo.count(include_deleted=True) == 0
    with pytest.raises(NotFoundError):
        repo.delete(org.id)


def test_list_pagination_and_ordering(repo: InMemoryCrudRepository) -> None:
    orgs = [Organization(name=f"org-{i}") for i in range(5)]
    repo.save_many(orgs)
    names = [e.name for e in repo.list(limit=2, offset=1, order_by="name", descending=False)]
    assert names == ["org-1", "org-2"]


def test_list_by_field(repo: InMemoryCrudRepository) -> None:
    repo.save_many(
        [
            Organization(name="a", industry="security"),
            Organization(name="b", industry="finance"),
            Organization(name="c", industry="security"),
        ]
    )
    matches = repo.list_by("industry", "security")
    assert {e.name for e in matches} == {"a", "c"}


def test_stream_yields_all(repo: InMemoryCrudRepository) -> None:
    repo.save_many([Organization(name=f"org-{i}") for i in range(2500)])
    streamed = list(repo.stream(batch_size=500))
    assert len(streamed) == 2500


def test_factory_reuses_instances() -> None:
    factory = InMemoryTidbRepositoryFactory()
    assert factory.repository_for(Organization) is factory.repository_for(Organization)
    assert factory.repository_for(Organization) is not factory.repository_for(Port)
    assert Program in factory.available_entities


def test_enum_values_roundtrip() -> None:
    repo = InMemoryCrudRepository(Program)
    prog = Program(organization_id="x", name="scope", status=ProgramStatus.COMPLETED)
    repo.save(prog)
    assert repo.get(prog.id).status is ProgramStatus.COMPLETED


def test_port_state_roundtrip() -> None:
    repo = InMemoryCrudRepository(Port)
    port = Port(ip_address_id="ip", number=22, state=PortState.OPEN)
    repo.save(port)
    assert repo.get(port.id).state is PortState.OPEN
