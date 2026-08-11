# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory TIDB CRUD repository.

A dict-backed implementation of the TIDB repository port used for tests,
prototyping and single-process ephemeral stores. It reproduces the soft-delete
and pagination semantics of the SQL adapter without a database.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Any

from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.ports.tidb_repositories import TidbRepository, TidbRepositoryFactory
from hunterx.infrastructure.db.sql.registry import all_entities, entity_class
from hunterx.shared.time import utcnow_iso


class InMemoryCrudRepository(TidbRepository[Any]):
    """Generic in-memory CRUD repository for one TIDB entity type."""

    def __init__(self, entity_cls: type) -> None:
        self.entity_cls = entity_cls
        self.entity_type = entity_cls
        self._store: dict[str, Any] = {}

    def _visible(self, entity: Any) -> bool:
        return getattr(entity, "deleted_at", None) is None

    def get(self, identifier: str, *, include_deleted: bool = False) -> Any | None:
        """Return the entity by identifier, or ``None`` if absent."""
        entity = self._store.get(identifier)
        if entity is None:
            return None
        if not include_deleted and not self._visible(entity):
            return None
        return entity

    def get_or_raise(self, identifier: str, *, include_deleted: bool = False) -> Any:
        """Return the entity by identifier, raising :class:`NotFoundError`."""
        entity = self.get(identifier, include_deleted=include_deleted)
        if entity is None:
            raise NotFoundError(self.entity_cls.__name__, identifier)
        return entity

    def save(self, entity: Any) -> None:
        """Insert or update the entity (upsert on ``id``)."""
        self._store[entity.id] = entity

    def save_many(self, entities: Iterable[Any]) -> int:
        """Bulk-persist a batch of entities; returns the number written."""
        batch = list(entities)
        for entity in batch:
            self._store[entity.id] = entity
        return len(batch)

    def delete(self, identifier: str) -> None:
        """Hard-delete the entity, raising :class:`NotFoundError` when absent."""
        if identifier not in self._store:
            raise NotFoundError(self.entity_cls.__name__, identifier)
        del self._store[identifier]

    def soft_delete(self, identifier: str) -> None:
        """Mark the entity deleted without removing the row."""
        entity = self.get_or_raise(identifier, include_deleted=True)
        entity.soft_delete(now=utcnow_iso())

    def count(self, *, include_deleted: bool = False) -> int:
        """Return the number of persisted entities."""
        if include_deleted:
            return len(self._store)
        return sum(1 for entity in self._store.values() if self._visible(entity))

    def _all_visible(self) -> list[Any]:
        return [entity for entity in self._store.values() if self._visible(entity)]

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at",
        descending: bool = True,
    ) -> Sequence[Any]:
        """Return a page of entities ordered by a column."""
        visible = self._all_visible()
        visible.sort(
            key=lambda e: (getattr(e, order_by, None) or "", e.id or ""), reverse=descending
        )
        return visible[offset : offset + limit]

    def list_by(self, field: str, value: Any, *, limit: int = 100, offset: int = 0) -> Sequence[Any]:
        """Return entities whose ``field`` equals ``value``."""
        matched = [e for e in self._all_visible() if getattr(e, field, None) == value]
        matched.sort(key=lambda e: (getattr(e, "created_at", None) or "", e.id or ""), reverse=True)
        return matched[offset : offset + limit]

    def stream(self, *, batch_size: int = 1000, include_deleted: bool = False) -> Iterator[Any]:
        """Yield all entities in batches without loading the table into memory."""
        entities = list(self._store.values()) if include_deleted else self._all_visible()
        for i in range(0, len(entities), batch_size):
            yield from entities[i : i + batch_size]


class InMemoryTidbRepositoryFactory(TidbRepositoryFactory):
    """Builds :class:`InMemoryCrudRepository` instances for any TIDB entity class."""

    def __init__(self) -> None:
        self._cache: dict[type, InMemoryCrudRepository] = {}

    def repository_for(self, entity_cls: type) -> InMemoryCrudRepository:
        """Return a (cached) in-memory repository for the given entity class."""
        cls = entity_class(entity_cls)
        if cls not in self._cache:
            self._cache[cls] = InMemoryCrudRepository(cls)
        return self._cache[cls]

    @property
    def available_entities(self) -> tuple[type, ...]:
        """Return all TIDB entity classes this factory can persist."""
        return tuple(all_entities())
