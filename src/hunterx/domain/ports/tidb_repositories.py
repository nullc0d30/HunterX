# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Repository port for TIDB entities.

A generic, entity-typed CRUD contract covering the system-of-record needs of
the TIDB: paginated reads, field filters, bulk writes, streaming for large
result sets and both hard and soft deletion. SQL and in-memory adapters
implement this port.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Iterator, Sequence
from typing import Any, ClassVar, Generic, TypeVar

E = TypeVar("E")


class TidbRepository(abc.ABC, Generic[E]):
    """Persistence contract for a single TIDB entity type."""

    entity_type: ClassVar[type]

    @abc.abstractmethod
    def get(self, identifier: str, *, include_deleted: bool = False) -> E | None:
        """Return the entity by identifier, or ``None`` if absent.

        Soft-deleted rows are hidden unless ``include_deleted`` is set.
        """

    @abc.abstractmethod
    def get_or_raise(self, identifier: str, *, include_deleted: bool = False) -> E:
        """Return the entity by identifier, raising :class:`NotFoundError`."""

    @abc.abstractmethod
    def save(self, entity: E) -> None:
        """Insert or update the entity (upsert on ``id``)."""

    @abc.abstractmethod
    def save_many(self, entities: Iterable[E]) -> int:
        """Bulk-persist a batch of entities; returns the number written."""

    @abc.abstractmethod
    def delete(self, identifier: str) -> None:
        """Hard-delete the entity, raising :class:`NotFoundError` when absent."""

    @abc.abstractmethod
    def soft_delete(self, identifier: str) -> None:
        """Mark the entity deleted without removing the row."""

    @abc.abstractmethod
    def count(self, *, include_deleted: bool = False) -> int:
        """Return the number of persisted entities."""

    @abc.abstractmethod
    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at",
        descending: bool = True,
    ) -> Sequence[E]:
        """Return a page of entities ordered by a column."""

    @abc.abstractmethod
    def list_by(
        self,
        field: str,
        value: Any,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[E]:
        """Return entities whose ``field`` equals ``value``."""

    @abc.abstractmethod
    def stream(self, *, batch_size: int = 1000, include_deleted: bool = False) -> Iterator[E]:
        """Yield all entities in batches without loading the table into memory."""


class TidbRepositoryFactory(abc.ABC):
    """Builds typed repositories for any TIDB entity class."""

    @abc.abstractmethod
    def repository_for(self, entity_cls: type) -> TidbRepository:
        """Return a repository for the given TIDB entity class."""
