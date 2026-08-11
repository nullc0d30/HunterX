# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SQL-backed generic TIDB CRUD repository.

Implements :class:`~hunterx.domain.ports.tidb_repositories.TidbRepository`
generically for any TIDB entity type using the row mapper. Bulk writes use a
single flush, reads are paginated without N+1 (whole rows are mapped in one
pass), and :meth:`stream` yields results in batches for large tables.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Any

from sqlalchemy import func, select

from hunterx.domain.exceptions import DomainValidationError, NotFoundError
from hunterx.domain.ports.tidb_repositories import TidbRepository, TidbRepositoryFactory
from hunterx.domain.services.validation import EnvelopeTidbValidator
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.infrastructure.db.sql.mapping import RowMapper
from hunterx.infrastructure.db.sql.registry import all_entities, entity_class
from hunterx.shared.time import utcnow_iso

_SAFE_ORDER = frozenset({"id", "created_at", "updated_at", "first_seen", "last_seen", "version", "revision"})


class SqlCrudRepository(TidbRepository[Any]):
    """Generic SQLAlchemy CRUD repository for one TIDB entity type."""

    def __init__(self, session_factory: SessionFactory, entity_cls: type) -> None:
        self._session_factory = session_factory
        self.entity_cls = entity_cls
        self.entity_type = entity_cls
        self._mapper = RowMapper(entity_cls)
        self._validator = EnvelopeTidbValidator()

    def _validate(self, entity: Any) -> None:
        result = self._validator.validate(entity)
        if not result.valid:
            raise DomainValidationError(
                "; ".join(f"{i.field}: {i.message}" for i in result.issues),
                errors=[f"{i.field}: {i.message}" for i in result.issues],
            )

    def _session(self) -> Any:
        return self._session_factory.session()

    def _validated_order_by(self, order_by: str) -> str:
        if order_by not in self._mapper.model_cls.__table__.columns:
            raise ValueError(f"Unknown column {order_by!r} for {self.entity_cls.__name__}")
        return order_by

    def get(self, identifier: str, *, include_deleted: bool = False) -> Any | None:
        """Return the entity by identifier, or ``None`` if absent."""
        with self._session() as session:
            row = session.get(self._mapper.model_cls, identifier)
            if row is None:
                return None
            if not include_deleted and row.deleted_at is not None:
                return None
            return self._mapper.to_entity(row)

    def get_or_raise(self, identifier: str, *, include_deleted: bool = False) -> Any:
        """Return the entity by identifier, raising :class:`NotFoundError`."""
        entity = self.get(identifier, include_deleted=include_deleted)
        if entity is None:
            raise NotFoundError(self.entity_cls.__name__, identifier)
        return entity

    def save(self, entity: Any) -> None:
        """Insert or update the entity (upsert on ``id``)."""
        self._validate(entity)
        with self._session() as session:
            row = session.get(self._mapper.model_cls, entity.id)
            if row is None:
                row = self._mapper.new_row(entity)
                session.add(row)
            else:
                self._mapper.apply(entity, row)
            session.commit()

    def save_many(self, entities: Iterable[Any]) -> int:
        """Bulk-persist a batch of entities; returns the number written."""
        batch = list(entities)
        for entity in batch:
            self._validate(entity)
        with self._session() as session:
            for entity in batch:
                row = session.get(self._mapper.model_cls, entity.id)
                if row is None:
                    session.add(self._mapper.new_row(entity))
                else:
                    self._mapper.apply(entity, row)
            session.commit()
        return len(batch)

    def delete(self, identifier: str) -> None:
        """Hard-delete the entity, raising :class:`NotFoundError` when absent."""
        with self._session() as session:
            row = session.get(self._mapper.model_cls, identifier)
            if row is None:
                raise NotFoundError(self.entity_cls.__name__, identifier)
            session.delete(row)
            session.commit()

    def soft_delete(self, identifier: str) -> None:
        """Mark the entity deleted without removing the row."""
        with self._session() as session:
            row = session.get(self._mapper.model_cls, identifier)
            if row is None:
                raise NotFoundError(self.entity_cls.__name__, identifier)
            now = utcnow_iso()
            row.deleted_at = now
            row.updated_at = now
            row.version = (row.version or 1) + 1
            row.revision = (row.revision or 1) + 1
            session.commit()

    def count(self, *, include_deleted: bool = False) -> int:
        """Return the number of persisted entities."""
        with self._session() as session:
            stmt = select(func.count()).select_from(self._mapper.model_cls)
            if not include_deleted:
                stmt = stmt.where(self._mapper.model_cls.deleted_at.is_(None))
            return int(session.scalar(stmt) or 0)

    def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at",
        descending: bool = True,
    ) -> Sequence[Any]:
        """Return a page of live entities ordered by a column.

        Soft-deleted rows are hidden, consistent with :meth:`count`,
        :meth:`get` and :meth:`stream`.
        """
        order_col = getattr(self._mapper.model_cls, self._validated_order_by(order_by))
        stmt = select(self._mapper.model_cls).order_by(order_col.desc() if descending else order_col)
        stmt = stmt.where(self._mapper.model_cls.deleted_at.is_(None))
        stmt = stmt.offset(offset).limit(limit)
        with self._session() as session:
            rows = list(session.execute(stmt).scalars())
        return [self._mapper.to_entity(row) for row in rows]

    def list_by(self, field: str, value: Any, *, limit: int = 100, offset: int = 0) -> Sequence[Any]:
        """Return live entities whose ``field`` equals ``value``.

        Soft-deleted rows are hidden, consistent with :meth:`count`,
        :meth:`get` and :meth:`stream`.
        """
        column = getattr(self._mapper.model_cls, field, None)
        if column is None:
            raise ValueError(f"Unknown column {field!r} for {self.entity_cls.__name__}")
        stmt = select(self._mapper.model_cls).where(column == value)
        stmt = stmt.where(self._mapper.model_cls.deleted_at.is_(None))
        stmt = stmt.order_by(self._mapper.model_cls.created_at.desc()).offset(offset).limit(limit)
        with self._session() as session:
            rows = list(session.execute(stmt).scalars())
        return [self._mapper.to_entity(row) for row in rows]

    def stream(self, *, batch_size: int = 1000, include_deleted: bool = False) -> Iterator[Any]:
        """Yield all entities in batches without loading the table into memory."""
        model_cls = self._mapper.model_cls
        stmt = select(model_cls).order_by(model_cls.id)
        if not include_deleted:
            stmt = stmt.where(model_cls.deleted_at.is_(None))
        with self._session() as session:
            result = session.execute(stmt.execution_options(yield_per=batch_size))
            for row in result.scalars():
                yield self._mapper.to_entity(row)


class SqlTidbRepositoryFactory(TidbRepositoryFactory):
    """Builds :class:`SqlCrudRepository` instances for any TIDB entity class."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory
        self._cache: dict[type, SqlCrudRepository] = {}

    def repository_for(self, entity_cls: type) -> SqlCrudRepository:
        """Return a (cached) SQL CRUD repository for the given entity class."""
        cls = entity_class(entity_cls)
        if cls not in self._cache:
            self._cache[cls] = SqlCrudRepository(self._session_factory, cls)
        return self._cache[cls]

    @property
    def available_entities(self) -> tuple[type, ...]:
        """Return all TIDB entity classes this factory can persist."""
        return tuple(all_entities())
