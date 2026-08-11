# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Generic mapper between TIDB domain entities and ORM model rows.

TIDB entities are dataclasses whose fields mirror the ORM columns 1:1. The
mapper copies entity fields onto a model instance (and back), converting enums
to their stored string values and JSON-serializable values to/from the JSON
columns. This keeps the storage adapter free of per-entity boilerplate.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from enum import Enum
from typing import Any, get_type_hints

from hunterx.infrastructure.db.sql.registry import entity_class, model_class


def _coerce_to_column(value: Any) -> Any:
    """Coerce a domain value to a JSON-safe column value."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (list, dict)):
        return value
    return value


def _coerce_from_column(entity_cls: type, field_name: str, value: Any) -> Any:
    """Coerce a stored column value back into a domain value (enum-aware)."""
    if value is None:
        return None
    hints = getattr(entity_cls, "__tidb_hints__", None)
    if hints is None:
        hints = get_type_hints(entity_cls)
        entity_cls.__tidb_hints__ = hints
    target = hints.get(field_name)
    if target is not None and isinstance(target, type) and issubclass(target, Enum):
        return target(value)
    return value


class RowMapper:
    """Maps a single TIDB entity type to/from its ORM model."""

    def __init__(self, entity_cls: type) -> None:
        self.entity_cls = entity_cls
        self.model_cls = model_class(entity_cls)
        self._fields = tuple(f.name for f in dataclasses.fields(entity_cls))

    def apply(self, entity: Any, row: Any) -> None:
        """Copy entity fields onto an existing ORM model row."""
        for name in self._fields:
            setattr(row, name, _coerce_to_column(getattr(entity, name)))

    def new_row(self, entity: Any) -> Any:
        """Create a fresh ORM model row populated from the entity."""
        row = self.model_cls()
        self.apply(entity, row)
        return row

    def to_entity(self, row: Any) -> Any:
        """Build a domain entity from an ORM model row."""
        values: dict[str, Any] = {}
        for name in self._fields:
            values[name] = _coerce_from_column(self.entity_cls, name, getattr(row, name))
        return self.entity_cls(**values)


def to_row(entity: Any) -> Any:
    """Map an entity instance to a fresh ORM model row."""
    return RowMapper(entity_class(entity)).new_row(entity)


def apply_entity(entity: Any, row: Any) -> None:
    """Copy an entity's fields onto an existing ORM model row."""
    RowMapper(entity_class(entity)).apply(entity, row)


def to_entity(entity_cls: type, row: Any) -> Any:
    """Map an ORM model row back to a domain entity instance."""
    return RowMapper(entity_cls).to_entity(row)


def entity_to_mapping(entity: Any) -> Mapping[str, Any]:
    """Serialize an entity to a JSON-safe field mapping."""
    values: dict[str, Any] = {}
    for f in dataclasses.fields(entity):
        values[f.name] = _coerce_to_column(getattr(entity, f.name))
    return values
