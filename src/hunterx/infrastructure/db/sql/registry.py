# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Registry mapping TIDB domain entities to their ORM models.

The TIDB models mirror the domain entities one-to-one, so the registry is
derived from class names (``OrganizationModel`` ↔ ``Organization``). Every
entity class in ``hunterx.domain.entities.tidb`` that is a dataclass has an
ORM model; enums and ``TidbEntity`` itself are excluded.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Final

import hunterx.domain.entities.tidb as _entities_pkg
import hunterx.infrastructure.db.sql.tidb_models as _models_pkg

_ENTITY_TO_MODEL: dict[type, type] = {}
_MODEL_TO_ENTITY: dict[type, type] = {}

for _name in _models_pkg.__all__:
    if not _name.endswith("Model") or _name == "TidbModelMixin":
        continue
    _model_cls = getattr(_models_pkg, _name)
    _entity_name = _name[: -len("Model")]
    if not hasattr(_entities_pkg, _entity_name):
        continue
    _entity_cls = getattr(_entities_pkg, _entity_name)
    if not dataclasses.is_dataclass(_entity_cls):
        continue
    _ENTITY_TO_MODEL[_entity_cls] = _model_cls
    _MODEL_TO_ENTITY[_model_cls] = _entity_cls

ENTITY_TO_MODEL: Final[dict[type, type]] = _ENTITY_TO_MODEL
MODEL_TO_ENTITY: Final[dict[type, type]] = _MODEL_TO_ENTITY

__all__ = ["ENTITY_TO_MODEL", "MODEL_TO_ENTITY", "entity_class", "model_class", "all_entities"]


def entity_class(entity_or_class: Any) -> type:
    """Return the entity class for an entity instance or entity class."""
    if isinstance(entity_or_class, type):
        return entity_or_class
    return type(entity_or_class)


def model_class(entity_or_class: Any) -> type:
    """Return the ORM model class for a TIDB entity instance or class."""
    cls = entity_class(entity_or_class)
    try:
        return ENTITY_TO_MODEL[cls]
    except KeyError as exc:  # pragma: no cover - defensive
        raise LookupError(f"No ORM model registered for {cls.__name__}") from exc


def all_entities() -> list[type]:
    """Return all registered TIDB entity classes, sorted by name."""
    return sorted(ENTITY_TO_MODEL, key=lambda cls: cls.__name__)
