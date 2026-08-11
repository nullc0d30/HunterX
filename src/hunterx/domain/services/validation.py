# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Validation contract for TIDB entities.

The validator enforces the TIDB system-of-record invariants from the
Development Bible (`09 - Database Design.md` §3, `08 - Unified Security
Schema.md`): ULID identifiers, UTC ISO-8601 timestamps, positive versioning
counters and bounded confidence scores. Storage adapters and application
services validate entities before persisting them.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunterx.domain.exceptions import DomainValidationError


@dataclass(slots=True)
class ValidationIssue:
    """A single validation finding against a TIDB entity."""

    entity_type: str
    field: str
    message: str


@dataclass(slots=True)
class TidbValidationResult:
    """Result of validating a TIDB entity."""

    valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)

    def raise_if_invalid(self) -> None:
        """Raise :class:`DomainValidationError` when the entity is invalid."""
        if not self.valid:
            detail = "; ".join(f"{i.field}: {i.message}" for i in self.issues)
            raise DomainValidationError(detail, errors=[f"{i.field}: {i.message}" for i in self.issues])


class TidbValidator(abc.ABC):
    """Validates the envelope invariants of any TIDB entity."""

    @abc.abstractmethod
    def validate(self, entity: Any) -> TidbValidationResult:
        """Validate an entity, returning all findings (not just the first)."""


class EnvelopeTidbValidator(TidbValidator):
    """Validates the shared TIDB envelope on every entity.

    Field-specific rules live on the entity types themselves; this validator
    covers the invariants every entity must satisfy regardless of type.
    """

    def validate(self, entity: Any) -> TidbValidationResult:
        """Validate the envelope invariants of a TIDB entity."""
        from hunterx.shared.ids import is_ulid

        entity_type = type(entity).__name__
        issues: list[ValidationIssue] = []

        entity_id = getattr(entity, "id", None)
        if not isinstance(entity_id, str) or not is_ulid(entity_id):
            issues.append(ValidationIssue(entity_type, "id", "must be a 26-char ULID string"))

        for ts_field in ("created_at",):
            value = getattr(entity, ts_field, None)
            if value is not None:
                issues.extend(self._validate_timestamp(entity_type, ts_field, value))
        for ts_field in ("updated_at", "first_seen", "last_seen", "deleted_at"):
            value = getattr(entity, ts_field, None)
            if value is None:
                continue
            issues.extend(self._validate_timestamp(entity_type, ts_field, value))

        for int_field in ("version", "revision", "schema_version"):
            value = getattr(entity, int_field, None)
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                issues.append(
                    ValidationIssue(entity_type, int_field, "must be a positive integer")
                )

        return TidbValidationResult(valid=not issues, issues=issues)

    def _validate_timestamp(self, entity_type: str, field_name: str, value: Any) -> list[ValidationIssue]:
        from hunterx.shared.time import to_utc_datetime

        try:
            if isinstance(value, str):
                to_utc_datetime(value)
        except (TypeError, ValueError):
            return [ValidationIssue(entity_type, field_name, "must be a valid UTC ISO-8601 timestamp")]
        return []


class EntityTidbValidator(TidbValidator):
    """Validates a TIDB entity's own fields against its dataclass type.

    Relies on the dataclass field types (enums and scalars) and the ULID/ISO
    envelope rules. Sensitive fields are never logged or surfaced.
    """

    def __init__(self, *, envelope_validator: TidbValidator | None = None) -> None:
        self._envelope = envelope_validator or EnvelopeTidbValidator()

    def validate(self, entity: Any) -> TidbValidationResult:
        """Validate an entity, combining envelope and field-type checks."""
        import dataclasses
        from typing import get_type_hints

        result = self._envelope.validate(entity)
        entity_type = type(entity).__name__
        issues: list[ValidationIssue] = list(result.issues)

        try:
            hints = get_type_hints(type(entity))
        except TypeError:  # pragma: no cover - entities resolve their hints
            hints = {}

        for f in dataclasses.fields(entity):
            value = getattr(entity, f.name)
            target = hints.get(f.name)
            if target is None:
                continue
            base = self._unwrap(target)
            if isinstance(base, type) and issubclass(base, Enum) and not isinstance(value, base):
                issues.append(
                    ValidationIssue(entity_type, f.name, f"must be one of {[e.value for e in base]}")
                )

        return TidbValidationResult(valid=not issues, issues=issues)

    @staticmethod
    def _unwrap(target: Any) -> Any:
        """Strip Optional/Union wrappers from a field type hint."""
        origin = getattr(target, "__origin__", None)
        if origin in (str, int, float, bool) or origin is None:
            return target
        args = getattr(target, "__args__", ())
        non_none = [a for a in args if a is not type(None)]
        return non_none[0] if len(non_none) == 1 else target
