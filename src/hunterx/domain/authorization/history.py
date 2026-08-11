# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization intelligence historical comparison.

Compares the current authorization state against historical records to detect
changes over time: added/removed roles, changed permissions and scopes, new or
removed admin surfaces, changed ownership/tenant models, changed policy models,
new frontend/backend enforcement and changed API authorization requirements.
Every change is reported with the before/after values, timestamps and sources
so it can be traced and correlated with security events.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.authorization.models import AuthorizationChange

_CHANGE_ADDED = "added"
_CHANGE_REMOVED = "removed"
_CHANGE_CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class AuthorizationHistoryComparison:
    """The diff between historical and current authorization state.

    Attributes:
        changes: the detected changes (added/removed/changed).
        unchanged: number of subjects present in both snapshots.
        historical: the historical snapshot size.
        current: the current snapshot size.

    """

    changes: tuple[AuthorizationChange, ...] = ()
    unchanged: int = 0
    historical: int = 0
    current: int = 0


class AuthorizationHistory:
    """Compare historical and current authorization snapshots.

    Usage::

        history = AuthorizationHistory()
        diff = history.compare(historical_records, current_records)
    """

    def compare(
        self,
        historical: Sequence[Any],
        current: Sequence[Any],
    ) -> AuthorizationHistoryComparison:
        """Return the changes between ``historical`` and ``current``."""
        historical_by_key = {_key_of(record): record for record in historical}
        current_by_key = {_key_of(record): record for record in current}
        changes: list[AuthorizationChange] = []
        unchanged = 0

        for key, current_record in current_by_key.items():
            previous = historical_by_key.get(key)
            if previous is None:
                changes.append(_added(current_record))
            elif _value_of(previous) != _value_of(current_record):
                changes.append(_changed(previous, current_record))
            else:
                unchanged += 1

        for key, previous in historical_by_key.items():
            if key not in current_by_key:
                changes.append(_removed(previous))

        changes.sort(key=lambda change: (change.subject_type, change.subject))
        return AuthorizationHistoryComparison(
            changes=tuple(changes),
            unchanged=unchanged,
            historical=len(historical),
            current=len(current),
        )

    def summarize(self, comparison: AuthorizationHistoryComparison) -> dict[str, int]:
        """Return a compact summary of a comparison."""
        counts: dict[str, int] = {_CHANGE_ADDED: 0, _CHANGE_REMOVED: 0, _CHANGE_CHANGED: 0}
        for change in comparison.changes:
            counts[change.change_type] = counts.get(change.change_type, 0) + 1
        return counts

    def by_kind(self, comparison: AuthorizationHistoryComparison, change_type: str) -> list[AuthorizationChange]:
        """Return the changes of a single change type."""
        return [change for change in comparison.changes if change.change_type == change_type]

    def by_subject(self, comparison: AuthorizationHistoryComparison, subject_type: str) -> list[AuthorizationChange]:
        """Return the changes concerning a single subject class."""
        return [change for change in comparison.changes if change.subject_type == subject_type]


# -- change factories ---------------------------------------------------------


def _added(record: Any) -> AuthorizationChange:
    return AuthorizationChange(
        subject_type=_subject_type(record),
        subject=_key_of(record),
        change_type=_CHANGE_ADDED,
        current=_value_of(record),
        source=str(getattr(record, "source", "")),
        details=_details_of(record),
    )


def _removed(record: Any) -> AuthorizationChange:
    return AuthorizationChange(
        subject_type=_subject_type(record),
        subject=_key_of(record),
        change_type=_CHANGE_REMOVED,
        previous=_value_of(record),
        source=str(getattr(record, "source", "")),
        details=_details_of(record),
    )


def _changed(previous: Any, current: Any) -> AuthorizationChange:
    return AuthorizationChange(
        subject_type=_subject_type(current),
        subject=_key_of(current),
        change_type=_CHANGE_CHANGED,
        previous=_value_of(previous),
        current=_value_of(current),
        source=str(getattr(current, "source", "")),
        details=_details_of(current),
    )


# -- accessors ----------------------------------------------------------------


def _key_of(record: Any) -> str:
    key = getattr(record, "key", None)
    return key() if callable(key) else str(record)


def _value_of(record: Any) -> str:
    """Return the scalar value that defines a record's change state."""
    parts: list[str] = []
    for name in (
        "subject_kind",
        "model_kind",
        "decision",
        "kind",
        "name",
        "value",
        "action",
        "resource",
        "field",
        "identifier",
        "surface_kind",
        "check_type",
        "mechanism",
        "role",
        "scope",
        "permission",
        "tenant",
        "relationship_type",
        "custom",
        "default",
        "model",
    ):
        value = getattr(record, name, None)
        if value is None:
            continue
        if hasattr(value, "value"):
            parts.append(str(value.value))
        elif isinstance(value, (tuple, list)):
            parts.append(",".join(sorted(str(item) for item in value)))
        else:
            parts.append(str(value))
    return "|".join(parts)


def _details_of(record: Any) -> dict[str, Any]:
    return {
        "origin": str(getattr(record, "origin", "")),
        "url": str(getattr(record, "url", "")),
        "endpoint": str(getattr(record, "endpoint", "")),
        "confidence": float(getattr(record, "confidence", 0.0) or 0.0),
    }


def _subject_type(record: Any) -> str:
    mapping = {
        "AuthzSubjectObservation": "subject",
        "AuthzRoleObservation": "role",
        "AuthzGroupObservation": "group",
        "AuthzPermissionObservation": "permission",
        "AuthzScopeObservation": "scope",
        "AuthzClaimObservation": "claim",
        "AuthzPolicyObservation": "policy",
        "AuthzResourceObservation": "resource",
        "AuthzActionObservation": "action",
        "AuthzResourceIdentifierObservation": "identifier",
        "AuthzOwnershipObservation": "ownership",
        "AuthzTenantObservation": "tenant",
        "AuthzAdminSurfaceObservation": "admin-surface",
        "AuthzFunctionLevelObservation": "function-level",
        "AuthzObjectLevelObservation": "object-level",
        "AuthzFieldLevelObservation": "field-level",
        "AuthzFrontendObservation": "frontend",
        "AuthzBackendObservation": "backend",
        "AuthzApiCorrelationObservation": "api-correlation",
        "AuthzGraphQLObservation": "graphql",
        "AuthzWebSocketObservation": "websocket",
        "AuthzServiceObservation": "service",
        "AuthzDecisionObservation": "decision",
        "AuthzMassAssignmentObservation": "mass-assignment",
        "AuthzAccessControlObservation": "access-control",
        "AuthzObservation": "observation",
    }
    return mapping.get(type(record).__name__, "observation")
