# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence historical diffing.

Deterministic comparison of a previous cloud observation snapshot against the
current correlated set. Produces added/removed/changed :class:`CloudChange`
records keyed by each subject's canonical deduplication key.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.cloud.models import CloudChange

_CHANGE_ADDED = "added"
_CHANGE_REMOVED = "removed"
_CHANGE_CHANGED = "changed"

#: Change-state scalar fields per observation family. Values are joined with a
#: stable separator so an equivalent record always yields an identical scalar.
_CHANGE_FIELDS: tuple[str, ...] = (
    "provider",
    "service",
    "category",
    "resource_kind",
    "storage_kind",
    "compute_kind",
    "container_kind",
    "database_kind",
    "kind",
    "name",
    "value",
    "identifier",
    "endpoint",
    "region",
    "environment",
    "plane",
    "exposure",
    "public",
    "display_name",
    "saas_provider",
    "integration_type",
    "identity_kind",
)


@dataclass(frozen=True, slots=True)
class CloudHistoryComparison:
    """The result of comparing historical and current cloud state.

    Attributes:
        changes: detected changes.
        unchanged: subjects present in both snapshots with equal state.
        historical: subject count in the historical snapshot.
        current: subject count in the current snapshot.

    """

    changes: tuple[CloudChange, ...] = ()
    unchanged: int = 0
    historical: int = 0
    current: int = 0


class CloudHistory:
    """Compare historical and current cloud observation snapshots."""

    def compare(
        self,
        historical: Sequence[Any],
        current: Sequence[Any],
    ) -> CloudHistoryComparison:
        """Diff two snapshots and return the deterministic change set."""
        history_map = {_key_of(record): record for record in historical}
        current_map = {_key_of(record): record for record in current}
        changes: list[CloudChange] = []
        unchanged = 0
        for key, record in current_map.items():
            previous = history_map.get(key)
            if previous is None:
                changes.append(_added(record))
                continue
            if _value_of(previous) != _value_of(record):
                changes.append(_changed(previous, record))
            else:
                unchanged += 1
        for key, record in history_map.items():
            if key not in current_map:
                changes.append(_removed(record))
        changes.sort(key=lambda change: (change.subject_type, change.subject))
        return CloudHistoryComparison(
            changes=tuple(changes),
            unchanged=unchanged,
            historical=len(history_map),
            current=len(current_map),
        )

    def summarize(self, comparison: CloudHistoryComparison) -> dict[str, int]:
        """Return change counts per change type."""
        summary = {_CHANGE_ADDED: 0, _CHANGE_REMOVED: 0, _CHANGE_CHANGED: 0}
        for change in comparison.changes:
            summary[change.change_type] = summary.get(change.change_type, 0) + 1
        return summary

    def by_kind(self, comparison: CloudHistoryComparison, change_type: str) -> list[CloudChange]:
        """Return changes of a given type."""
        return [change for change in comparison.changes if change.change_type == change_type]

    def by_subject(self, comparison: CloudHistoryComparison, subject_type: str) -> list[CloudChange]:
        """Return changes affecting a given subject type."""
        return [change for change in comparison.changes if change.subject_type == subject_type]


def _key_of(record: Any) -> str:
    key = getattr(record, "key", None)
    return key() if callable(key) else str(record)


def _added(record: Any) -> CloudChange:
    return CloudChange(
        subject_type=_subject_type(record),
        subject=_key_of(record),
        change_type=_CHANGE_ADDED,
        current=_value_of(record),
        source=str(getattr(record, "source", "") or ""),
        details=_details_of(record),
    )


def _removed(record: Any) -> CloudChange:
    return CloudChange(
        subject_type=_subject_type(record),
        subject=_key_of(record),
        change_type=_CHANGE_REMOVED,
        previous=_value_of(record),
        source=str(getattr(record, "source", "") or ""),
        details=_details_of(record),
    )


def _changed(previous: Any, current: Any) -> CloudChange:
    return CloudChange(
        subject_type=_subject_type(current),
        subject=_key_of(current),
        change_type=_CHANGE_CHANGED,
        previous=_value_of(previous),
        current=_value_of(current),
        source=str(getattr(current, "source", "") or ""),
        details=_details_of(current),
    )


def _value_of(record: Any) -> str:
    """Return the deterministic change-state scalar of a record."""
    parts: list[str] = []
    for name in _CHANGE_FIELDS:
        value = getattr(record, name, None)
        if value is None:
            continue
        if hasattr(value, "value"):
            value = value.value
        if isinstance(value, (tuple, list)):
            parts.append(",".join(sorted(str(item) for item in value)))
        else:
            parts.append(str(value))
    return "|".join(parts)


def _details_of(record: Any) -> Mapping[str, Any]:
    """Return provenance detail for a change record."""
    details: dict[str, Any] = {}
    for name in ("origin", "url", "confidence"):
        value = getattr(record, name, None)
        if value is not None:
            details[name] = value
    return details


def _subject_type(record: Any) -> str:
    mapping = {
        "CloudProviderObservation": "provider",
        "CloudServiceObservation": "service",
        "CloudResourceObservation": "resource",
        "CloudEndpointObservation": "endpoint",
        "CloudAccountObservation": "account",
        "CloudRegionObservation": "region",
        "CloudEnvironmentObservation": "environment",
        "CloudIdentityObservation": "identity",
        "CloudRoleObservation": "role",
        "CloudPermissionObservation": "permission",
        "CloudIntegrationObservation": "integration",
        "SaaSProviderObservation": "saas",
        "SaaSApplicationObservation": "saas-application",
        "SaaSIntegrationObservation": "saas-integration",
        "WebhookObservation": "webhook",
        "CloudDependencyObservation": "dependency",
        "StorageResourceObservation": "storage",
        "ComputeResourceObservation": "compute",
        "ContainerResourceObservation": "container",
        "KubernetesResourceObservation": "kubernetes",
        "DatabaseResourceObservation": "database",
        "MessageInfrastructureObservation": "message",
        "ApiGatewayResourceObservation": "gateway",
        "CdnResourceObservation": "cdn",
        "LoadBalancerResourceObservation": "load-balancer",
        "CiCdResourceObservation": "ci-cd",
        "SecretManagementObservation": "secret",
        "CloudExposureObservation": "exposure",
        "CloudObservation": "observation",
    }
    return mapping.get(type(record).__name__, "observation")
