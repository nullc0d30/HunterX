# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API historical comparison.

Compares current API intelligence state against historical records to detect
changes over time: hosts added/removed, spec documents appearing or vanishing,
endpoint operations added/removed/changed and parameter/auth changes. Every
change is reported with the before/after values, the producing tool and the
detection timestamp so it can be traced and correlated.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from hunterx.domain.api.models import (
    ApiChange,
    APIHostObservation,
    ApiOperationObservation,
    APISpecObservation,
)

_ADDED = "added"
_REMOVED = "removed"
_CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class ApiHistoryComparison:
    """The diff between historical and current API state.

    Attributes:
        changes: the detected changes (added/removed/changed).
        unchanged: number of subjects present in both snapshots.
        historical: the historical snapshot size.
        current: the current snapshot size.

    """

    changes: tuple[ApiChange, ...] = ()
    unchanged: int = 0
    historical: int = 0
    current: int = 0

    def __len__(self) -> int:
        """Return the number of detected changes."""
        return len(self.changes)


class ApiHistory:
    """Compare historical and current API snapshots.

    Usage::

        history = ApiHistory()
        diff = history.compare(historical_operations, current_operations)
    """

    def compare_operations(
        self,
        historical: Sequence[ApiOperationObservation],
        current: Sequence[ApiOperationObservation],
        *,
        source: str = "api",
    ) -> ApiHistoryComparison:
        """Diff operation snapshots by canonical key."""
        historical_map = {item.key(): item for item in historical}
        current_map = {item.key(): item for item in current}
        changes: list[ApiChange] = []
        unchanged = 0

        for key, previous in historical_map.items():
            current_item = current_map.get(key)
            if current_item is None:
                changes.append(
                    ApiChange(
                        subject_type="operation",
                        subject=key,
                        change_type=_REMOVED,
                        previous=previous.path,
                        current="",
                        source=source,
                    )
                )
            elif previous.path != current_item.path or previous.confidence != current_item.confidence:
                changes.append(
                    ApiChange(
                        subject_type="operation",
                        subject=key,
                        change_type=_CHANGED,
                        previous=previous.path,
                        current=current_item.path,
                        source=source,
                        details={
                            "previous_confidence": previous.confidence,
                            "current_confidence": current_item.confidence,
                        },
                    )
                )
            else:
                unchanged += 1

        for key, current_item in current_map.items():
            if key not in historical_map:
                changes.append(
                    ApiChange(
                        subject_type="operation",
                        subject=key,
                        change_type=_ADDED,
                        previous="",
                        current=current_item.path,
                        source=source,
                    )
                )

        return ApiHistoryComparison(
            changes=tuple(changes),
            unchanged=unchanged,
            historical=len(historical),
            current=len(current),
        )

    def compare_hosts(
        self,
        historical: Sequence[APIHostObservation],
        current: Sequence[APIHostObservation],
        *,
        source: str = "api",
    ) -> ApiHistoryComparison:
        """Diff host snapshots by origin key."""
        historical_map = {item.key(): item for item in historical}
        current_map = {item.key(): item for item in current}
        changes: list[ApiChange] = []
        unchanged = 0

        for key, previous in historical_map.items():
            current_item = current_map.get(key)
            if current_item is None:
                changes.append(
                    ApiChange(
                        subject_type="host",
                        subject=key,
                        change_type=_REMOVED,
                        previous=previous.origin_key,
                        current="",
                        source=source,
                    )
                )
            elif previous.documented != current_item.documented:
                changes.append(
                    ApiChange(
                        subject_type="host",
                        subject=key,
                        change_type=_CHANGED,
                        previous=str(previous.documented),
                        current=str(current_item.documented),
                        source=source,
                    )
                )
            else:
                unchanged += 1

        for key, current_item in current_map.items():
            if key not in historical_map:
                changes.append(
                    ApiChange(
                        subject_type="host",
                        subject=key,
                        change_type=_ADDED,
                        previous="",
                        current=current_item.origin_key,
                        source=source,
                    )
                )

        return ApiHistoryComparison(
            changes=tuple(changes),
            unchanged=unchanged,
            historical=len(historical),
            current=len(current),
        )

    def compare(
        self,
        historical: Sequence[object],
        current: Sequence[object],
        *,
        source: str = "api",
    ) -> ApiHistoryComparison:
        """Diff typed API snapshots by record class."""
        historical_ops = [item for item in historical if isinstance(item, ApiOperationObservation)]
        current_ops = [item for item in current if isinstance(item, ApiOperationObservation)]
        result = self.compare_operations(historical_ops, current_ops, source=source)

        historical_hosts = [item for item in historical if isinstance(item, APIHostObservation)]
        current_hosts = [item for item in current if isinstance(item, APIHostObservation)]
        host_result = self.compare_hosts(historical_hosts, current_hosts, source=source)

        historical_specs = [item for item in historical if isinstance(item, APISpecObservation)]
        current_specs = [item for item in current if isinstance(item, APISpecObservation)]
        spec_result = self.compare_specs(historical_specs, current_specs, source=source)

        return ApiHistoryComparison(
            changes=tuple(result.changes) + tuple(host_result.changes) + tuple(spec_result.changes),
            unchanged=result.unchanged + host_result.unchanged + spec_result.unchanged,
            historical=len(historical),
            current=len(current),
        )

    def compare_specs(
        self,
        historical: Sequence[APISpecObservation],
        current: Sequence[APISpecObservation],
        *,
        source: str = "api",
    ) -> ApiHistoryComparison:
        """Diff spec document snapshots by source URL."""
        historical_map = {item.key(): item for item in historical}
        current_map = {item.key(): item for item in current}
        changes: list[ApiChange] = []
        unchanged = 0

        for key, previous in historical_map.items():
            current_item = current_map.get(key)
            if current_item is None:
                changes.append(
                    ApiChange(
                        subject_type="spec",
                        subject=key,
                        change_type=_REMOVED,
                        previous=previous.source_url,
                        current="",
                        source=source,
                    )
                )
            elif (
                previous.integrity != current_item.integrity or previous.operation_count != current_item.operation_count
            ):
                changes.append(
                    ApiChange(
                        subject_type="spec",
                        subject=key,
                        change_type=_CHANGED,
                        previous=previous.source_url,
                        current=current_item.source_url,
                        source=source,
                        details={
                            "previous_operations": previous.operation_count,
                            "current_operations": current_item.operation_count,
                            "previous_integrity": previous.integrity,
                            "current_integrity": current_item.integrity,
                        },
                    )
                )
            else:
                unchanged += 1

        for key, current_item in current_map.items():
            if key not in historical_map:
                changes.append(
                    ApiChange(
                        subject_type="spec",
                        subject=key,
                        change_type=_ADDED,
                        previous="",
                        current=current_item.source_url,
                        source=source,
                    )
                )

        return ApiHistoryComparison(
            changes=tuple(changes),
            unchanged=unchanged,
            historical=len(historical),
            current=len(current),
        )
