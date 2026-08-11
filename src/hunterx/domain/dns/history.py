# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS historical comparison.

Compares current observations against historical records to detect changes
over time: records added, removed, or whose value changed. Every change is
reported with the before/after values, timestamps and sources so it can be
traced and correlated with security events.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from hunterx.domain.dns.models import DnsRecord, DnsRecordType

_CHANGE_ADDED = "added"
_CHANGE_REMOVED = "removed"
_CHANGE_CHANGED = "changed"
_CHANGE_UNCHANGED = "unchanged"


@dataclass(frozen=True, slots=True)
class DnsChange:
    """A detected change between historical and current DNS observations.

    Attributes:
        name: the owner name.
        record_type: the record type.
        change: one of ``added``, ``removed``, ``changed``.
        previous: previous value (empty for added records).
        current: current value (empty for removed records).
        observed_previous: when the previous value was last observed.
        observed_current: when the current value was observed.
        source: which source observed the current value.
        details: extra context.

    """

    name: str
    record_type: DnsRecordType
    change: str
    previous: str = ""
    current: str = ""
    observed_previous: str = ""
    observed_current: str = ""
    source: str = ""
    details: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class HistoryComparison:
    """The diff between historical and current DNS records.

    Attributes:
        changes: the detected changes (added/removed/changed).
        unchanged: number of records present in both snapshots.
        historical: the historical snapshot size.
        current: the current snapshot size.

    """

    changes: list[DnsChange] = field(default_factory=list)
    unchanged: int = 0
    historical: int = 0
    current: int = 0


class DnsHistory:
    """Compare historical and current DNS snapshots.

    Usage::

        history = DnsHistory()
        diff = history.compare(historical_records, current_records)
    """

    def compare(self, historical: Sequence[DnsRecord], current: Sequence[DnsRecord]) -> HistoryComparison:
        """Return the changes between ``historical`` and ``current``."""
        historical_by_key = {_key(record): record for record in historical}
        current_by_key = {_key(record): record for record in current}
        changes: list[DnsChange] = []
        unchanged = 0

        for key, current_record in current_by_key.items():
            previous = historical_by_key.get(key)
            if previous is None:
                changes.append(
                    DnsChange(
                        name=current_record.name,
                        record_type=current_record.record_type,
                        change=_CHANGE_ADDED,
                        current=current_record.value,
                        observed_current=current_record.observed_at,
                        source=current_record.source,
                    )
                )
            elif previous.value != current_record.value:
                changes.append(
                    DnsChange(
                        name=current_record.name,
                        record_type=current_record.record_type,
                        change=_CHANGE_CHANGED,
                        previous=previous.value,
                        current=current_record.value,
                        observed_previous=previous.observed_at,
                        observed_current=current_record.observed_at,
                        source=current_record.source,
                    )
                )
            else:
                unchanged += 1

        for key, previous in historical_by_key.items():
            if key not in current_by_key:
                changes.append(
                    DnsChange(
                        name=previous.name,
                        record_type=previous.record_type,
                        change=_CHANGE_REMOVED,
                        previous=previous.value,
                        observed_previous=previous.observed_at,
                        source=previous.source,
                    )
                )

        return HistoryComparison(
            changes=changes,
            unchanged=unchanged,
            historical=len(historical),
            current=len(current),
        )

    def summarize(self, comparison: HistoryComparison) -> dict[str, int]:
        """Return a compact summary of a comparison."""
        counts = {_CHANGE_ADDED: 0, _CHANGE_REMOVED: 0, _CHANGE_CHANGED: 0}
        for change in comparison.changes:
            counts[change.change] = counts.get(change.change, 0) + 1
        return counts

    def by_name(self, comparison: HistoryComparison, name: str) -> list[DnsChange]:
        """Return the changes affecting a single owner name."""
        return [change for change in comparison.changes if change.name.lower() == name.lower()]


def _key(record: DnsRecord) -> tuple[str, str]:
    """Return the comparison key (name + record type)."""
    return (record.name.lower(), record.record_type.value)
