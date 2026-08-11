# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology historical comparison.

Compares current technology state against historical records to detect changes
over time: technologies added, technologies removed, versions changed, web
servers/frameworks/CMS swapped, CDN/WAF/hosting changes and technology
conflicts. Every change is reported with the before/after values, timestamps
and sources so it can be traced and correlated with security events.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from hunterx.domain.technology.models import TechChange, TechnologyObservation

_CHANGE_ADDED = "added"
_CHANGE_REMOVED = "removed"
_CHANGE_CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class TechnologyHistoryComparison:
    """The diff between historical and current technology state.

    Attributes:
        changes: the detected changes (added/removed/changed).
        unchanged: number of technologies present in both snapshots.
        historical: the historical snapshot size.
        current: the current snapshot size.

    """

    changes: tuple[TechChange, ...] = ()
    unchanged: int = 0
    historical: int = 0
    current: int = 0


class TechnologyHistory:
    """Compare historical and current technology snapshots.

    Usage::

        history = TechnologyHistory()
        diff = history.compare(historical_observations, current_observations)
    """

    def compare(
        self,
        historical: Sequence[TechnologyObservation],
        current: Sequence[TechnologyObservation],
    ) -> TechnologyHistoryComparison:
        """Return the changes between ``historical`` and ``current``."""
        historical_by_key = {_key(observation): observation for observation in historical}
        current_by_key = {_key(observation): observation for observation in current}
        changes: list[TechChange] = []
        unchanged = 0

        for key, current_observation in current_by_key.items():
            previous = historical_by_key.get(key)
            if previous is None:
                changes.append(_added(current_observation))
            elif _value_of(previous) != _value_of(current_observation):
                changes.append(_changed(previous, current_observation))
            else:
                unchanged += 1

        for key, previous in historical_by_key.items():
            if key not in current_by_key:
                changes.append(_removed(previous))

        changes.sort(key=lambda change: (change.asset, change.technology))
        return TechnologyHistoryComparison(
            changes=tuple(changes),
            unchanged=unchanged,
            historical=len(historical),
            current=len(current),
        )

    def summarize(self, comparison: TechnologyHistoryComparison) -> dict[str, int]:
        """Return a compact summary of a comparison."""
        counts: dict[str, int] = {_CHANGE_ADDED: 0, _CHANGE_REMOVED: 0, _CHANGE_CHANGED: 0}
        for change in comparison.changes:
            counts[change.change_type] = counts.get(change.change_type, 0) + 1
        return counts

    def by_kind(self, comparison: TechnologyHistoryComparison, change_type: str) -> list[TechChange]:
        """Return the changes of a single change type."""
        return [change for change in comparison.changes if change.change_type == change_type]


# -- change factories ---------------------------------------------------------


def _added(observation: TechnologyObservation) -> TechChange:
    return TechChange(
        asset=observation.asset,
        technology=observation.canonical_name or observation.raw_name,
        change_type=_CHANGE_ADDED,
        current=_value_of(observation),
        source=observation.tool_id or observation.source,
        details={"category": observation.category.value, "family": observation.family.value},
    )


def _removed(observation: TechnologyObservation) -> TechChange:
    return TechChange(
        asset=observation.asset,
        technology=observation.canonical_name or observation.raw_name,
        change_type=_CHANGE_REMOVED,
        previous=_value_of(observation),
        source=observation.tool_id or observation.source,
        details={"category": observation.category.value, "family": observation.family.value},
    )


def _changed(previous: TechnologyObservation, current: TechnologyObservation) -> TechChange:
    return TechChange(
        asset=current.asset,
        technology=current.canonical_name or current.raw_name,
        change_type=_CHANGE_CHANGED,
        previous=_value_of(previous),
        current=_value_of(current),
        source=current.tool_id or current.source,
        details={
            "previous_category": previous.category.value,
            "current_category": current.category.value,
            "previous_observed_at": previous.observed_at,
        },
    )


# -- observation accessors ----------------------------------------------------


def _key(observation: TechnologyObservation) -> str:
    return observation.key()


def _value_of(observation: TechnologyObservation) -> str:
    """Return the scalar value that defines a technology's change state."""
    version = observation.version or ""
    category = observation.category.value
    family = observation.family.value
    return f"{category}|{family}|{version}"
