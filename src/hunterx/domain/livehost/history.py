# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live discovery historical comparison.

Compares current observations against historical records to detect changes over
time: hosts coming online or going offline, ports opening or closing, service
fingerprints and certificates rotating. Every change is reported with the
before/after values, timestamps and sources so it can be traced and correlated
with security events.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from hunterx.domain.livehost.models import (
    HttpFinding,
    LiveChange,
    LiveHost,
    PortFinding,
    ServiceFinding,
    TlsFinding,
)

_CHANGE_ADDED = "added"
_CHANGE_REMOVED = "removed"
_CHANGE_CHANGED = "changed"


@dataclass(frozen=True, slots=True)
class LiveHistoryComparison:
    """The diff between historical and current discovery state.

    Attributes:
        changes: the detected changes (added/removed/changed).
        unchanged: number of observations present in both snapshots.
        historical: the historical snapshot size.
        current: the current snapshot size.

    """

    changes: tuple[LiveChange, ...] = ()
    unchanged: int = 0
    historical: int = 0
    current: int = 0


class LiveHistory:
    """Compare historical and current discovery snapshots.

    Usage::

        history = LiveHistory()
        diff = history.compare(historical_observations, current_observations)
    """

    def compare(
        self,
        historical: Sequence[object],
        current: Sequence[object],
    ) -> LiveHistoryComparison:
        """Return the changes between ``historical`` and ``current``."""
        historical_by_key = {_key(observation): observation for observation in historical}
        current_by_key = {_key(observation): observation for observation in current}
        changes: list[LiveChange] = []
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

        changes.sort(key=lambda change: change.key)
        return LiveHistoryComparison(
            changes=tuple(changes),
            unchanged=unchanged,
            historical=len(historical),
            current=len(current),
        )

    def summarize(self, comparison: LiveHistoryComparison) -> dict[str, int]:
        """Return a compact summary of a comparison."""
        counts: dict[str, int] = {_CHANGE_ADDED: 0, _CHANGE_REMOVED: 0, _CHANGE_CHANGED: 0}
        for change in comparison.changes:
            counts[change.change_type] = counts.get(change.change_type, 0) + 1
        return counts

    def by_kind(self, comparison: LiveHistoryComparison, kind: str) -> list[LiveChange]:
        """Return the changes affecting a single observation kind."""
        return [change for change in comparison.changes if change.kind == kind]


# -- change factories ---------------------------------------------------------


def _added(observation: object) -> LiveChange:
    return LiveChange(
        kind=_kind_of(observation),
        key=_key(observation),
        change_type=_CHANGE_ADDED,
        current=_value_of(observation),
        source=_source_of(observation),
    )


def _removed(observation: object) -> LiveChange:
    return LiveChange(
        kind=_kind_of(observation),
        key=_key(observation),
        change_type=_CHANGE_REMOVED,
        previous=_value_of(observation),
        source=_source_of(observation),
    )


def _changed(previous: object, current: object) -> LiveChange:
    return LiveChange(
        kind=_kind_of(current),
        key=_key(current),
        change_type=_CHANGE_CHANGED,
        previous=_value_of(previous),
        current=_value_of(current),
        source=_source_of(current),
        details={"previous_observed_at": _observed_of(previous)},
    )


# -- observation accessors ----------------------------------------------------


def _key(observation: object) -> str:
    key = getattr(observation, "key", None)
    return str(key()) if callable(key) else ""


def _kind_of(observation: object) -> str:
    if isinstance(observation, LiveHost):
        return "host"
    if isinstance(observation, PortFinding):
        return "port"
    if isinstance(observation, ServiceFinding):
        return "service"
    if isinstance(observation, TlsFinding):
        return "tls"
    if isinstance(observation, HttpFinding):
        return "http"
    return "unknown"


def _value_of(observation: object) -> str:
    """Return the scalar value that defines an observation's change state."""
    if isinstance(observation, LiveHost):
        return observation.state.value
    if isinstance(observation, PortFinding):
        return observation.state.value
    if isinstance(observation, ServiceFinding):
        return f"{observation.product}|{observation.version}"
    if isinstance(observation, TlsFinding):
        return observation.sha256
    if isinstance(observation, HttpFinding):
        return str(observation.status_code)
    return ""


def _source_of(observation: object) -> str:
    return str(getattr(observation, "source", ""))


def _observed_of(observation: object) -> str:
    return str(getattr(observation, "observed_at", ""))
