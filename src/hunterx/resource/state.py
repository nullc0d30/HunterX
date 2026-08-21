# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource governance — canonical resource states.

The mission resource governor is the single authoritative layer that maps the
live resource situation of the whole HunterX mission process tree (parent +
children + grandchildren + external tools) onto an explicit state. Each state
has a documented behaviour:

``NORMAL``
    Normal bounded execution at the configured concurrency.
``CONSTRAINED``
    Moderate pressure; concurrency is reduced.
``DEGRADED``
    High pressure; nonessential work (heavy tools, bulk probing) is stopped.
``CRITICAL``
    Hard pressure; no new expensive work is spawned (tools, probes, model
    calls).
``EMERGENCY``
    The absolute budget is exceeded; the mission is terminated gracefully
    (stop scheduling, terminate the process tree, persist state, mark
    degraded).

Thresholds are configurable (``hunterx.config.settings.ResourceSettings``) and
are never hardcoded arbitrary values.
"""

from __future__ import annotations

from enum import StrEnum


class ResourceState(StrEnum):
    """Live resource state of the HunterX process tree and host."""

    NORMAL = "normal"
    CONSTRAINED = "constrained"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

    @property
    def admits_new_expensive_work(self) -> bool:
        """Return ``True`` while new expensive work (tools/probes/model) is allowed."""
        return self not in (ResourceState.CRITICAL, ResourceState.EMERGENCY)

    @property
    def is_emergency(self) -> bool:
        """Return ``True`` only for the emergency (hard-budget) state."""
        return self is ResourceState.EMERGENCY


#: Ordered state severity used for comparisons (higher is worse).
_STATE_SEVERITY: dict[ResourceState, int] = {
    ResourceState.NORMAL: 0,
    ResourceState.CONSTRAINED: 1,
    ResourceState.DEGRADED: 2,
    ResourceState.CRITICAL: 3,
    ResourceState.EMERGENCY: 4,
}


def state_severity(state: ResourceState | str) -> int:
    """Return the numeric severity of a resource state."""
    return _STATE_SEVERITY.get(
        state if isinstance(state, ResourceState) else ResourceState(str(state)),
        0,
    )


__all__ = ["ResourceState", "state_severity"]
