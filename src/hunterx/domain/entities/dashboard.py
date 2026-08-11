# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Dashboard data models.

Lightweight, storage-agnostic models that future dashboards (mission view,
metrics view, health view, event stream) will render from. They are pure value
shapes: no persistence or rendering logic lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class DashboardQuery:
    """A dashboard query: which metric, over which window, grouped by tags."""

    metric: str
    window_seconds: int = 300
    tags: dict[str, str] = field(default_factory=dict)
    aggregate: str = "mean"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the query for API responses."""
        return {
            "metric": self.metric,
            "window_seconds": self.window_seconds,
            "tags": dict(self.tags),
            "aggregate": self.aggregate,
        }


@dataclass(frozen=True, slots=True)
class MetricSeries:
    """A time series of a single metric sample."""

    name: str
    points: list[tuple[float, float]] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the series for charting."""
        return {
            "name": self.name,
            "tags": dict(self.tags),
            "points": [[ts, value] for ts, value in self.points],
        }


@dataclass(frozen=True, slots=True)
class DashboardPanel:
    """A single panel on a dashboard (one query, one or more series)."""

    title: str
    queries: list[DashboardQuery] = field(default_factory=list)
    kind: str = "line"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the panel."""
        return {
            "title": self.title,
            "kind": self.kind,
            "queries": [query.to_dict() for query in self.queries],
        }


@dataclass(frozen=True, slots=True)
class DashboardModel:
    """A dashboard composed of named panels."""

    name: str
    panels: list[DashboardPanel] = field(default_factory=list)
    refresh_seconds: int = 30

    def to_dict(self) -> dict[str, Any]:
        """Serialize the dashboard."""
        return {
            "name": self.name,
            "refresh_seconds": self.refresh_seconds,
            "panels": [panel.to_dict() for panel in self.panels],
        }


#: Reference dashboard definitions supporting the observability UI.
#: These are the models future dashboards will hydrate at runtime.
SYSTEM_DASHBOARDS: tuple[DashboardModel, ...] = (
    DashboardModel(
        name="overview",
        refresh_seconds=15,
        panels=[
            DashboardPanel(title="Execution Duration", queries=[DashboardQuery("execution_duration_seconds")]),
            DashboardPanel(title="Error Rate", queries=[DashboardQuery("error_rate")]),
            DashboardPanel(title="Cache Hit Ratio", queries=[DashboardQuery("cache_hit_ratio")]),
        ],
    ),
    DashboardModel(
        name="missions",
        refresh_seconds=30,
        panels=[
            DashboardPanel(title="Mission Duration", queries=[DashboardQuery("mission_duration_seconds")]),
            DashboardPanel(title="Success vs Failure", queries=[DashboardQuery("mission_result")]),
        ],
    ),
    DashboardModel(
        name="health",
        refresh_seconds=60,
        panels=[
            DashboardPanel(title="Component Health", kind="table", queries=[]),
            DashboardPanel(title="Queue Size", queries=[DashboardQuery("queue_size")]),
            DashboardPanel(title="Memory Usage", queries=[DashboardQuery("memory_usage_bytes")]),
        ],
    ),
    DashboardModel(
        name="events",
        refresh_seconds=10,
        panels=[
            DashboardPanel(title="Event Stream", kind="table", queries=[]),
            DashboardPanel(title="Events by Category", kind="bar", queries=[DashboardQuery("events_published")]),
        ],
    ),
)


def dashboard_definitions() -> list[dict[str, Any]]:
    """Return the serialized reference dashboard definitions."""
    return [dashboard.to_dict() for dashboard in SYSTEM_DASHBOARDS]
