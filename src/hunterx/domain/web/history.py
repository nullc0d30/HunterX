# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Temporal change detection for the web attack-surface inventory.

Compares a current crawl against a previously persisted snapshot and reports
which URLs appeared, disappeared or changed (status/content-type). Deterministic
and stateless — the caller supplies the historical and current observations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from hunterx.domain.web.models import URLObservation


@dataclass(frozen=True, slots=True)
class WebCrawlChange:
    """One detected change in the web surface.

    Attributes:
        url: the affected URL.
        change_type: ``new`` | ``removed`` | ``changed``.
        previous: previous value (status/content-type) when known.
        current: current value when known.
        field: the changed attribute (``status_code``, ``content_type``).
        tool_id: source of the current observation.
        correlation_id / mission_id.

    """

    url: str
    change_type: str
    previous: str = ""
    current: str = ""
    field: str = ""
    tool_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class WebCrawlDiff:
    """Aggregated diff of two web-surface snapshots."""

    changes: list[WebCrawlChange] = field(default_factory=list)

    @property
    def added(self) -> list[WebCrawlChange]:
        """Return the new-URL changes."""
        return [change for change in self.changes if change.change_type == "new"]

    @property
    def removed(self) -> list[WebCrawlChange]:
        """Return the removed-URL changes."""
        return [change for change in self.changes if change.change_type == "removed"]

    @property
    def modified(self) -> list[WebCrawlChange]:
        """Return the changed-URL changes."""
        return [change for change in self.changes if change.change_type == "changed"]

    def counts(self) -> dict[str, int]:
        """Return per-type change counts."""
        return {
            "new": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.modified),
        }


class WebCrawlHistory:
    """Diff a current crawl against a historical snapshot."""

    def compare(
        self,
        historical: Sequence[URLObservation],
        current: Sequence[URLObservation],
        *,
        correlation_id: str = "",
        mission_id: str = "",
    ) -> WebCrawlDiff:
        """Return the changes between two URL snapshots.

        Comparison keys on the canonical URL (the dedup key without method),
        so a resource moved between methods is reported as a change rather
        than a spurious removal.
        """
        past = {obs.url: obs for obs in historical}
        present = {obs.url: obs for obs in current}
        diff = WebCrawlDiff()
        for url, observation in present.items():
            previous = past.get(url)
            if previous is None:
                diff.changes.append(
                    WebCrawlChange(
                        url=url,
                        change_type="new",
                        current=_state(observation),
                        tool_id=observation.tool_id,
                        correlation_id=correlation_id,
                        mission_id=mission_id,
                    )
                )
                continue
            _append_modifications(
                diff,
                url,
                previous,
                observation,
                correlation_id=correlation_id,
                mission_id=mission_id,
            )
        for url, observation in past.items():
            if url not in present:
                diff.changes.append(
                    WebCrawlChange(
                        url=url,
                        change_type="removed",
                        previous=_state(observation),
                        tool_id=observation.tool_id,
                        correlation_id=correlation_id,
                        mission_id=mission_id,
                    )
                )
        return diff


def _state(observation: URLObservation) -> str:
    """Return a compact state string for an observation."""
    status = observation.status_code or 0
    content_type = observation.content_type or ""
    return f"{status} {content_type}".strip()


def _append_modifications(
    diff: WebCrawlDiff,
    url: str,
    previous: URLObservation,
    current: URLObservation,
    *,
    correlation_id: str,
    mission_id: str,
) -> None:
    """Record status/content-type changes for a URL present in both snapshots."""
    if previous.status_code != current.status_code and current.status_code is not None:
        diff.changes.append(
            WebCrawlChange(
                url=url,
                change_type="changed",
                field="status_code",
                previous=str(previous.status_code or ""),
                current=str(current.status_code),
                tool_id=current.tool_id,
                correlation_id=correlation_id,
                mission_id=mission_id,
            )
        )
    if previous.content_type != current.content_type and current.content_type:
        diff.changes.append(
            WebCrawlChange(
                url=url,
                change_type="changed",
                field="content_type",
                previous=previous.content_type or "",
                current=current.content_type,
                tool_id=current.tool_id,
                correlation_id=correlation_id,
                mission_id=mission_id,
            )
        )
