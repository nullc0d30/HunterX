# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding timeline builder.

Builds the finding timeline strictly from actual persisted events and
timestamps — never from invented data. The application service feeds
chronological event snapshots in and the builder orders them.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.reporting.models import FindingTimeline, TimelineEntry
from hunterx.shared.ids import generate_id


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    """One actual timeline event.

    Attributes:
        event: canonical event name.
        detail: explainable detail.
        occurred_at: UTC ISO-8601 event timestamp.
        provenance: producing source.

    """

    event: str
    detail: str = ""
    occurred_at: str = ""
    provenance: str = ""


class FindingTimelineBuilder:
    """Deterministic timeline assembler.

    Events are sorted by their actual occurrence timestamps. Empty timestamps
    are rejected so no invented timestamp enters the timeline.
    """

    def build(self, *, finding_id: str, events: tuple[TimelineEvent, ...]) -> FindingTimeline:
        """Build a timeline from actual events.

        Args:
            finding_id: owning finding.
            events: chronological event records.

        Returns:
            A :class:`FindingTimeline` ordered by occurrence time.

        Raises:
            ValueError: when an event carries no timestamp.

        """
        for event in events:
            if not event.occurred_at:
                raise ValueError(f"timeline event '{event.event}' carries no timestamp; refusing to invent one")
        ordered = tuple(sorted(events, key=lambda item: item.occurred_at))
        entries = tuple(
            TimelineEntry(
                event=item.event,
                detail=item.detail,
                occurred_at=item.occurred_at,
                provenance=item.provenance,
            )
            for item in ordered
        )
        return FindingTimeline(timeline_id=generate_id(), finding_id=finding_id, entries=entries)


__all__ = ["FindingTimelineBuilder", "TimelineEvent"]
