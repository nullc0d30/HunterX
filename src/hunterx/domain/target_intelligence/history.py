# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target History & Change Detection.

Sprint 026. HunterX maintains historical target state: first_seen, last_seen,
changed_at, previous_value, new_value, source and confidence for every tracked
fact. The :class:`TargetHistory` records entries and the
:class:`TargetChangeDetector` compares a previous asset/intelligence snapshot
with the current one and classifies changes as NEW, REMOVED, CHANGED,
REAPPEARED, EXPIRED, RECLASSIFIED, CORROBORATED or CONFLICTED. Detected changes
influence future mission planning.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.target_intelligence.enums import ChangeKind
from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceChange,
    IntelligenceConflict,
    TargetHistoryEntry,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class TargetHistory:
    """Append-only history of target facts.

    History entries are immutable records of "what changed, from what, to
    what, observed by whom, with what confidence".
    """

    def __init__(self) -> None:
        self._entries: dict[str, list[TargetHistoryEntry]] = {}

    def record(
        self,
        *,
        target_id: str,
        mission_id: str = "",
        asset_key: str = "",
        attribute: str = "",
        kind: ChangeKind = ChangeKind.NEW,
        previous_value: str = "",
        new_value: str = "",
        source: str = "",
        confidence: float = 1.0,
        changed_at: str = "",
        correlation_id: str = "",
    ) -> TargetHistoryEntry:
        """Append a history entry for a target."""
        entry = TargetHistoryEntry(
            history_id=generate_id(),
            target_id=target_id,
            mission_id=mission_id,
            asset_key=asset_key,
            attribute=attribute,
            kind=kind,
            previous_value=previous_value,
            new_value=new_value,
            source=source,
            confidence=confidence,
            changed_at=changed_at or utcnow_iso(),
            correlation_id=correlation_id,
        )
        self._entries.setdefault(target_id, []).append(entry)
        return entry

    def for_target(self, target_id: str, *, limit: int = 0) -> list[TargetHistoryEntry]:
        """Return history entries for a target (newest first)."""
        entries = list(reversed(self._entries.get(target_id, [])))
        return entries[:limit] if limit else entries

    def count(self, target_id: str = "") -> int:
        """Return the number of recorded entries (optionally per target)."""
        if target_id:
            return len(self._entries.get(target_id, []))
        return sum(len(entries) for entries in self._entries.values())

    def clear_target(self, target_id: str) -> None:
        """Drop history for a target."""
        self._entries.pop(target_id, None)


class TargetChangeDetector:
    """Detect intelligence changes between two target snapshots.

    The detector works on canonical asset fingerprints (kind + name + key +
    properties) so a tool run can be diffed against the persisted state without
    holding the whole history in memory.
    """

    #: Threshold (seconds) after which a missing asset is considered EXPIRED
    #: rather than merely REMOVED. Configurable per instance.
    def __init__(self, *, expiry_days: float = 30.0) -> None:
        self._expiry_seconds = expiry_days * 86400.0

    def detect(
        self,
        *,
        target_id: str,
        mission_id: str = "",
        previous: Mapping[str, IntelligenceAsset],
        current: Mapping[str, IntelligenceAsset],
        now: str | None = None,
        source: str = "target-intelligence",
    ) -> list[IntelligenceChange]:
        """Return classified changes comparing ``current`` to ``previous``."""
        from hunterx.shared.time import to_utc_datetime

        stamp = now or utcnow_iso()
        now_dt = to_utc_datetime(stamp)
        changes: list[IntelligenceChange] = []

        for key in sorted(current):
            asset = current[key]
            prior = previous.get(key)
            if prior is None:
                changes.append(
                    IntelligenceChange(
                        change_id=generate_id(),
                        target_id=target_id,
                        mission_id=mission_id,
                        asset_key=key,
                        kind=ChangeKind.NEW,
                        previous={},
                        current=asset.to_dict(),
                        source=source,
                        confidence=asset.confidence,
                        detected_at=stamp,
                    )
                )
            else:
                kind, previous_map, current_map = self._classify(prior, asset)
                if kind is not None:
                    changes.append(
                        IntelligenceChange(
                            change_id=generate_id(),
                            target_id=target_id,
                            mission_id=mission_id,
                            asset_key=key,
                            kind=kind,
                            previous=previous_map,
                            current=current_map,
                            source=source,
                            confidence=asset.confidence,
                            detected_at=stamp,
                        )
                    )

        for key in sorted(previous):
            if key in current:
                continue
            prior = previous[key]
            expired = self._expired(prior, now_dt)
            changes.append(
                IntelligenceChange(
                    change_id=generate_id(),
                    target_id=target_id,
                    mission_id=mission_id,
                    asset_key=key,
                    kind=ChangeKind.EXPIRED if expired else ChangeKind.REMOVED,
                    previous=prior.to_dict(),
                    current={},
                    source=source,
                    confidence=prior.confidence,
                    detected_at=stamp,
                )
            )

        return changes

    def detect_reappeared(
        self,
        *,
        target_id: str,
        mission_id: str = "",
        observed_keys: Sequence[str],
        previously_removed: Sequence[IntelligenceChange],
        source: str = "target-intelligence",
    ) -> list[IntelligenceChange]:
        """Flag assets that were removed before and are observed again."""
        removed_keys = {
            change.asset_key
            for change in previously_removed
            if change.kind in (ChangeKind.REMOVED, ChangeKind.EXPIRED)
        }
        reappeared = set(observed_keys) & removed_keys
        stamp = utcnow_iso()
        return [
            IntelligenceChange(
                change_id=generate_id(),
                target_id=target_id,
                mission_id=mission_id,
                asset_key=key,
                kind=ChangeKind.REAPPEARED,
                previous={},
                current={},
                source=source,
                confidence=0.9,
                detected_at=stamp,
            )
            for key in sorted(reappeared)
        ]

    def detect_conflicts(
        self,
        *,
        target_id: str,
        mission_id: str = "",
        conflicts: Sequence[IntelligenceConflict],
        source: str = "target-intelligence",
    ) -> list[IntelligenceChange]:
        """Emit CONFLICTED changes for open conflicts."""
        stamp = utcnow_iso()
        return [
            IntelligenceChange(
                change_id=generate_id(),
                target_id=target_id,
                mission_id=mission_id,
                asset_key=conflict.asset_key,
                kind=ChangeKind.CONFLICTED,
                previous={},
                current={"conflict_id": conflict.conflict_id, "tools": list(conflict.tools)},
                source=source,
                confidence=0.8,
                detected_at=stamp,
            )
            for conflict in conflicts
            if conflict.state.value == "open"
        ]

    # -- internals ----------------------------------------------------------

    def _classify(
        self,
        prior: IntelligenceAsset,
        current: IntelligenceAsset,
    ) -> tuple[ChangeKind | None, dict[str, Any], dict[str, Any]]:
        """Classify the change between two versions of the same asset."""
        prior_kind = prior.kind.value if isinstance(prior.kind, EntityKind) else str(prior.kind)
        current_kind = current.kind.value if isinstance(current.kind, EntityKind) else str(current.kind)
        if prior_kind != current_kind:
            return ChangeKind.RECLASSIFIED, prior.to_dict(), current.to_dict()

        # CORROBORATED: same value, independent new source.
        if prior.name == current.name and prior.properties == current.properties:
            new_sources = set(current.observed_by) - set(prior.observed_by)
            if new_sources and prior.source != current.source:
                return ChangeKind.CORROBORATED, prior.to_dict(), current.to_dict()
            return None, {}, {}

        changed_fields = _diff_fields(prior, current)
        if not changed_fields:
            return None, {}, {}
        return ChangeKind.CHANGED, prior.to_dict(), current.to_dict()

    def _expired(self, asset: IntelligenceAsset, now: Any) -> bool:
        from hunterx.shared.time import to_utc_datetime

        try:
            last_seen = to_utc_datetime(asset.last_seen)
        except ValueError:
            return False
        elapsed = to_utc_datetime(now) - last_seen
        return bool(elapsed.total_seconds() > self._expiry_seconds)


def _diff_fields(prior: IntelligenceAsset, current: IntelligenceAsset) -> list[str]:
    """Return the property names that differ between two assets."""
    prior_props = prior.properties
    current_props = current.properties
    keys = set(prior_props) | set(current_props)
    return sorted(key for key in keys if prior_props.get(key) != current_props.get(key))


__all__ = [
    "ChangeKind",
    "TargetChangeDetector",
    "TargetHistory",
    "TargetHistoryEntry",
    "IntelligenceChange",
]
