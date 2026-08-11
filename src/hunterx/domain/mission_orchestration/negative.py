# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Negative-evidence engine.

Sprint 032. HunterX must remember what was tested and what was NOT found —
with the exact tool, version, input, conditions and outcome. "Not found" is
never "not vulnerable": a negative record is a bounded observation that keeps
the mission from re-testing blindly while preserving the distinction between
TESTED / NOT_VULNERABLE / NOT_REPRODUCIBLE / BLOCKED / INCONCLUSIVE /
NOT_APPLICABLE / NOT_TESTED.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from hunterx.domain.mission_orchestration.enums import NegativeEvidenceKind
from hunterx.domain.mission_orchestration.models import NegativeEvidenceRecord
from hunterx.shared.ids import generate_content_id, generate_id
from hunterx.shared.time import utcnow_iso


class NegativeEvidenceEngine:
    """Record, query and deduplicate bounded negative-evidence records."""

    def __init__(self) -> None:
        self._records: list[NegativeEvidenceRecord] = []

    def record(
        self,
        *,
        mission_id: str,
        asset_key: str,
        capability: str,
        kind: NegativeEvidenceKind | str = NegativeEvidenceKind.TESTED,
        tool_id: str = "",
        tool_version: str = "",
        input: Any = None,
        outcome: str = "",
        conditions: dict[str, Any] | None = None,
        notes: str = "",
    ) -> NegativeEvidenceRecord:
        """Record a bounded negative-evidence result.

        The record is deduplicated on (asset, capability, tool, input-hash):
        re-recording the same test refreshes the existing record instead of
        duplicating it.
        """
        kind_enum = kind if isinstance(kind, NegativeEvidenceKind) else NegativeEvidenceKind(kind)
        input_hash = generate_content_id("input", str(input))[:24]
        marker = generate_content_id(asset_key, capability, tool_id, input_hash)
        existing = self._find(marker)
        if existing is not None:
            return existing
        record = NegativeEvidenceRecord(
            record_id=generate_id(),
            mission_id=mission_id,
            asset_key=asset_key,
            capability=capability,
            kind=kind_enum,
            tool_id=tool_id,
            tool_version=tool_version,
            input_hash=input_hash,
            outcome=outcome,
            conditions=dict(conditions or {}),
            tested_at=utcnow_iso(),
            notes=notes,
        )
        self._records.append(record)
        return record

    def _find(self, marker: str) -> NegativeEvidenceRecord | None:
        """Return a record matching the content marker."""
        for record in self._records:
            if generate_content_id(record.asset_key, record.capability, record.tool_id, record.input_hash) == marker:
                return record
        return None

    def for_asset(self, asset_key: str) -> list[NegativeEvidenceRecord]:
        """Return negative records for an asset."""
        return [record for record in self._records if record.asset_key == asset_key]

    def for_capability(self, capability: str) -> list[NegativeEvidenceRecord]:
        """Return negative records for a capability."""
        return [record for record in self._records if record.capability == capability]

    def all(self) -> list[NegativeEvidenceRecord]:
        """Return all negative records."""
        return list(self._records)

    def count_by_kind(self) -> dict[str, int]:
        """Return negative-record counts per kind."""
        counts: dict[str, int] = {}
        for record in self._records:
            counts[record.kind.value] = counts.get(record.kind.value, 0) + 1
        return counts

    def known_absent(self, asset_key: str, capability: str, *, tool_id: str = "") -> bool:
        """Return ``True`` when a capability was tested negative on an asset.

        This never claims "not vulnerable" — only that a specific (asset,
        capability, tool) combination was exercised with no evidence.
        """
        for record in self._records:
            if record.asset_key != asset_key or record.capability != capability:
                continue
            if tool_id and record.tool_id != tool_id:
                continue
            if record.kind in (
                NegativeEvidenceKind.NOT_VULNERABLE,
                NegativeEvidenceKind.NOT_REPRODUCIBLE,
                NegativeEvidenceKind.TESTED,
            ):
                return True
        return False

    def reset(self) -> None:
        """Drop all negative records (test isolation)."""
        self._records.clear()

    def extend(self, records: Iterable[NegativeEvidenceRecord]) -> None:
        """Import a batch of records (e.g. on resume)."""
        seen = {generate_content_id(r.asset_key, r.capability, r.tool_id, r.input_hash) for r in self._records}
        for record in records:
            marker = generate_content_id(record.asset_key, record.capability, record.tool_id, record.input_hash)
            if marker not in seen:
                self._records.append(record)
                seen.add(marker)


__all__ = ["NegativeEvidenceEngine"]
