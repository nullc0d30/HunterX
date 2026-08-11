# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Structured reasoning trace.

Sprint 032. Persists structured reasoning metadata — observation, hypothesis,
decision, evidence, action, result, decision rationale — as an auditable
reasoning graph. It never stores arbitrary uncontrolled internal
chain-of-thought. Every entry links to its parent so the full reasoning path
can be replayed.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.mission_orchestration.enums import ReasoningTraceKind
from hunterx.domain.mission_orchestration.models import ReasoningTraceEntry
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ReasoningTrace:
    """Append and query structured reasoning-trace entries."""

    def __init__(self) -> None:
        self._entries: list[ReasoningTraceEntry] = []

    def record(
        self,
        *,
        mission_id: str,
        kind: ReasoningTraceKind | str,
        node_id: str,
        content: dict[str, Any],
        parent_entry_id: str = "",
    ) -> ReasoningTraceEntry:
        """Append a structured reasoning-trace entry."""
        kind_enum = kind if isinstance(kind, ReasoningTraceKind) else ReasoningTraceKind(kind)
        entry = ReasoningTraceEntry(
            entry_id=generate_id(),
            mission_id=mission_id,
            kind=kind_enum,
            node_id=node_id,
            content=dict(content),
            parent_entry_id=parent_entry_id,
            occurred_at=utcnow_iso(),
        )
        self._entries.append(entry)
        return entry

    def entries(self, mission_id: str = "") -> list[ReasoningTraceEntry]:
        """Return trace entries, optionally filtered by mission."""
        if not mission_id:
            return list(self._entries)
        return [entry for entry in self._entries if entry.mission_id == mission_id]

    def chain_for(self, entry_id: str) -> list[ReasoningTraceEntry]:
        """Return the reasoning chain ending at ``entry_id`` (parents first)."""
        by_id = {entry.entry_id: entry for entry in self._entries}
        chain: list[ReasoningTraceEntry] = []
        current = by_id.get(entry_id)
        while current is not None:
            chain.insert(0, current)
            current = by_id.get(current.parent_entry_id) if current.parent_entry_id else None
        return chain

    def to_dicts(self, mission_id: str = "") -> list[dict[str, Any]]:
        """Serialize trace entries to JSON-safe mappings."""
        return [entry.to_dict() for entry in self.entries(mission_id)]

    def reset(self) -> None:
        """Drop all trace entries (test isolation)."""
        self._entries.clear()

    def extend(self, entries: list[ReasoningTraceEntry]) -> None:
        """Import trace entries (e.g. on resume)."""
        existing = {entry.entry_id for entry in self._entries}
        for entry in entries:
            if entry.entry_id not in existing:
                self._entries.append(entry)
                existing.add(entry.entry_id)


__all__ = ["ReasoningTrace"]
