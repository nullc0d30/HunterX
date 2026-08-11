# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target-specific tool history.

Tracks what was run against a target/asset/mission, with which version and
configuration, what happened, what was learned and what remains unknown.
Results influence future tool decisions but remain evidence-based and
explainable.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from hunterx.domain.tool_mastery import ToolHistoryEntry, ToolHistoryStatus


@dataclass(slots=True)
class ToolHistory:
    """Per-target tool execution memory.

    Query helpers answer "has tool X run against target Y?", "what versions
    were used?", "what was learned?" — the memory a professional operator
    keeps between engagements.
    """

    entries: list[ToolHistoryEntry] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def record(self, entry: ToolHistoryEntry) -> None:
        """Append a tool history entry (newest first)."""
        with self._lock:
            self.entries.insert(0, entry)

    def record_run(
        self,
        tool_id: str,
        target: str,
        *,
        tool_version: str = "",
        mission_id: str = "",
        configuration: dict[str, object] | None = None,
        status: ToolHistoryStatus = ToolHistoryStatus.COMPLETED,
        learned: str = "",
        unknown: str = "",
    ) -> ToolHistoryEntry:
        """Record a completed run in a single step."""
        entry = ToolHistoryEntry(
            entry_id=_new_id(tool_id, target),
            tool_id=tool_id,
            target=target,
            mission_id=mission_id,
            tool_version=tool_version,
            configuration=dict(configuration or {}),
            status=status,
            learned=learned,
            unknown=unknown,
        )
        self.record(entry)
        return entry

    # -- queries ----------------------------------------------------------

    def history(self, target: str) -> tuple[ToolHistoryEntry, ...]:
        """Return history for ``target``, newest first."""
        with self._lock:
            return tuple(e for e in self.entries if e.target == target)

    def for_tool(self, tool_id: str, target: str | None = None) -> tuple[ToolHistoryEntry, ...]:
        """Return history for ``tool_id`` optionally filtered by target."""
        with self._lock:
            return tuple(
                e
                for e in self.entries
                if e.tool_id == tool_id and (target is None or e.target == target)
            )

    def for_mission(self, mission_id: str) -> tuple[ToolHistoryEntry, ...]:
        """Return history belonging to ``mission_id``."""
        with self._lock:
            return tuple(e for e in self.entries if e.mission_id == mission_id)

    def has_executed(self, target: str, tool_id: str) -> bool:
        """Return ``True`` when ``tool_id`` already ran against ``target``."""
        with self._lock:
            return any(e.tool_id == tool_id for e in self.entries if e.target == target)

    def versions_used(self, target: str, tool_id: str) -> tuple[str, ...]:
        """Return every tool version used against ``target``."""
        versions: list[str] = []
        with self._lock:
            for e in self.entries:
                if e.target == target and e.tool_id == tool_id and e.tool_version and e.tool_version not in versions:
                    versions.append(e.tool_version)
        return tuple(versions)

    def learned_for(self, target: str, tool_id: str) -> tuple[str, ...]:
        """Return the recorded lessons for ``tool_id`` against ``target``."""
        with self._lock:
            return tuple(
                e.learned
                for e in self.entries
                if e.target == target and e.tool_id == tool_id and e.learned
            )

    def tools_for(self, target: str) -> tuple[str, ...]:
        """Return every tool that ran against ``target`` (deduplicated)."""
        tools: list[str] = []
        with self._lock:
            for e in self.entries:
                if e.target == target and e.tool_id not in tools:
                    tools.append(e.tool_id)
        return tuple(tools)

    def clear(self, target: str | None = None) -> None:
        """Clear history, optionally scoped to a target."""
        with self._lock:
            if target is None:
                self.entries.clear()
            else:
                self.entries = [e for e in self.entries if e.target != target]


def _new_id(tool_id: str, target: str) -> str:
    """Build a stable entry id from tool + target + wall clock."""
    import time

    return f"{tool_id}@{target}#{time.time_ns()}"
