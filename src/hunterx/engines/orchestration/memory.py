# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Persistent mission memory.

Every target gets persistent mission memory: previously discovered assets,
technologies, tools used, previous results, vulnerabilities, false positives,
validations, risk, first-seen/last-seen and tool reliability. Memory is scoped
per target so cross-target and cross-mission isolation is guaranteed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class TargetMemory:
    """Persistent mission memory for a single target.

    Attributes:
        target: the target identifier.
        mission_id: owning mission (empty for cross-mission memory).
        discovered_assets: asset identifiers discovered for the target.
        technologies: technology identifiers observed.
        tools_used: tool ids executed against the target.
        previous_results: canonical result summaries keyed by step.
        vulnerabilities: vulnerability identifiers observed.
        false_positives: false-positive identifiers recorded.
        validations: validation outcomes keyed by hypothesis.
        risk: risk assessment summary.
        tool_reliability: per-tool reliability signals.
        evidence_history: evidence ids collected for the target.
        first_seen / last_seen: state-time stamps.

    """

    target: str
    mission_id: str = ""
    discovered_assets: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    previous_results: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    validations: dict[str, str] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    tool_reliability: dict[str, Any] = field(default_factory=dict)
    evidence_history: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)

    def touch(self) -> None:
        """Refresh the last-seen stamp."""
        self.last_seen = utcnow_iso()

    def add_asset(self, asset: str) -> None:
        """Record a discovered asset (deduplicated)."""
        if asset and asset not in self.discovered_assets:
            self.discovered_assets.append(asset)
            self.touch()

    def add_technology(self, technology: str) -> None:
        """Record an observed technology (deduplicated)."""
        if technology and technology not in self.technologies:
            self.technologies.append(technology)
            self.touch()

    def add_tool(self, tool_id: str) -> None:
        """Record a used tool (deduplicated)."""
        if tool_id and tool_id not in self.tools_used:
            self.tools_used.append(tool_id)
            self.touch()

    def add_vulnerability(self, vulnerability_id: str) -> None:
        """Record an observed vulnerability (deduplicated)."""
        if vulnerability_id and vulnerability_id not in self.vulnerabilities:
            self.vulnerabilities.append(vulnerability_id)
            self.touch()

    def record_result(self, step_id: str, summary: dict[str, Any]) -> None:
        """Record a canonical result summary for a step."""
        self.previous_results[step_id] = summary
        self.touch()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "target": self.target,
            "mission_id": self.mission_id,
            "discovered_assets": list(self.discovered_assets),
            "technologies": list(self.technologies),
            "tools_used": list(self.tools_used),
            "previous_results": dict(self.previous_results),
            "vulnerabilities": list(self.vulnerabilities),
            "false_positives": list(self.false_positives),
            "validations": dict(self.validations),
            "risk": dict(self.risk),
            "tool_reliability": dict(self.tool_reliability),
            "evidence_history": list(self.evidence_history),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class MissionMemoryStore:
    """Persistent per-target mission memory keyed by ``(mission_id, target)``.

    When ``mission_id`` is empty, the memory is shared across missions for a
    target. Callers may inject a repository-backed store to make memory durable.
    """

    def __init__(self, *, repository: Any | None = None) -> None:
        self._repository = repository
        self._store: dict[tuple[str, str], TargetMemory] = {}

    def memory(self, *, mission_id: str = "", target: str) -> TargetMemory:
        """Return (creating if needed) the memory for a target."""
        key = (mission_id, target)
        entry = self._store.get(key)
        if entry is None:
            entry = TargetMemory(target=target, mission_id=mission_id)
            self._store[key] = entry
            if self._repository is not None:
                self._repository.save(entry)
        return entry

    def all_for_target(self, target: str) -> list[TargetMemory]:
        """Return every mission memory entry for ``target`` (cross-mission)."""
        return [entry for (_, t), entry in self._store.items() if t == target]

    def targets(self, *, mission_id: str = "") -> list[str]:
        """Return distinct targets with memory, optionally scoped to a mission."""
        if mission_id:
            return [target for (m, target) in self._store if m == mission_id]
        return sorted({target for (_, target) in self._store})

    def update_from_outcome(self, *, mission_id: str, target: str, outcome: Any) -> None:
        """Update target memory from a step outcome."""
        memory = self.memory(mission_id=mission_id, target=target)
        if outcome.tool_id:
            memory.add_tool(outcome.tool_id)
        output = outcome.output
        if isinstance(output, dict):
            for asset in _list_of(output.get("assets")):
                memory.add_asset(str(asset))
            for tech in _list_of(output.get("technologies")):
                memory.add_technology(str(tech))
            for vuln in _list_of(output.get("vulnerabilities")):
                memory.add_vulnerability(str(vuln))
        memory.record_result(outcome.step_id, outcome.to_dict())
        if self._repository is not None:
            self._repository.save(memory)

    def export(self, *, mission_id: str = "") -> list[dict[str, Any]]:
        """Return a JSON-safe export of mission memory."""
        entries: list[TargetMemory] = []
        for (m, _), entry in self._store.items():
            if not mission_id or m == mission_id:
                entries.append(entry)
        return [entry.to_dict() for entry in entries]


def _list_of(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]
