# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission coverage engine.

Sprint 032. Tracks assets covered, ports covered, services covered,
technologies covered, endpoints covered, parameters covered, vulnerability
classes tested, findings validated, unknown areas and untested attack paths.
Coverage is measured per (asset, capability) cell — never "number of tools
executed".

The engine mirrors the Sprint 026 :class:`CoverageEngine` contract at the
orchestration aggregate level so coverage is reported per mission.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.mission_orchestration.mission import OrchestratedMission
from hunterx.domain.target_intelligence.enums import CoverageCapability, CoverageState


class MissionCoverageEngine:
    """Record and query mission-level coverage."""

    def record(
        self,
        mission: OrchestratedMission,
        *,
        asset_key: str,
        capability: CoverageCapability | str,
        state: CoverageState | str,
        tool_id: str = "",
        confidence: float = 0.0,
        evidence_refs: tuple[str, ...] = (),
        tested_at: str = "",
        notes: str = "",
    ) -> None:
        """Record (or replace) a coverage cell on the mission."""
        mission.record_coverage(
            asset_key=asset_key,
            capability=capability,
            state=state,
            tool_id=tool_id,
            confidence=confidence,
            evidence_refs=evidence_refs,
            tested_at=tested_at,
            notes=notes,
        )

    def unknown_areas(self, mission: OrchestratedMission) -> list[str]:
        """Return asset keys with uncovered (unknown/not-assessed) cells."""
        unknown: set[str] = set()
        for asset_key, cells in mission.coverage.items():
            if any(cell.state.uncovered() for cell in cells.values()):
                unknown.add(asset_key)
        return sorted(unknown)

    def untested_capabilities(self, mission: OrchestratedMission) -> list[str]:
        """Return capabilities never exercised on any asset."""
        untested: dict[str, int] = {}
        for cells in mission.coverage.values():
            for cell in cells.values():
                untested[cell.capability] = untested.get(cell.capability, 0) + (
                    1 if cell.state.uncovered() else 0
                )
        return sorted(
            (capability for capability, count in untested.items() if count > 0),
            key=lambda capability: -untested[capability],
        )

    def summary(self, mission: OrchestratedMission) -> dict[str, Any]:
        """Return the JSON-safe coverage summary."""
        cells = mission.coverage_cells()
        by_state: dict[str, int] = {}
        by_capability: dict[str, int] = {}
        validated = 0
        for cell in cells:
            by_state[cell.state.value] = by_state.get(cell.state.value, 0) + 1
            by_capability[cell.capability] = by_capability.get(cell.capability, 0) + 1
            if cell.state in (CoverageState.VALIDATED, CoverageState.PROVED):
                validated += 1
        return {
            "coverage_ratio": mission.coverage_ratio(),
            "cell_count": len(cells),
            "validated_cells": validated,
            "by_state": by_state,
            "by_capability": by_capability,
            "unknown_areas": self.unknown_areas(mission),
            "untested_capabilities": self.untested_capabilities(mission),
        }

    @staticmethod
    def capability_for_class(vulnerability_class: str) -> CoverageCapability:
        """Return the coverage capability for a vulnerability class."""
        return CoverageCapability.for_hypothesis(vulnerability_class)


__all__ = ["MissionCoverageEngine"]
