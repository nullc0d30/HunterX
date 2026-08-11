# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Planning engine.

Deterministic planner that expands a mission into an ordered, dependency-aware
plan. Steps are derived from the mission's kind and the configured workflow
definition.
"""

from __future__ import annotations

from hunterx.domain.entities import Mission, MissionKind
from hunterx.domain.services.planner import Plan, PlannedStep, PlannerService
from hunterx.shared.ids import generate_id


class DeterministicPlanner(PlannerService):
    """Expand a mission into a concrete execution plan.

    The default recipe is: enumerate assets → fingerprint services → scan
    for known issues → validate candidate findings. Custom workflows override
    this recipe via the ``workflow`` field of the mission.
    """

    def plan(self, mission: Mission) -> Plan:
        """Expand a mission into an ordered, dependency-aware plan."""
        steps: list[PlannedStep] = []
        sequence = self._recipe(mission.kind)
        for target in mission.targets:
            base = len(steps)
            for index, action in enumerate(sequence):
                steps.append(
                    PlannedStep(
                        step_id=generate_id(),
                        action=action,
                        target=target,
                        parameters=dict(mission.config.get(action, {})),
                        depends_on=tuple(
                            steps[base + previous].step_id for previous in range(index)
                        ),
                    )
                )
        return Plan(tuple(steps))

    @staticmethod
    def _recipe(kind: MissionKind) -> list[str]:
        recipes: dict[MissionKind, list[str]] = {
            MissionKind.RECON: ["recon.enumerate", "recon.fingerprint", "recon.snapshot"],
            MissionKind.SCAN: ["scan.discover", "scan.fingerprint", "scan.vulnerabilities", "scan.validate"],
            MissionKind.ASSESS: ["scan.discover", "scan.fingerprint", "scan.vulnerabilities", "assess.analyze"],
            MissionKind.MONITOR: ["monitor.collect", "monitor.compare"],
            MissionKind.CUSTOM: ["custom.execute"],
        }
        return recipes.get(kind, ["custom.execute"])
