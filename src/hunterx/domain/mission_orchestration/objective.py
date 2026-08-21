# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Orchestration objective vocabulary.

Sprint 032. The orchestration layer accepts the mission-objective vocabulary of
the sprint (``full_security_assessment``, ``bug_bounty_hunt``, ``pentest``,
``red_team_assessment``, ...) and maps each name onto the ratified Sprint 027
:class:`MissionObjective` values — the planning vocabulary is never duplicated.
Objectives influence strategy through the decision-engine weights.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import MissionObjective

#: Sprint-032 objective names → ratified Sprint-027 planning objectives.
_OBJECTIVE_MAP: dict[str, MissionObjective] = {
    "full_security_assessment": MissionObjective.FULL_SECURITY_ASSESSMENT,
    "bug_bounty_hunt": MissionObjective.BUG_BOUNTY_ASSESSMENT,
    "bug_bounty_assessment": MissionObjective.BUG_BOUNTY_ASSESSMENT,
    "pentest": MissionObjective.PENTEST_ASSESSMENT,
    "pentest_assessment": MissionObjective.PENTEST_ASSESSMENT,
    "red_team_assessment": MissionObjective.RED_TEAM_SIMULATION,
    "red_team_simulation": MissionObjective.RED_TEAM_SIMULATION,
    "web_application_assessment": MissionObjective.WEB_SECURITY_ASSESSMENT,
    "web_security_assessment": MissionObjective.WEB_SECURITY_ASSESSMENT,
    "api_assessment": MissionObjective.API_SECURITY_ASSESSMENT,
    "api_security_assessment": MissionObjective.API_SECURITY_ASSESSMENT,
    "cloud_assessment": MissionObjective.CLOUD_SECURITY_ASSESSMENT,
    "cloud_security_assessment": MissionObjective.CLOUD_SECURITY_ASSESSMENT,
    "external_attack_surface": MissionObjective.ATTACK_SURFACE_DISCOVERY,
    "attack_surface_discovery": MissionObjective.ATTACK_SURFACE_DISCOVERY,
    "internal_assessment": MissionObjective.NETWORK_SECURITY_ASSESSMENT,
    "network_security_assessment": MissionObjective.NETWORK_SECURITY_ASSESSMENT,
    "vulnerability_research": MissionObjective.VULNERABILITY_DISCOVERY,
    "vulnerability_discovery": MissionObjective.VULNERABILITY_DISCOVERY,
    "targeted_vulnerability_test": MissionObjective.FINDING_VALIDATION,
    "finding_validation": MissionObjective.FINDING_VALIDATION,
    "target_monitoring": MissionObjective.TARGET_MONITORING,
    "proof_collection": MissionObjective.PROOF_COLLECTION,
}


def resolve_objective(name: str) -> MissionObjective:
    """Resolve a sprint objective name to a ratified planning objective.

    Unknown names fall back to the full security assessment default so the
    orchestrator always stays functional.
    """
    normalized = str(name).strip().lower()
    return _OBJECTIVE_MAP.get(normalized, MissionObjective.ATTACK_SURFACE_DISCOVERY)


__all__ = ["resolve_objective"]
