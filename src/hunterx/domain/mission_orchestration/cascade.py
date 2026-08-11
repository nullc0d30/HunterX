# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding cascade & reassessment engine.

Sprint 032. A validated finding may create new attack hypotheses (SSRF →
internal service discovery → new service → new endpoint → new vulnerability
candidate). After every major validated finding the orchestrator recalculates
the attack surface, updates the graph, generates new hypotheses and continues.
The cascade engine derives those follow-on hypotheses deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.mission_orchestration.mission import OrchestratedMission
from hunterx.domain.mission_orchestration.models import MissionHypothesis
from hunterx.domain.target_intelligence.enums import HypothesisType
from hunterx.shared.ids import generate_id


def _to_hypothesis_type(value: object) -> HypothesisType:
    """Coerce a cascade rule category into a canonical :class:`HypothesisType`."""
    if isinstance(value, HypothesisType):
        return value
    try:
        return HypothesisType(str(value))
    except ValueError:
        return HypothesisType.UNKNOWN_BEHAVIOR


@dataclass(frozen=True, slots=True)
class CascadeTrigger:
    """A validated finding that may open new attack hypotheses.

    Attributes:
        finding_id: the validated finding.
        vulnerability_class: class of the validated finding.
        asset_key: asset the finding affects.
        detail: additional context (discovered service, endpoint, credential, ...).

    """

    finding_id: str
    vulnerability_class: str
    asset_key: str
    detail: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", dict(self.detail or {}))


class FindingCascadeEngine:
    """Derive follow-on hypotheses from validated findings.

    Rules are deterministic: each vulnerability class maps to the cascade
    hypotheses it enables (SSRF → internal service discovery; secret exposure →
    authorized credential reuse; new API → authentication/authorization
    analysis; ...).
    """

    def cascade(self, trigger: CascadeTrigger) -> list[MissionHypothesis]:
        """Return the follow-on hypotheses a validated finding opens."""
        rules = {
            "sql_injection": [
                {
                    "statement": f"SQL injection on {trigger.asset_key} may expose database schema/user data; enumerate reachable data.",
                    "category": HypothesisType.INJECTION,
                    "validation_strategy": "database-behavior-mapping",
                    "priority": 0.8,
                },
                {
                    "statement": f"SQL injection on {trigger.asset_key} may enable file/database writes; assess impact boundary.",
                    "category": HypothesisType.RCE,
                    "validation_strategy": "impact-boundary-testing",
                    "priority": 0.6,
                },
            ],
            "ssrf": [
                {
                    "statement": f"SSRF on {trigger.asset_key} may reach internal services; map internal reachability.",
                    "category": HypothesisType.UNKNOWN_BEHAVIOR,
                    "validation_strategy": "internal-service-discovery",
                    "priority": 0.85,
                },
                {
                    "statement": f"SSRF on {trigger.asset_key} may read internal files/metadata; test controlled targets.",
                    "category": HypothesisType.LFI,
                    "validation_strategy": "controlled-ssrf-test",
                    "priority": 0.7,
                },
            ],
            "secret_exposure": [
                {
                    "statement": f"Exposed secret on {trigger.asset_key} may authorize access to associated services; map authorized repositories.",
                    "category": HypothesisType.AUTHENTICATION_ISSUE,
                    "validation_strategy": "credential-context-mapping",
                    "priority": 0.9,
                }
            ],
            "api_security": [
                {
                    "statement": f"New API on {trigger.asset_key} may expose unauthenticated or weakly authorized endpoints.",
                    "category": HypothesisType.AUTHORIZATION_ISSUE,
                    "validation_strategy": "api-endpoint-enumeration",
                    "priority": 0.8,
                },
                {
                    "statement": f"API on {trigger.asset_key} should be inspected for parameter-level injection.",
                    "category": HypothesisType.INJECTION,
                    "validation_strategy": "parameter-injection-testing",
                    "priority": 0.7,
                },
            ],
            "auth_bypass": [
                {
                    "statement": f"Authentication bypass on {trigger.asset_key} may expose privileged functionality.",
                    "category": HypothesisType.AUTHORIZATION_ISSUE,
                    "validation_strategy": "privilege-boundary-testing",
                    "priority": 0.85,
                }
            ],
            "authorization_bypass": [
                {
                    "statement": f"Authorization bypass on {trigger.asset_key} may extend to other privileged objects/endpoints.",
                    "category": HypothesisType.AUTHORIZATION_ISSUE,
                    "validation_strategy": "privilege-boundary-testing",
                    "priority": 0.8,
                },
                {
                    "statement": f"Authorization bypass on {trigger.asset_key} may expose additional credential material; map privileged resources.",
                    "category": HypothesisType.SECRET_EXPOSURE,
                    "validation_strategy": "credential-context-mapping",
                    "priority": 0.7,
                },
            ],
            "idor": [
                {
                    "statement": f"IDOR on {trigger.asset_key} may extend to other objects of the same class.",
                    "category": HypothesisType.IDOR,
                    "validation_strategy": "object-level-authorization-testing",
                    "priority": 0.75,
                }
            ],
        }
        hypotheses: list[MissionHypothesis] = []
        for rule in rules.get(trigger.vulnerability_class, ()):
            hypotheses.append(
                MissionHypothesis(
                    hypothesis_id=generate_id(),
                    mission_id="",
                    statement=str(rule["statement"]),
                    category=_to_hypothesis_type(rule["category"]),
                    validation_strategy=str(rule["validation_strategy"]),
                    priority=float(str(rule["priority"])),
                    confidence=0.5,
                    provenance={
                        "source": "finding-cascade",
                        "parent_finding": trigger.finding_id,
                        "vulnerability_class": trigger.vulnerability_class,
                    },
                )
            )
        return hypotheses

    def reassess(self, mission: OrchestratedMission) -> dict[str, Any]:
        """Return the reassessment summary after a validated finding.

        The reassessment recalculates the attack surface from current context
        and lists the follow-on hypotheses that should be opened.
        """
        validated = [
            finding
            for finding in mission.context.findings
            if finding.get("stage") in ("verified", "proven", "report_ready")
        ]
        follow_ons: list[MissionHypothesis] = []
        for finding in validated:
            trigger = CascadeTrigger(
                finding_id=str(finding.get("finding_id", "")),
                vulnerability_class=str(finding.get("vulnerability_class", "unknown_behavior")),
                asset_key=str(finding.get("asset_key") or finding.get("target") or ""),
                detail=finding,
            )
            follow_ons.extend(self.cascade(trigger))
        return {
            "mission_id": mission.mission_id,
            "validated_findings": len(validated),
            "follow_on_hypotheses": [hypothesis.to_dict() for hypothesis in follow_ons],
            "attack_surface_assets": len(mission.context.assets),
            "endpoints": len(mission.context.endpoints),
            "services": len(mission.context.services),
        }


__all__ = ["CascadeTrigger", "FindingCascadeEngine"]
