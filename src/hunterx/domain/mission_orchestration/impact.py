# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Impact analysis engine.

Sprint 032. For validated findings the engine computes technical impact,
affected assets, affected users, data exposure potential, privilege boundary,
business impact indicators, exploitability, reproducibility and confidence.
Impact analysis runs only on findings that reached the ``verified`` stage or
beyond — a candidate never receives an impact analysis.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.mission_orchestration.models import ImpactAnalysis
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ImpactAnalysisEngine:
    """Compute impact analysis for validated findings."""

    #: Vulnerability class → (technical impact, privilege boundary) hints.
    _TECHNICAL_IMPACT: dict[str, tuple[str, str]] = {
        "rce": ("remote command execution under the application's privileges", "application → host"),
        "sql_injection": ("database read/write within the application's DB user", "application → database"),
        "xss": ("client-side script execution in the victim's browser session", "application → browser session"),
        "ssrf": ("server-side request forgery reaching internal services", "application → internal network"),
        "idor": ("object-level authorization bypass", "user → arbitrary object"),
        "lfi": ("local file inclusion of readable server files", "application → filesystem"),
        "ssti": ("server-side template injection", "template → application"),
        "auth_bypass": ("authentication bypass", "anonymous → authenticated"),
        "secret_exposure": ("credential/secret disclosure", "repository → credential"),
    }

    def analyze(
        self,
        *,
        finding: dict[str, Any],
        mission_id: str,
        confidence: float = 0.0,
        reproducible: bool = True,
    ) -> ImpactAnalysis:
        """Compute the impact analysis for a validated finding.

        ``finding`` is a finding-dictionary carrying ``finding_id``,
        ``vulnerability_class``, ``target``/``asset_key`` and ``severity``.
        """
        finding_id = str(finding.get("finding_id", generate_id()))
        vulnerability_class = str(finding.get("vulnerability_class", "unknown_behavior"))
        affected_assets = tuple(
            dict.fromkeys(
                [
                    str(finding.get("asset_key") or finding.get("target") or ""),
                    *[str(asset) for asset in (finding.get("affected_assets") or ()) if asset],
                ]
            )
        )
        technical_impact, privilege_boundary = self._TECHNICAL_IMPACT.get(
            vulnerability_class,
            ("undefined technical impact; requires domain-specific analysis", "undefined"),
        )
        if vulnerability_class == "unknown_behavior":
            technical_impact = "behavior requires behavioral-model analysis before impact is assessed"
            privilege_boundary = "unknown"

        severity = str(finding.get("severity", "info")).lower()
        data_exposure = self._data_exposure(vulnerability_class, severity)
        exploitability = self._exploitability(vulnerability_class, severity)
        affected_users = self._affected_users(finding)

        return ImpactAnalysis(
            impact_id=generate_id(),
            finding_id=finding_id,
            mission_id=mission_id,
            technical_impact=technical_impact,
            affected_assets=affected_assets,
            affected_users=affected_users,
            data_exposure_potential=data_exposure,
            privilege_boundary=privilege_boundary,
            business_impact_indicators={
                "severity": severity,
                "exposure_surface": str(finding.get("exposure_surface", "network")),
                "asset_criticality": str(finding.get("asset_criticality", "unknown")),
            },
            exploitability=exploitability,
            reproducibility=bool(reproducible),
            confidence=round(confidence, 4),
            analyzed_at=utcnow_iso(),
        )

    def to_dict(self, analysis: ImpactAnalysis) -> dict[str, Any]:
        """Serialize an impact analysis."""
        return analysis.to_dict()

    @staticmethod
    def _data_exposure(vulnerability_class: str, severity: str) -> str:
        """Estimate data-exposure potential from the vulnerability class."""
        if vulnerability_class in ("rce", "sql_injection", "ssrf"):
            return "high" if severity in ("critical", "high") else "medium"
        if vulnerability_class in ("xss", "ssti", "lfi", "idor"):
            return "medium"
        return "low"

    @staticmethod
    def _exploitability(vulnerability_class: str, severity: str) -> str:
        """Estimate exploitability from the vulnerability class."""
        if vulnerability_class in ("rce", "sql_injection", "lfi", "ssti"):
            return "high"
        if vulnerability_class in ("ssrf", "idor", "xss"):
            return "medium"
        return "low"

    @staticmethod
    def _affected_users(finding: dict[str, Any]) -> str:
        """Return the affected-users estimate."""
        users = finding.get("affected_users")
        if users:
            return str(users)
        return "all users of the affected application context"


__all__ = ["ImpactAnalysisEngine"]
