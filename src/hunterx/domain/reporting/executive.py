# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Executive summary engine.

Aggregates finding counts, severity distribution, critical assets, major
attack paths, root causes, risk concentration, remediation priorities and
validated impact into an executive-level summary that avoids technical jargon
where unnecessary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.reporting.models import ExecutiveSummary


@dataclass(frozen=True, slots=True)
class ExecutiveSummaryInput:
    """Inputs for the executive summary engine.

    Attributes:
        report_id: report identity.
        findings: finding-intelligence mappings (JSON-safe).
        attack_paths: attack-path references.
        root_causes: root-cause references.

    """

    report_id: str = ""
    findings: tuple[dict[str, Any], ...] = ()
    attack_paths: tuple[str, ...] = ()
    root_causes: tuple[str, ...] = ()


class ExecutiveSummaryEngine:
    """Deterministic executive summary aggregator."""

    def summarize(self, inp: ExecutiveSummaryInput) -> ExecutiveSummary:
        """Summarize the report at executive level.

        Args:
            inp: aggregated report inputs.

        Returns:
            An :class:`ExecutiveSummary`.

        """
        severity_distribution: dict[str, int] = {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        critical_assets: set[str] = set()
        remediation_priorities: list[str] = []
        validated_impact: list[str] = []
        for finding in inp.findings:
            severity = str(finding.get("severity") or {}).lower()
            severity = (
                str((finding.get("severity") or {}).get("severity") or "informational")
                if isinstance(finding.get("severity"), dict)
                else "informational"
            )
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            priority = (finding.get("priority") or {}).get("priority")
            if isinstance(finding.get("priority"), dict) and priority:
                remediation_priorities.append(
                    f"{priority.upper()} - {finding.get('finding_id')} ({severity})"
                )
            criticality = (finding.get("asset_criticality") or {})
            if isinstance(criticality, dict) and criticality.get("importance") == "critical":
                critical_assets.add(str(criticality.get("asset") or finding.get("finding_id")))
            if isinstance(finding.get("impact"), dict) and (finding.get("impact") or {}).get("any_impact"):
                validated_impact.append(str(finding.get("finding_id")))

        risk_concentration: list[str] = []
        for severity, count in severity_distribution.items():
            if count and severity in ("high", "critical"):
                risk_concentration.append(f"{count} {severity} findings")

        return ExecutiveSummary(
            report_id=inp.report_id,
            finding_count=len(inp.findings),
            severity_distribution=severity_distribution,
            critical_assets=tuple(sorted(critical_assets)),
            major_attack_paths=tuple(inp.attack_paths),
            root_causes=tuple(inp.root_causes),
            risk_concentration=tuple(risk_concentration),
            remediation_priorities=tuple(remediation_priorities),
            validated_impact=tuple(validated_impact),
        )


__all__ = ["ExecutiveSummaryEngine", "ExecutiveSummaryInput"]
