# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report view models.

Views are the presentation-facing projection of report data. Renderers read
views (never domain entities directly) so a change in rendering never leaks
into the domain, and vice versa.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities import Finding, Mission, Report
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class FindingView:
    """Presentation projection of a finding."""

    finding_id: str
    title: str
    severity: str
    target: str
    tool: str
    description: str = ""
    risk_score: float | None = None
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MissionView:
    """Presentation projection of a mission."""

    mission_id: str
    name: str
    kind: str
    status: str
    progress: float = 0.0
    targets: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReportView:
    """The full data surface available to every renderer."""

    report_id: str
    mission: MissionView
    title: str
    summary: str = ""
    findings: tuple[FindingView, ...] = ()
    correlation_groups: tuple[dict[str, object], ...] = ()
    generated_at: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


def build_report_view(
    report: Report,
    *,
    mission: Mission | None = None,
    findings: list[Finding] | None = None,
    correlation_groups: list[dict[str, object]] | None = None,
) -> ReportView:
    """Project domain objects into a renderer-friendly :class:`ReportView`."""
    mission_view = MissionView(
        mission_id=mission.mission_id if mission else report.mission_id,
        name=mission.name if mission else report.mission_id,
        kind=mission.kind.value if mission else "unknown",
        status=mission.status.value if mission else "unknown",
        progress=mission.progress if mission else 0.0,
        targets=tuple(mission.targets) if mission else (),
    )
    finding_views = tuple(
        FindingView(
            finding_id=finding.finding_id,
            title=finding.title,
            severity=finding.severity.name,
            target=finding.target,
            tool=finding.tool,
            description=finding.description,
            risk_score=finding.risk_score,
            references=tuple(finding.references),
        )
        for finding in (findings or [])
    )
    return ReportView(
        report_id=report.report_id,
        mission=mission_view,
        title=report.title,
        summary=report.summary,
        findings=finding_views,
        correlation_groups=tuple(correlation_groups or ()),
        generated_at=utcnow_iso(),
    )
