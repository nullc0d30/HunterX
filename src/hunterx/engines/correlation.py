# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Correlation engine.

Groups findings into clusters by shared target and content themes so the final
report describes relationships rather than disconnected observations.
"""

from __future__ import annotations

from hunterx.domain.entities import Finding
from hunterx.domain.services.correlator import CorrelationGroup, CorrelatorService
from hunterx.shared.ids import generate_id


class TargetCorrelator(CorrelatorService):
    """Correlate findings by shared target and tool.

    Findings targeting the same identifier are grouped together; the narrative
    summarizes the affected target and the tools involved.
    """

    def correlate(self, findings: list[Finding]) -> list[CorrelationGroup]:
        """Group findings into clusters by shared target and tool."""
        buckets: dict[str, list[Finding]] = {}
        for finding in findings:
            buckets.setdefault(finding.target, []).append(finding)

        groups: list[CorrelationGroup] = []
        for target, members in sorted(buckets.items()):
            tools = sorted({member.tool for member in members})
            groups.append(
                CorrelationGroup(
                    group_id=generate_id(),
                    finding_ids=tuple(member.finding_id for member in members),
                    narrative=(
                        f"{len(members)} finding(s) on target '{target}' "
                        f"produced by {', '.join(tools)}."
                    ),
                )
            )
        return groups
