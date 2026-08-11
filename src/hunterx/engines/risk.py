# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Risk scoring engine.

Computes a normalized risk score for a finding from its severity band and any
additional risk metadata the producing tool supplied.
"""

from __future__ import annotations

from hunterx.domain.entities import Finding
from hunterx.domain.services.risk import RiskScorerService
from hunterx.domain.value_objects import RiskScore, Severity

_SEVERITY_BASE = {
    Severity.NONE: 0.0,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 9.5,
}


class DefaultRiskScorer(RiskScorerService):
    """Score a finding by severity band, optionally nudged by tool metadata.

    A producing tool may include a ``risk_override`` value in
    ``finding.metadata``; when present and within range it takes precedence.
    """

    def score(self, finding: Finding) -> RiskScore:
        """Compute the normalized risk score for a finding."""
        override = finding.metadata.get("risk_override")
        if isinstance(override, (int, float)):
            return RiskScore(float(override))
        base = _SEVERITY_BASE.get(finding.severity, 0.0)
        if finding.risk_score is not None:
            return RiskScore(finding.risk_score)
        return RiskScore(base)
