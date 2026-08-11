# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reportability engine.

Determines whether a finding is reportable by evaluating scope, validation,
proof, reproducibility, impact, severity, confidence, evidence completeness,
duplicate status, false-positive status, required metadata and policy. The
verdict is one of REPORTABLE / INCOMPLETE / DISPUTED / DUPLICATE /
OUT_OF_SCOPE / NOT_ACTIONABLE.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.reporting.enums import ReportabilityStatus
from hunterx.domain.reporting.models import Reportability, ReportabilityCheck


@dataclass(frozen=True, slots=True)
class ReportabilityInput:
    """Inputs for the reportability engine.

    Attributes:
        finding_id: owning finding.
        finding_state: canonical finding lifecycle state.
        scope_ok: whether the finding is in scope.
        validated: whether the finding was validated.
        proof_validated: whether the proof was validated.
        reproducible: whether the finding was reproduced.
        impact_assessed: whether positive impact evidence exists.
        severity: final severity.
        confidence: evidence-driven confidence in ``[0, 1]``.
        evidence_items: number of evidence fragments.
        duplicate: whether the finding was marked duplicate.
        false_positive: whether the finding was marked false positive.
        required_metadata_present: whether required metadata is present.
        policy_allows: whether reporting policy permits the finding.

    """

    finding_id: str = ""
    finding_state: str = "candidate"
    scope_ok: bool = False
    validated: bool = False
    proof_validated: bool = False
    reproducible: bool = False
    impact_assessed: bool = False
    severity: str = "informational"
    confidence: float = 0.0
    evidence_items: int = 0
    duplicate: bool = False
    false_positive: bool = False
    required_metadata_present: bool = True
    policy_allows: bool = True


class ReportabilityEngine:
    """Deterministic reportability evaluator.

    Every criterion is evaluated as an explainable check; the verdict follows
    from the mandatory checks.
    """

    def evaluate(self, inp: ReportabilityInput) -> Reportability:
        """Evaluate whether ``inp`` is reportable.

        Returns:
            A :class:`Reportability` verdict with per-criteria checks.

        """
        checks = [
            ReportabilityCheck("scope", inp.scope_ok, "target is in scope", required=True),
            ReportabilityCheck("validated", inp.validated, "finding validated", required=True),
            ReportabilityCheck(
                "proof_validated",
                inp.proof_validated,
                "proof validated",
                required=inp.severity in ("high", "critical"),
            ),
            ReportabilityCheck(
                "reproducible",
                inp.reproducible,
                "behavior reproducible",
                required=inp.severity in ("high", "critical"),
            ),
            ReportabilityCheck(
                "impact_assessed",
                inp.impact_assessed,
                "impact assessed with evidence",
                required=inp.severity not in ("informational", "low"),
            ),
            ReportabilityCheck("evidence_completeness", inp.evidence_items >= 2, "evidence present", required=True),
            ReportabilityCheck("not_duplicate", not inp.duplicate, "finding is not a duplicate", required=True),
            ReportabilityCheck("not_false_positive", not inp.false_positive, "finding is not a false positive", required=True),
            ReportabilityCheck("metadata", inp.required_metadata_present, "required metadata present", required=True),
            ReportabilityCheck("policy", inp.policy_allows, "reporting policy allows", required=True),
            ReportabilityCheck(
                "confidence",
                inp.confidence >= 0.4,
                "confidence sufficient",
                required=inp.severity in ("high", "critical"),
            ),
        ]

        failed_required = [check for check in checks if check.required and not check.passed]
        if not inp.scope_ok:
            status = ReportabilityStatus.OUT_OF_SCOPE
        elif inp.false_positive or inp.finding_state in ("disproved", "rejected"):
            status = ReportabilityStatus.NOT_ACTIONABLE
        elif inp.duplicate or inp.finding_state == "duplicate":
            status = ReportabilityStatus.DUPLICATE
        elif inp.finding_state == "disputed":
            status = ReportabilityStatus.DISPUTED
        elif failed_required:
            status = ReportabilityStatus.INCOMPLETE
        else:
            status = ReportabilityStatus.REPORTABLE

        reasons = [
            f"{check.name}: {'ok' if check.passed else 'missing'} - {check.detail}"
            for check in checks
            if not check.passed
        ]
        if status is ReportabilityStatus.REPORTABLE:
            reasons.append("all mandatory reportability criteria satisfied")

        return Reportability(
            finding_id=inp.finding_id,
            status=status,
            checks=tuple(checks),
            reasons=tuple(reasons),
        )


__all__ = ["ReportabilityEngine", "ReportabilityInput"]
