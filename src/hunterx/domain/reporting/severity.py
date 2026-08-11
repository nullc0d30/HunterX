# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Evidence-backed severity assessment engine.

Severity is never derived from the vulnerability class alone: it is derived
from evidence-backed impact dimensions, exploitability signals, proof state,
confidence, scope and business context. ``Critical`` requires direct evidence
of high-impact, exploitable impact — a class name alone can never produce it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.reporting.models import AssetCriticality, SeverityAssessment

#: Numeric contribution per impact level for a single dimension.
_LEVEL_SCORE = {"none": 0.0, "low": 0.25, "medium": 0.5, "high": 1.0}

#: Impact dimensions with the strongest weight on severity.
_IMPACT_KEYS = (
    "confidentiality",
    "integrity",
    "availability",
    "authorization_boundary",
    "privilege_boundary",
    "remote_execution",
    "account_takeover",
    "data_exposure",
    "credential_exposure",
    "cloud_resource_access",
    "business_impact",
)

#: Severity bands for the composite impact score in ``[0, 10]``.
def _band(score: float) -> tuple[str, float]:
    """Map a composite score to a (severity, risk_score) pair."""
    if score >= 9.0:
        return ("critical", score)
    if score >= 7.0:
        return ("high", score)
    if score >= 4.0:
        return ("medium", score)
    if score > 1.0:
        return ("low", score)
    return ("informational", score)


def _impact_base(levels: dict[str, str]) -> tuple[float, tuple[str, ...]]:
    """Compute a calibrated base impact score from per-dimension levels.

    A single ``high`` dimension yields ``high`` severity; multiple ``high``
    dimensions (or high plus remote execution) yield ``critical``. The
    vulnerability class alone never drives the score.
    """
    high_dims = [key for key, level in levels.items() if _LEVEL_SCORE.get(level) == 1.0]
    medium_dims = [key for key, level in levels.items() if _LEVEL_SCORE.get(level) == 0.5]
    low_dims = [key for key, level in levels.items() if _LEVEL_SCORE.get(level) == 0.25]
    remote_execution = any(key == "remote_execution" for key in high_dims)
    high_count = len(high_dims)
    if high_count >= 3 or (high_count >= 2 and remote_execution):
        return (9.2, tuple(high_dims))
    if high_count == 2:
        return (9.0, tuple(high_dims))
    if high_count == 1:
        return (7.5, tuple(high_dims))
    if medium_dims:
        return (4.5, tuple(medium_dims))
    if low_dims:
        return (2.0, tuple(low_dims))
    return (0.0, ())


@dataclass(frozen=True, slots=True)
class SeverityInput:
    """Inputs for the severity assessment engine.

    Attributes:
        finding_id: owning finding.
        vulnerability_class: canonical class.
        impact_dimensions: per-dimension impact level (none/low/medium/high).
        confidence: evidence-driven confidence in ``[0, 1]``.
        proof_replayed: whether the proof PoC was replayed successfully.
        exploitability_evidence: whether direct exploitability evidence exists.
        scope: scope classification.
        disputed: whether the finding has an unresolved evidence conflict.
        asset_criticality: asset criticality context.
        business_context: business-context boosts (dict of signals).
        cvss_severity: optional CVSS severity band as a cross-check.

    """

    finding_id: str = ""
    vulnerability_class: str = "unknown_behavior"
    impact_dimensions: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0
    proof_replayed: bool = False
    exploitability_evidence: bool = False
    scope: str = "in_scope"
    disputed: bool = False
    asset_criticality: AssetCriticality = field(default_factory=AssetCriticality)
    business_context: dict[str, str] = field(default_factory=dict)
    cvss_severity: str | None = None


class SeverityAssessmentEngine:
    """Deterministic severity engine.

    The engine computes a composite impact score from the evidence-backed
    impact dimensions, applies a confidence cap (low-confidence findings can
    never reach ``critical`` without a replayed proof), then applies asset
    criticality and business-context adjustments. Every adjustment is recorded
    as an explainable reasoning line.
    """

    def assess(self, inp: SeverityInput) -> SeverityAssessment:
        """Assess severity for ``inp``.

        Returns:
            An explainable :class:`SeverityAssessment`.

        """
        reasoning: list[str] = []
        evidence_refs: set[str] = set()

        if inp.scope not in ("in_scope", "authorized"):
            return SeverityAssessment(
                finding_id=inp.finding_id,
                severity="informational",
                risk_score=0.0,
                reasoning=("finding is out of scope; severity not assessable",),
                evidence_backed=True,
            )

        if inp.disputed:
            return SeverityAssessment(
                finding_id=inp.finding_id,
                severity="informational",
                risk_score=0.0,
                reasoning=("finding has an unresolved evidence conflict; severity not asserted",),
                evidence_backed=False,
            )

        if not inp.impact_dimensions:
            reasoning.append("no impact dimensions provided; severity stays informational")
            return SeverityAssessment(
                finding_id=inp.finding_id,
                severity="informational",
                risk_score=0.0,
                reasoning=tuple(reasoning),
                evidence_backed=False,
            )

        scored = 0.0
        weights = 0.0
        levels: dict[str, str] = {}
        for key in _IMPACT_KEYS:
            level = inp.impact_dimensions.get(key)
            if not level:
                continue
            levels[key] = level
            scored += _LEVEL_SCORE.get(level, 0.0)
            weights += 1.0
            if _LEVEL_SCORE.get(level, 0.0) > 0.0:
                reasoning.append(f"impact dimension '{key}' assessed {level}")
        impact_score, high_dims = _impact_base(levels)
        if impact_score == 0.0:
            reasoning.append("no impact dimensions above low; severity stays informational/low")
        else:
            reasoning.append(f"impact base from {len(high_dims)} high-impact dimension(s): {', '.join(high_dims) if high_dims else 'medium/low'}")

        # Proof/exploitability uplift is only applied when direct evidence exists.
        if inp.proof_replayed:
            impact_score = min(10.0, impact_score + 0.5)
            reasoning.append("replayed proof raises severity confidence")
        if inp.exploitability_evidence:
            impact_score = min(10.0, impact_score + 0.3)
            reasoning.append("direct exploitability evidence present")

        # Confidence cap: a finding with no validated proof and confidence below
        # 0.9 can never reach high severity no matter how strong the asset or
        # business boosts are.
        confidence_ceiling = 10.0
        if not inp.proof_replayed and inp.confidence < 0.9:
            confidence_ceiling = 8.9
            reasoning.append("confidence below 0.9 without a replayed proof caps severity below high")

        # Asset criticality adjustment.
        if inp.asset_criticality.criticality_level() >= 3:
            impact_score = min(confidence_ceiling, impact_score + 0.4)
            reasoning.append("asset criticality is critical; severity adjusted up")
            evidence_refs.add("asset_criticality")
        elif inp.asset_criticality.criticality_level() >= 2:
            impact_score = min(confidence_ceiling, impact_score + 0.2)
            reasoning.append("asset criticality is high; severity adjusted up")

        if inp.asset_criticality.internet_exposure:
            impact_score = min(confidence_ceiling, impact_score + 0.2)
            reasoning.append("internet-exposed asset; severity adjusted up")

        # Business context adjustment.
        for signal, level in inp.business_context.items():
            impact_score = min(confidence_ceiling, impact_score + _LEVEL_SCORE.get(level, 0.0) * 0.4)
            reasoning.append(f"business context signal '{signal}' assessed {level}")

        # CVSS cross-check: never raise severity above what CVSS supports.
        if inp.cvss_severity:
            cvss_cap = {"none": 0.0, "low": 3.9, "medium": 6.9, "high": 8.9, "critical": 10.0}.get(
                inp.cvss_severity, 10.0
            )
            if impact_score > cvss_cap:
                reasoning.append(
                    f"CVSS severity '{inp.cvss_severity}' caps the severity below the impact-driven estimate"
                )
                impact_score = cvss_cap

        severity, risk_score = _band(round(impact_score * 10.0) / 10.0)

        evidence_backed = inp.proof_replayed or inp.exploitability_evidence or bool(inp.impact_dimensions)
        reasoning.append(f"final severity {severity} with risk score {risk_score}")
        return SeverityAssessment(
            finding_id=inp.finding_id,
            severity=severity,
            risk_score=risk_score,
            reasoning=tuple(reasoning),
            evidence_refs=tuple(sorted(evidence_refs)),
            evidence_backed=evidence_backed,
        )


__all__ = ["SeverityAssessmentEngine", "SeverityInput"]
