# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability Proof & PoC report views and builders.

Presentation-facing projection of a proof run. The builder aggregates proofs,
PoCs, evidence, replays, impact, confidence, transitions and the reproduction
package into a renderer-friendly view that answers: WHAT is vulnerable, WHERE,
WHY, HOW it was validated, WHAT evidence proves it, WHAT PoC demonstrates it,
CAN it be reproduced, WHAT impact was demonstrated, WHAT confidence exists, WHAT
tool produced the evidence, WHEN it was validated and WHAT scope authorized it.
Reports never expose secrets.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.vulnerability_proof.models import (
    ConfidenceAssessment,
    FindingStateTransition,
    ImpactAssessment,
    ProofOfConcept,
    ProofQuality,
    ProofReplay,
    ReproductionPackage,
    VulnerabilityProof,
)
from hunterx.domain.vulnerability_validation.enums import VerdictResult  # noqa: F401  (re-exported for symmetry)
from hunterx.domain.vulnerability_validation.models import ValidationEvidence, VulnerabilityHypothesis
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class ProofEntryView:
    """A single proof entry in a proof report."""

    proof_id: str
    hypothesis_id: str
    finding_id: str = ""
    asset_id: str = ""
    vulnerability_id: str = ""
    proof_type: str = ""
    proof_status: str = "candidate"
    reproducibility: str = "not_assessed"
    confidence: float = 0.0
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProofReportView:
    """The full data surface of a proof report.

    Attributes:
        report_id: stable report identifier.
        mission_id: owning mission.
        target_id: owning target.
        analysis_version: analysis version.
        generated_at: UTC ISO-8601 generation timestamp.
        summary: aggregate counters.
        proofs: proof entries.
        evidence: evidence inventory.
        pocs: PoC projections.
        replays: replay inventory.
        impact: impact assessment projections.
        confidence: confidence assessment projections.
        transitions: finding lifecycle transitions.
        quality: proof quality projections.
        package: reproduction package projection (``None`` when absent).
        metadata: free-form metadata.

    """

    report_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    analysis_version: str = "1.0.0"
    generated_at: str = ""
    summary: dict[str, int] = field(default_factory=dict)
    proofs: tuple[ProofEntryView, ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()
    pocs: tuple[dict[str, Any], ...] = ()
    replays: tuple[dict[str, Any], ...] = ()
    impact: tuple[dict[str, Any], ...] = ()
    confidence: tuple[dict[str, Any], ...] = ()
    transitions: tuple[dict[str, Any], ...] = ()
    quality: tuple[dict[str, Any], ...] = ()
    package: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        import dataclasses

        return {
            "report_id": self.report_id,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "analysis_version": self.analysis_version,
            "generated_at": self.generated_at,
            "summary": dict(self.summary),
            "proofs": [dataclasses.asdict(entry) for entry in self.proofs],
            "evidence": list(self.evidence),
            "pocs": list(self.pocs),
            "replays": list(self.replays),
            "impact": list(self.impact),
            "confidence": list(self.confidence),
            "transitions": list(self.transitions),
            "quality": list(self.quality),
            "package": dict(self.package) if self.package else None,
        }

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> ProofReportView:
        """Rebuild a view from JSON-safe report data."""

        def _proofs(key: str) -> tuple[ProofEntryView, ...]:
            return tuple(
                ProofEntryView(
                    proof_id=str(item.get("proof_id") or ""),
                    hypothesis_id=str(item.get("hypothesis_id") or ""),
                    finding_id=str(item.get("finding_id") or ""),
                    asset_id=str(item.get("asset_id") or ""),
                    vulnerability_id=str(item.get("vulnerability_id") or ""),
                    proof_type=str(item.get("proof_type") or ""),
                    proof_status=str(item.get("proof_status") or "candidate"),
                    reproducibility=str(item.get("reproducibility_status") or "not_assessed"),
                    confidence=float(item.get("confidence") or 0.0),
                    evidence_ids=tuple(str(entry) for entry in item.get("evidence_ids") or ()),
                )
                for item in data.get(key) or ()
                if isinstance(item, dict)
            )

        def _dicts(key: str) -> tuple[dict[str, Any], ...]:
            return tuple(dict(item) for item in data.get(key) or () if isinstance(item, dict))

        package = data.get("package")
        return cls(
            report_id=str(data.get("report_id") or ""),
            mission_id=str(data.get("mission_id") or ""),
            target_id=str(data.get("target_id") or ""),
            analysis_version=str(data.get("analysis_version") or "1.0.0"),
            generated_at=str(data.get("generated_at") or ""),
            summary={str(key): int(value) for key, value in dict(data.get("summary") or {}).items()},
            proofs=_proofs("proofs"),
            evidence=_dicts("evidence"),
            pocs=_dicts("pocs"),
            replays=_dicts("replays"),
            impact=_dicts("impact"),
            confidence=_dicts("confidence"),
            transitions=_dicts("transitions"),
            quality=_dicts("quality"),
            package=dict(package) if isinstance(package, dict) else None,
            metadata=dict(data.get("metadata") or {}),
        )


class ProofReportBuilder:
    """Aggregate proof records into a :class:`ProofReportView`.

    Example::

        builder = ProofReportBuilder()
        view = builder.build(
            mission_id="m1", target_id="t1",
            proofs=[...], hypothesis=hypothesis,
            evidence=[...], pocs=[...], replays=[...],
            impact=impact, confidence=confidence,
            transitions=[...], quality=quality, package=package,
        )
    """

    def build(
        self,
        *,
        mission_id: str,
        target_id: str,
        proofs: list[VulnerabilityProof],
        hypothesis: VulnerabilityHypothesis | None = None,
        evidence: list[ValidationEvidence] | None = None,
        pocs: list[ProofOfConcept] | None = None,
        replays: list[ProofReplay] | None = None,
        impact: ImpactAssessment | None = None,
        confidence: ConfidenceAssessment | None = None,
        transitions: list[FindingStateTransition] | None = None,
        quality: ProofQuality | None = None,
        package: ReproductionPackage | None = None,
        analysis_version: str = "1.0.0",
        report_id: str = "",
    ) -> ProofReportView:
        """Aggregate the proof records into a report view."""
        from hunterx.shared.ids import generate_id

        entry_views = tuple(_entry(proof) for proof in proofs)
        validated = sum(1 for proof in proofs if proof.proof_status.value == "validated")
        reproducible = sum(1 for proof in proofs if proof.reproducibility_status.value == "reproducible")
        summary: dict[str, int] = {
            "proofs": len(proofs),
            "validated": validated,
            "reproducible": reproducible,
            "evidence": len(evidence or []),
            "replays": len(replays or []),
            "impact": 1 if impact is not None else 0,
            "confidence": 1 if confidence is not None else 0,
            "transitions": len(transitions or []),
            "report_ready": sum(1 for item in (transitions or []) if item.to_state.value == "report_ready"),
        }
        hypothesis_id = hypothesis.hypothesis_id if hypothesis else ""
        evidence_dicts = tuple(_evidence_dict(item) for item in evidence or [])
        poc_dicts = tuple(item.to_dict() for item in pocs or [])
        replay_dicts = tuple(_replay_dict(item) for item in replays or [])
        return ProofReportView(
            report_id=report_id or generate_id(),
            mission_id=mission_id,
            target_id=target_id,
            analysis_version=analysis_version,
            generated_at=utcnow_iso(),
            summary=summary,
            proofs=entry_views,
            evidence=evidence_dicts,
            pocs=poc_dicts,
            replays=replay_dicts,
            impact=(impact.to_dict(),) if impact is not None else (),
            confidence=(confidence.to_dict(),) if confidence is not None else (),
            transitions=tuple(item.to_dict() for item in transitions or []),
            quality=(quality.to_dict(),) if quality is not None else (),
            package=package.to_dict() if package is not None else None,
            metadata={"hypothesis_id": hypothesis_id},
        )


def _entry(proof: VulnerabilityProof) -> ProofEntryView:
    return ProofEntryView(
        proof_id=proof.proof_id,
        hypothesis_id=proof.hypothesis_id,
        finding_id=proof.finding_id,
        asset_id=proof.asset_id,
        vulnerability_id=proof.vulnerability_id,
        proof_type=proof.proof_type.value,
        proof_status=proof.proof_status.value,
        reproducibility=proof.reproducibility_status.value,
        confidence=proof.confidence,
        evidence_ids=proof.evidence_ids,
    )


def _evidence_dict(item: ValidationEvidence) -> dict[str, Any]:
    observation = item.observation.to_dict() if item.observation is not None else None
    return {
        "evidence_id": item.evidence_id,
        "validation_id": item.validation_id,
        "hypothesis_id": item.hypothesis_id,
        "asset_id": item.asset_id,
        "tool_id": item.tool_id,
        "tool_version": item.tool_version,
        "timestamp": item.timestamp,
        "input_hash": item.input_hash,
        "output_hash": item.output_hash,
        "observation": observation,
        "comparison": item.comparison.value,
        "confidence": item.confidence,
    }


def _replay_dict(item: ProofReplay) -> dict[str, Any]:
    return {
        "replay_id": item.replay_id,
        "proof_id": item.proof_id,
        "poc_id": item.poc_id,
        "poc_version": item.poc_version,
        "tool_id": item.tool_id,
        "tool_version": item.tool_version,
        "input_hash": item.input_hash,
        "evidence_hash": item.evidence_hash,
        "result": item.result.value,
        "verdict": item.verdict.value,
        "timestamp": item.timestamp,
    }


__all__ = ["ProofEntryView", "ProofReportBuilder", "ProofReportView"]
