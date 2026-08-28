# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal capability-finding pipeline (Phase 6).

Bridges the capability-execution engine (Phase 5) into the existing HunterX
validated-finding lifecycle: every differential-supported ``FINDING`` becomes
a candidate that is promoted, deduplicated, re-verified, replayed in
isolation, classified for reproduction, impact-assessed, turned into a PoC,
severity-scored, remediated and — only when reproduction + impact + PoC +
verification all pass — finalized as ``REPORT_READY``.

The pipeline drives the canonical :class:`VulnerabilityFindingService`; it
never fabricates findings, never marks a contradicted or non-reproducible
candidate as valid, and never auto-assigns ``CRITICAL``.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.capability_finding.lifecycle import ReproductionClassifier, stage_for_state
from hunterx.domain.capability_finding.models import CapabilityCandidate
from hunterx.domain.capability_finding.remediation import RemediationGuide
from hunterx.domain.capability_finding.replay import ReplayEngine
from hunterx.domain.capability_finding.severity import EvidenceSeverityEngine
from hunterx.domain.vulnerability_finding.enums import DuplicateRelation, FindingVulnerabilityClass

_REPORTABLE_VERDICTS = ("report_ready",)


def _class_from_capability(capability_id: str) -> FindingVulnerabilityClass:
    """Coerce a capability id (``sql-injection``) into a canonical class."""
    try:
        return FindingVulnerabilityClass(str(capability_id or "").replace("-", "_"))
    except ValueError:
        return FindingVulnerabilityClass.UNKNOWN_BEHAVIOR


def _cookie_headers(cookie: str) -> tuple[tuple[str, str], ...]:
    """Return the probe headers carrying an established session cookie."""
    return (("Cookie", cookie),) if cookie else ()


class CapabilityFindingPipeline:
    """Drive candidates from capability execution through the finding lifecycle."""

    def __init__(
        self,
        service: Any,
        *,
        replay_engine: ReplayEngine | None = None,
        severity_engine: EvidenceSeverityEngine | None = None,
        remediation_guide: RemediationGuide | None = None,
        classifier: ReproductionClassifier | None = None,
    ) -> None:
        self.service = service
        self._replay = replay_engine or ReplayEngine()
        self._severity = severity_engine or EvidenceSeverityEngine()
        self._remediation = remediation_guide or RemediationGuide()
        self._classifier = classifier or ReproductionClassifier()
        self.promoted: dict[str, str] = {}

    # -- candidate seeding ----------------------------------------------------

    def candidates_from(self, execution_engine: Any) -> list[CapabilityCandidate]:
        """Return a candidate for every capability-execution ``FINDING``."""
        candidates: list[CapabilityCandidate] = []
        for record in list(getattr(execution_engine, "records", ()) or ()):
            if record.outcome is not CapabilityExecutionStatus.FINDING:
                continue
            if not record.endpoint:
                continue
            candidates.append(CapabilityCandidate.from_capability_record(record))
        return candidates

    # -- promotion ------------------------------------------------------------

    def promote(self, candidate: CapabilityCandidate) -> str:
        """Create the canonical finding (CANDIDATE) from the candidate."""
        severity, reasons = self._severity.calculate(candidate)
        remediation = self._remediation.guide(candidate)
        record = self.service.create_finding(
            mission_id=candidate.mission_id,
            target_id=candidate.surface_key,
            vulnerability_class=candidate.finding_class,
            title=f"{candidate.finding_class.replace('_', ' ')} detected on {candidate.endpoint}",
            description=(
                f"Differential capability finding '{candidate.capability_id}' on "
                f"{candidate.endpoint} (vector {candidate.vector or 'n/a'}, "
                f"session {candidate.session_state}). Retained evidence: "
                f"{len(candidate.response_summaries)} responses across "
                f"{len(candidate.request_summaries)} requests."
            ),
            severity=severity,
            tool="hunterx-capability",
            asset_id=candidate.surface_key,
            asset=candidate.surface_key,
            endpoints=(candidate.endpoint,),
            parameters=(candidate.vector,) if candidate.vector else (),
            observations=[
                {
                    "kind": "detection_signature",
                    "value": (
                        f"capability '{candidate.capability_id}' observed a "
                        f"{candidate.evidence.get('signal') or 'differential'} "
                        f"signal on {candidate.endpoint}"
                    ),
                    "quality": "medium",
                    "source": "capability-execution",
                    "provenance": {
                        "candidate_id": candidate.candidate_id,
                        "capability_id": candidate.capability_id,
                        "strategies": list(candidate.strategies),
                        "evidence": dict(candidate.evidence),
                    },
                }
            ],
            scope={
                "surface_key": candidate.surface_key,
                "session_state": candidate.session_state,
                "strategies": list(candidate.strategies),
                "tools": list(candidate.tools),
                "vector": candidate.vector,
                "request_summaries": [dict(item) for item in candidate.request_summaries],
                "response_summaries": [dict(item) for item in candidate.response_summaries],
                "severity": severity,
                "severity_reasons": list(reasons),
                "remediation": remediation.to_dict(),
            },
            provenance=f"capability-execution:{candidate.capability_id}",
        )
        finding_id = str(record.get("finding_id") or record.get("id") or "")
        self.promoted[finding_id] = candidate.candidate_id
        return finding_id

    # -- lifecycle ------------------------------------------------------------

    def run(self, candidate: CapabilityCandidate) -> dict[str, Any]:
        """Run the full candidate lifecycle; return the outcome + evidence."""
        outcome: dict[str, Any] = {
            "candidate_id": candidate.candidate_id,
            "finding_class": candidate.finding_class,
            "endpoint": candidate.endpoint,
            "vector": candidate.vector,
            "session_state": candidate.session_state,
            "stages": [],
        }

        def stage(name: str, payload: dict[str, Any]) -> None:
            outcome["stages"].append({"stage": stage_for_state(name), **payload})

        try:
            finding_id = self.promote(candidate)
        except Exception as exc:  # noqa: BLE001 - bounded lifecycle failure
            outcome["verdict"] = "failed"
            outcome["reason"] = f"promotion failed: {exc}"
            return outcome
        outcome["finding_id"] = finding_id
        stage("candidate", {"finding_id": finding_id, "finding_class": candidate.finding_class})
        severity, severity_reasons = self._severity.calculate(candidate)
        remediation = self._remediation.guide(candidate)
        outcome["severity"] = severity
        outcome["severity_reasons"] = list(severity_reasons)
        outcome["remediation"] = remediation.to_dict()

        dedup = self.service.deduplicate_finding(finding_id)
        stage("evidence_collected", {"finding_id": finding_id})
        if dedup.get("relation") not in (None, DuplicateRelation.INDEPENDENT_FINDING.value):
            stage("rejected", {"reason": f"duplicate of {dedup.get('matched_finding_id')}", "relation": dedup.get("relation")})
            outcome["verdict"] = "duplicate"
            outcome["duplicate_of"] = dedup.get("matched_finding_id")
            return outcome

        verify = self.service.verify_with_probe(finding_id, probe_headers=_cookie_headers(self._replay.cookie))
        if verify.get("status") in ("blocked", "contradicted"):
            stage("rejected", {"reason": verify.get("reason") or verify.get("status"), "verification": verify.get("verdict")})
            outcome["verdict"] = "contradicted"
            outcome["reason"] = verify.get("reason") or "verification did not reconfirm the differential"
            return outcome
        stage("replaying", {"verification": verify.get("status")})

        attempts = self._replay.replay(candidate)
        reproduction = self._classifier.classify(attempts)
        candidate = dataclasses.replace(candidate, replay_attempts=attempts, reproduction=reproduction)
        outcome["reproduction"] = reproduction.value
        outcome["replay_attempts"] = [attempt.to_dict() for attempt in attempts]
        if reproduction.value == "not_reproducible":
            self.service.reject_finding(finding_id, reason="isolated replay could not reproduce the differential signal", state="disproved")
            stage("rejected", {"reason": "isolated replay could not reproduce the signal"})
            outcome["verdict"] = "not_reproducible"
            return outcome
        stage("reproduced", {"reproduction": reproduction.value})

        impact = self.service.assess_impact(finding_id)
        stage("impact_assessed", {"impact": impact})
        outcome["impact"] = impact

        poc = self.service.generate_reproduction_and_poc(finding_id)
        stage("poc_generated", {"pocs": poc.get("pocs") or poc.get("poc") or poc})
        outcome["poc"] = poc

        replay = self.service.replay_probe(finding_id, probe_headers=_cookie_headers(self._replay.cookie))
        if replay.get("status") == "not_reproduced":
            stage("rejected", {"reason": replay.get("reason")})
            outcome["verdict"] = "not_reproduced"
            outcome["reason"] = replay.get("reason")
            return outcome
        stage("validated", {"replay": replay.get("status")})
        outcome["replay"] = replay

        confidence = self.service.calculate_confidence(finding_id)
        final = self.service.finalize_report_ready(finding_id)
        package = self.service.get_finding_package(finding_id)
        stage("report_ready", {"confidence": confidence.get("score"), "final": final.get("finding_id")})
        outcome["verdict"] = "report_ready"
        outcome["confidence"] = confidence
        outcome["final"] = final
        outcome["package"] = package
        return outcome

    def run_all(self, execution_engine: Any) -> dict[str, Any]:
        """Promote + run every candidate; return the mission summary."""
        candidates = self.candidates_from(execution_engine)
        outcomes = [self.run(candidate) for candidate in candidates]
        reportable = [item for item in outcomes if item.get("verdict") in _REPORTABLE_VERDICTS]
        return {
            "candidates": len(candidates),
            "reportable": len(reportable),
            "outcomes": outcomes,
            "findings": [item.get("package") for item in reportable],
        }


__all__ = ["CapabilityFindingPipeline"]
