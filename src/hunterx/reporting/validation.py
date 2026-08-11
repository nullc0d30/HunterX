# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Safe vulnerability validation report views and builders.

Presentation-facing projection of a validation run. The builder aggregates
verdicts, hypotheses, evidence and executions into a renderer-friendly view
covering every mandated section: validation summary, confirmed/validated/
suspected vulnerabilities, false positives, inconclusive tests, scope-blocked
and safety-blocked tests, evidence inventory, validation timeline, risk
changes, remediation-relevant evidence, tool execution summary, confidence
summary and reproducibility information.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.vulnerability_validation.enums import VerdictResult
from hunterx.domain.vulnerability_validation.models import (
    ValidationEvidence,
    ValidationExecution,
    ValidationPolicyDecision,
    ValidationToolUsage,
    ValidationVerdict,
    VulnerabilityHypothesis,
)
from hunterx.shared.time import utcnow_iso

#: Verdict results reported as distinct sections.
_CONFIRMED = VerdictResult.CONFIRMED
_VALIDATED = VerdictResult.VALIDATED
_SUSPECTED = VerdictResult.SUSPECTED
_FALSE_POSITIVE = VerdictResult.FALSE_POSITIVE
_INCONCLUSIVE = VerdictResult.INCONCLUSIVE
_SCOPE_BLOCKED = VerdictResult.SCOPE_BLOCKED
_SAFETY_BLOCKED = VerdictResult.SAFETY_BLOCKED


@dataclass(frozen=True, slots=True)
class ValidationEntryView:
    """A single verdict entry in a validation report."""

    hypothesis_id: str
    vulnerability_id: str
    asset_id: str
    result: str
    confidence: float = 0.0
    reason: str = ""
    verdict_id: str = ""
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ValidationReportView:
    """The full data surface of a validation report.

    Attributes:
        report_id: stable report identifier.
        mission_id: owning mission.
        target_id: owning target.
        analysis_version: analysis version of the run.
        generated_at: UTC ISO-8601 generation timestamp.
        summary: aggregate counters.
        confirmed: confirmed-vulnerability entries.
        validated: validated-vulnerability entries.
        suspected: suspected-vulnerability entries.
        false_positives: refuted entries.
        inconclusive: inconclusive entries.
        scope_blocked: scope-blocked entries.
        safety_blocked: safety-blocked entries.
        evidence: evidence inventory.
        timeline: validation timeline entries.
        risk_changes: risk-change records.
        remediation_evidence: remediation-relevant evidence entries.
        tool_summary: tool execution summaries.
        confidence_summary: confidence distribution.
        reproducibility: reproducibility metadata.
        policies: policy decisions recorded during the run.
        metadata: free-form metadata.

    """

    report_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    analysis_version: str = "1.0.0"
    generated_at: str = ""
    summary: dict[str, int] = field(default_factory=dict)
    confirmed: tuple[ValidationEntryView, ...] = ()
    validated: tuple[ValidationEntryView, ...] = ()
    suspected: tuple[ValidationEntryView, ...] = ()
    false_positives: tuple[ValidationEntryView, ...] = ()
    inconclusive: tuple[ValidationEntryView, ...] = ()
    scope_blocked: tuple[ValidationEntryView, ...] = ()
    safety_blocked: tuple[ValidationEntryView, ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()
    timeline: tuple[dict[str, Any], ...] = ()
    risk_changes: tuple[dict[str, Any], ...] = ()
    remediation_evidence: tuple[dict[str, Any], ...] = ()
    tool_summary: tuple[dict[str, Any], ...] = ()
    confidence_summary: dict[str, Any] = field(default_factory=dict)
    reproducibility: dict[str, Any] = field(default_factory=dict)
    policies: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        import dataclasses

        def _entry(entry: ValidationEntryView) -> dict[str, Any]:
            return dataclasses.asdict(entry)

        return {
            "report_id": self.report_id,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "analysis_version": self.analysis_version,
            "generated_at": self.generated_at,
            "summary": dict(self.summary),
            "confirmed": [_entry(entry) for entry in self.confirmed],
            "validated": [_entry(entry) for entry in self.validated],
            "suspected": [_entry(entry) for entry in self.suspected],
            "false_positives": [_entry(entry) for entry in self.false_positives],
            "inconclusive": [_entry(entry) for entry in self.inconclusive],
            "scope_blocked": [_entry(entry) for entry in self.scope_blocked],
            "safety_blocked": [_entry(entry) for entry in self.safety_blocked],
            "evidence": list(self.evidence),
            "timeline": list(self.timeline),
            "risk_changes": list(self.risk_changes),
            "remediation_evidence": list(self.remediation_evidence),
            "tool_summary": list(self.tool_summary),
            "confidence_summary": dict(self.confidence_summary),
            "reproducibility": dict(self.reproducibility),
            "policies": list(self.policies),
        }

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> ValidationReportView:
        """Rebuild a view from JSON-safe report data (produced by the engine).

        Args:
            data: the report-data mapping produced by the validation engine's
                PHASE 11 reporting.

        Returns:
            A :class:`ValidationReportView`.

        """

        def _entries(key: str) -> tuple[ValidationEntryView, ...]:
            return tuple(
                ValidationEntryView(
                    hypothesis_id=str(item.get("hypothesis_id") or ""),
                    vulnerability_id=str(item.get("vulnerability_id") or ""),
                    asset_id=str(item.get("asset_id") or ""),
                    result=str(item.get("result") or "inconclusive"),
                    confidence=float(item.get("confidence") or 0.0),
                    reason=str(item.get("reason") or ""),
                    verdict_id=str(item.get("verdict_id") or ""),
                    evidence_ids=tuple(str(entry) for entry in item.get("evidence_ids") or ()),
                )
                for item in data.get(key) or ()
                if isinstance(item, dict)
            )

        summary = dict(data.get("summary") or {})
        confidence = dict(data.get("confidence_summary") or {})
        return cls(
            report_id=str(data.get("report_id") or ""),
            mission_id=str(data.get("mission_id") or ""),
            target_id=str(data.get("target_id") or ""),
            analysis_version=str(data.get("analysis_version") or "1.0.0"),
            generated_at=str(data.get("generated_at") or ""),
            summary={str(key): int(value) for key, value in summary.items()},
            confirmed=_entries("confirmed"),
            validated=_entries("validated"),
            suspected=_entries("suspected"),
            false_positives=_entries("false_positives"),
            inconclusive=_entries("inconclusive"),
            scope_blocked=_entries("scope_blocked"),
            safety_blocked=_entries("safety_blocked"),
            evidence=tuple(dict(item) for item in data.get("evidence") or () if isinstance(item, dict)),
            timeline=tuple(dict(item) for item in data.get("timeline") or () if isinstance(item, dict)),
            risk_changes=tuple(dict(item) for item in data.get("risk_changes") or () if isinstance(item, dict)),
            remediation_evidence=tuple(dict(item) for item in data.get("remediation_evidence") or () if isinstance(item, dict)),
            tool_summary=tuple(dict(item) for item in data.get("tool_summary") or () if isinstance(item, dict)),
            confidence_summary={str(key): value for key, value in confidence.items()},
            reproducibility=dict(data.get("reproducibility") or {}),
            policies=tuple(dict(item) for item in data.get("policies") or () if isinstance(item, dict)),
            metadata=dict(data.get("metadata") or {}),
        )


class ValidationReportBuilder:
    """Aggregate validation records into a :class:`ValidationReportView`.

    Example::

        builder = ValidationReportBuilder()
        view = builder.build(
            mission_id="m1", target_id="t1",
            hypotheses=[...], verdicts=[...], evidence=[...],
            executions=[...], decisions=[...], usage=[...],
            differentials=[...],
        )
    """

    def build(
        self,
        *,
        mission_id: str,
        target_id: str,
        hypotheses: list[VulnerabilityHypothesis],
        verdicts: list[ValidationVerdict],
        evidence: list[ValidationEvidence],
        executions: list[ValidationExecution],
        decisions: list[ValidationPolicyDecision] | None = None,
        usage: list[ValidationToolUsage] | None = None,
        differentials: list[Any] | None = None,
        analysis_version: str = "1.0.0",
        report_id: str = "",
    ) -> ValidationReportView:
        """Aggregate the validation records into a report view."""
        from hunterx.shared.ids import generate_id

        hypothesis_by_id = {item.hypothesis_id: item for item in hypotheses}
        grouped: dict[str, list[ValidationEntryView]] = {
            "confirmed": [],
            "validated": [],
            "suspected": [],
            "false_positives": [],
            "inconclusive": [],
            "scope_blocked": [],
            "safety_blocked": [],
        }
        for verdict in verdicts:
            entry = self._entry(verdict, hypothesis_by_id)
            if verdict.result == _CONFIRMED:
                grouped["confirmed"].append(entry)
            elif verdict.result == _VALIDATED:
                grouped["validated"].append(entry)
            elif verdict.result == _SUSPECTED:
                grouped["suspected"].append(entry)
            elif verdict.result == _FALSE_POSITIVE:
                grouped["false_positives"].append(entry)
            elif verdict.result == _INCONCLUSIVE:
                grouped["inconclusive"].append(entry)
            elif verdict.result == _SCOPE_BLOCKED:
                grouped["scope_blocked"].append(entry)
            elif verdict.result == _SAFETY_BLOCKED:
                grouped["safety_blocked"].append(entry)

        total = len(verdicts)
        summary: dict[str, int] = {
            "total_verdicts": total,
            "confirmed": len(grouped["confirmed"]),
            "validated": len(grouped["validated"]),
            "suspected": len(grouped["suspected"]),
            "false_positives": len(grouped["false_positives"]),
            "inconclusive": len(grouped["inconclusive"]),
            "scope_blocked": len(grouped["scope_blocked"]),
            "safety_blocked": len(grouped["safety_blocked"]),
            "evidence": len(evidence),
            "executions": len(executions),
        }
        evidence_inventory = tuple(_evidence_dict(item) for item in evidence)
        timeline = tuple(_execution_dict(item) for item in executions)
        tool_summary = tuple(_usage_dict(item) for item in usage or [])
        policies = tuple(_decision_dict(item) for item in decisions or [])
        confidence = self._confidence_summary(verdicts)
        return ValidationReportView(
            report_id=report_id or generate_id(),
            mission_id=mission_id,
            target_id=target_id,
            analysis_version=analysis_version,
            generated_at=utcnow_iso(),
            summary=summary,
            confirmed=tuple(grouped["confirmed"]),
            validated=tuple(grouped["validated"]),
            suspected=tuple(grouped["suspected"]),
            false_positives=tuple(grouped["false_positives"]),
            inconclusive=tuple(grouped["inconclusive"]),
            scope_blocked=tuple(grouped["scope_blocked"]),
            safety_blocked=tuple(grouped["safety_blocked"]),
            evidence=evidence_inventory,
            timeline=timeline,
            risk_changes=_risk_changes(differentials or []),
            remediation_evidence=_remediation_evidence(evidence),
            tool_summary=tool_summary,
            confidence_summary=confidence,
            reproducibility=_reproducibility(verdicts, executions),
            policies=policies,
        )

    @staticmethod
    def _entry(
        verdict: ValidationVerdict,
        hypotheses: dict[str, VulnerabilityHypothesis],
    ) -> ValidationEntryView:
        hypothesis = hypotheses.get(verdict.hypothesis_id)
        return ValidationEntryView(
            hypothesis_id=verdict.hypothesis_id,
            vulnerability_id=hypothesis.vulnerability_id if hypothesis else "",
            asset_id=verdict.asset_id,
            result=verdict.result.value,
            confidence=verdict.confidence,
            reason=verdict.reason,
            verdict_id=verdict.verdict_id,
            evidence_ids=verdict.evidence_ids,
        )

    @staticmethod
    def _confidence_summary(verdicts: list[ValidationVerdict]) -> dict[str, Any]:
        if not verdicts:
            return {"mean": 0.0, "distribution": {}}
        bands: Counter[str] = Counter()
        for verdict in verdicts:
            if verdict.confidence >= 0.9:
                bands["0.9-1.0"] += 1
            elif verdict.confidence >= 0.7:
                bands["0.7-0.9"] += 1
            elif verdict.confidence >= 0.5:
                bands["0.5-0.7"] += 1
            elif verdict.confidence > 0.0:
                bands["0.0-0.5"] += 1
            else:
                bands["0.0"] += 1
        return {
            "mean": round(sum(item.confidence for item in verdicts) / len(verdicts), 4),
            "distribution": dict(bands),
        }


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


def _execution_dict(item: ValidationExecution) -> dict[str, Any]:
    return {
        "validation_id": item.validation_id,
        "hypothesis_id": item.hypothesis_id,
        "plan_id": item.plan_id,
        "tool_id": item.tool_id,
        "status": item.status.value,
        "phase": item.phase.value,
        "started_at": item.started_at,
        "completed_at": item.completed_at,
        "duration_ms": item.duration_ms,
    }


def _usage_dict(item: ValidationToolUsage) -> dict[str, Any]:
    return {
        "tool_id": item.tool_id,
        "requests": item.requests,
        "failures": item.failures,
        "retries": item.retries,
        "rate_limited": item.rate_limited,
        "blocked": item.blocked,
        "total_duration_ms": item.total_duration_ms,
    }


def _decision_dict(item: ValidationPolicyDecision) -> dict[str, Any]:
    return {
        "decision_id": item.decision_id,
        "kind": item.kind,
        "allowed": item.allowed,
        "reason": item.reason,
        "detail": dict(item.detail),
    }


def _risk_changes(differentials: list[Any]) -> tuple[dict[str, Any], ...]:
    changes: list[dict[str, Any]] = []
    for differential in differentials:
        changes.append(
            {
                "hypothesis_id": getattr(differential, "hypothesis_id", ""),
                "vulnerability_id": getattr(differential, "vulnerability_id", ""),
                "changes": [item.value if hasattr(item, "value") else str(item) for item in differential.changes],
                "details": dict(getattr(differential, "details", {})),
            }
        )
    return tuple(changes)


def _remediation_evidence(evidence: list[ValidationEvidence]) -> tuple[dict[str, Any], ...]:
    relevant: list[dict[str, Any]] = []
    for item in evidence:
        if item.comparison.value in ("match", "partial_match"):
            relevant.append(
                {
                    "evidence_id": item.evidence_id,
                    "hypothesis_id": item.hypothesis_id,
                    "asset_id": item.asset_id,
                    "observation": item.observation.value if item.observation is not None else "",
                    "kind": item.observation.kind.value if item.observation is not None else "",
                    "expected_behavior": item.expected_behavior,
                    "observed_behavior": item.observed_behavior,
                }
            )
    return tuple(relevant)


def _reproducibility(
    verdicts: list[ValidationVerdict],
    executions: list[ValidationExecution],
) -> dict[str, Any]:
    versions = {item.analysis_version for item in verdicts}
    versions.update(item.analysis_version for item in executions)
    return {
        "analysis_versions": sorted(versions),
        "verdict_count": len(verdicts),
        "execution_count": len(executions),
        "deterministic": True,
        "reproducible": True,
    }


__all__ = ["ValidationEntryView", "ValidationReportBuilder", "ValidationReportView"]
