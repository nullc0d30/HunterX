# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability finding orchestration TIDB entities.

System-of-record entities for the Sprint 028 autonomous vulnerability
validation & proof orchestration capability: the canonical finding record,
evidence requirements and gaps, validation attempts, PoC artifacts and replay
records, impact and confidence assessments, evidence conflicts, deduplication
decisions, root-cause records, unknown-behavior profiles, reproduction data,
report-readiness checklists, state transitions and consolidated report
packages.

Security boundary: these tables store canonical findings, redacted evidence
and lifecycle metadata only — never exploit payloads, never credentials,
never out-of-scope request material.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class FindingRecord(TidbEntity):
    """Canonical orchestrated finding projection.

    Attributes:
        finding_id: canonical finding identifier (envelope ``id`` aliases it).
        mission_id / target_id / asset_id: scoping identifiers.
        vulnerability_class: canonical vulnerability class.
        title / description / severity: finding summary fields.
        confidence: evidence-driven confidence in ``[0, 1]``.
        status: canonical lifecycle status.
        affected_assets / affected_endpoints / affected_parameters: affected
            surface.
        observations: canonical normalized observations.
        evidence_refs / validation_refs / proof_refs / impact_refs /
        reproduction_refs: lifecycle reference lists.
        scope: scope context (JSON-safe).
        provenance: provenance of the finding.
        analysis_version: analysis version.

    """

    finding_id: str
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    vulnerability_class: str = "unknown_behavior"
    title: str = ""
    description: str = ""
    severity: str = "info"
    confidence: float = 0.0
    status: str = "candidate"
    affected_assets: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    affected_parameters: list[str] = field(default_factory=list)
    observations: list[dict[str, object]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    validation_refs: list[str] = field(default_factory=list)
    proof_refs: list[str] = field(default_factory=list)
    impact_refs: list[str] = field(default_factory=list)
    reproduction_refs: list[str] = field(default_factory=list)
    scope: dict[str, object] = field(default_factory=dict)
    provenance: str = ""
    analysis_version: str = "1.0.0"


@dataclass(slots=True)
class FindingEvidenceRequirement(TidbEntity):
    """Persisted evidence requirement + sufficiency snapshot for a finding.

    Attributes:
        finding_id: owning finding.
        purpose: evidence purpose.
        required_kinds: evidence kinds required for the purpose.
        present_kinds: evidence kinds present.
        missing_kinds: evidence kinds missing.
        contradictory_kinds: evidence kinds contradicting the hypothesis.
        sufficiency: evidence sufficiency level.
        assessed_at: UTC ISO-8601 assessment timestamp.

    """

    finding_id: str
    purpose: str = "validation"
    required_kinds: list[str] = field(default_factory=list)
    present_kinds: list[str] = field(default_factory=list)
    missing_kinds: list[str] = field(default_factory=list)
    contradictory_kinds: list[str] = field(default_factory=list)
    sufficiency: str = "insufficient"
    assessed_at: str = ""


@dataclass(slots=True)
class FindingEvidenceGap(TidbEntity):
    """A persisted evidence gap for a finding.

    Attributes:
        finding_id: owning finding.
        purpose: purpose the gap blocks.
        requirement_kind: gapped evidence kind.
        gap_kind: missing/contradictory/insufficient/stale/not-authorized.
        description: explainable gap description.
        resolved: whether the gap was resolved.

    """

    finding_id: str
    purpose: str = "validation"
    requirement_kind: str = "behavioral_differential"
    gap_kind: str = "missing"
    description: str = ""
    resolved: bool = False


@dataclass(slots=True)
class FindingValidationAttempt(TidbEntity):
    """A persisted validation attempt for a finding.

    Attributes:
        validation_id: validation identifier.
        finding_id: owning finding.
        plan_id / strategy_id: planning references.
        tool_id: tool executed.
        status: execution status.
        verdict: evidence-correlation verdict.
        reason: explainable result reason.
        observations: normalized observations.
        evidence_ids: evidence fragments captured.
        raw_output_hash: hash of the raw tool output.
        duration_ms: elapsed milliseconds.
        correlation_id: correlation identifier.
        executed_at: UTC ISO-8601 completion timestamp.

    """

    validation_id: str
    finding_id: str
    plan_id: str = ""
    strategy_id: str = ""
    tool_id: str = ""
    status: str = "pending"
    verdict: str = ""
    reason: str = ""
    observations: list[dict[str, object]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    raw_output_hash: str = ""
    duration_ms: int = 0
    correlation_id: str = ""
    executed_at: str = ""


@dataclass(slots=True)
class FindingPoC(TidbEntity):
    """A persisted PoC artifact.

    Attributes:
        poc_id: PoC identifier (envelope ``id`` aliases it).
        finding_id: owning finding.
        format: PoC representation format.
        content: sanitized PoC content.
        lifecycle_state: PoC lifecycle state.
        content_hash: SHA-256 content hash.
        redacted: whether the PoC has been redacted.
        deterministic / scope_bound / minimal: PoC quality flags.
        created_at: UTC ISO-8601 creation timestamp.

    """

    poc_id: str
    finding_id: str
    format: str = "http_request"
    content: str = ""
    lifecycle_state: str = "generated"
    content_hash: str = ""
    redacted: bool = True
    deterministic: bool = True
    scope_bound: bool = True
    minimal: bool = True


@dataclass(slots=True)
class FindingReplayRecord(TidbEntity):
    """A persisted controlled proof replay.

    Attributes:
        replay_id: replay identifier.
        poc_id: replayed PoC.
        finding_id: owning finding.
        target: target the replay ran against.
        scope_verified / hypothesis_verified: condition checks.
        input_hash: hash of the replayed input.
        behavior: observed security behavior.
        evidence_class: evidence class produced.
        verdict: replay verdict.
        duration_ms: elapsed milliseconds.
        captured_evidence_id: evidence captured by the replay.
        replayed_at: UTC ISO-8601 replay timestamp.

    """

    replay_id: str
    poc_id: str
    finding_id: str
    target: str = ""
    scope_verified: bool = False
    hypothesis_verified: bool = False
    input_hash: str = ""
    behavior: str = ""
    evidence_class: str = ""
    verdict: str = "not_reproducible"
    duration_ms: int = 0
    captured_evidence_id: str = ""
    replayed_at: str = ""


@dataclass(slots=True)
class FindingImpactAssessment(TidbEntity):
    """A persisted evidence-backed impact assessment.

    Attributes:
        assessment_id: assessment identifier.
        finding_id: owning finding.
        dimensions: per-dimension impact level.
        evidence_refs: evidence identifiers per dimension.
        reasoning: explainable reasoning.
        assessed_at: UTC ISO-8601 assessment timestamp.

    """

    assessment_id: str
    finding_id: str
    dimensions: dict[str, str] = field(default_factory=dict)
    evidence_refs: dict[str, list[str]] = field(default_factory=dict)
    reasoning: list[str] = field(default_factory=list)
    assessed_at: str = ""


@dataclass(slots=True)
class FindingConfidenceAssessment(TidbEntity):
    """A persisted evidence-driven confidence assessment.

    Attributes:
        assessment_id: assessment identifier.
        finding_id: owning finding.
        score: composite score in ``[0, 1]``.
        level: confidence level band.
        factors: per-factor scores and weights.
        policy_version: confidence policy version.
        calculated_at: UTC ISO-8601 calculation timestamp.

    """

    assessment_id: str
    finding_id: str
    score: float = 0.0
    level: str = "low"
    factors: list[dict[str, object]] = field(default_factory=list)
    policy_version: str = "1.0.0"
    calculated_at: str = ""


@dataclass(slots=True)
class FindingConflict(TidbEntity):
    """A persisted evidence conflict.

    Attributes:
        conflict_id: conflict identifier.
        finding_id: owning finding.
        evidence_a / evidence_b: conflicting evidence fragments.
        kind: conflict kind.
        description: explainable description.
        status: open/resolved/disputed.
        resolution: resolution steps applied.
        resolution_reason: explainable resolution.
        observed_at: UTC ISO-8601 observation timestamp.

    """

    conflict_id: str
    finding_id: str
    evidence_a: dict[str, object] | None = None
    evidence_b: dict[str, object] | None = None
    kind: str = "contradictory_evidence"
    description: str = ""
    status: str = "open"
    resolution: list[str] = field(default_factory=list)
    resolution_reason: str = ""
    observed_at: str = ""


@dataclass(slots=True)
class FindingDedupDecision(TidbEntity):
    """A persisted deduplication decision.

    Attributes:
        decision_id: decision identifier.
        finding_id: candidate finding.
        matched_finding_id: matched existing finding (``""`` when independent).
        relation: duplicate relation.
        key: canonical correlation key.
        reasons: explainable reasons.
        decided_at: UTC ISO-8601 decision timestamp.

    """

    decision_id: str
    finding_id: str
    matched_finding_id: str = ""
    relation: str = "independent_finding"
    key: str = ""
    reasons: list[str] = field(default_factory=list)
    decided_at: str = ""


@dataclass(slots=True)
class FindingRootCause(TidbEntity):
    """A persisted root-cause correlation record.

    Attributes:
        root_cause_id: root-cause identifier.
        mission_id: owning mission.
        related_finding_ids: findings deriving from the condition.
        affected_assets: affected asset identifiers.
        description: condition description.
        evidence_ids: supporting evidence.
        created_at: UTC ISO-8601 creation timestamp.

    """

    root_cause_id: str
    mission_id: str = ""
    related_finding_ids: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    description: str = ""
    evidence_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FindingUnknownBehavior(TidbEntity):
    """A persisted unknown-behavior characterization.

    Attributes:
        profile_id: profile identifier.
        finding_id: owning finding.
        observations: captured unknown observations.
        hypotheses: generated hypotheses.
        classification: final classification.
        security_relevance: whether the behavior is security-relevant.
        evidence_ids: supporting evidence.
        classification_reason: explainable classification.
        created_at: UTC ISO-8601 creation timestamp.

    """

    profile_id: str
    finding_id: str
    observations: list[dict[str, object]] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    classification: str = "unresolved"
    security_relevance: bool = False
    evidence_ids: list[str] = field(default_factory=list)
    classification_reason: str = ""


@dataclass(slots=True)
class FindingReproduction(TidbEntity):
    """A persisted redacted reproduction record.

    Attributes:
        reproduction_id: reproduction identifier.
        finding_id: owning finding.
        request / method: request line.
        headers / cookies / parameters: redacted request data.
        payload_reference: reference to the payload used.
        environment: target environment fingerprint.
        response_characteristics / timing: observed behavior.
        callback_evidence: controlled callback evidence.
        expected_result / actual_result: behavior comparison.
        redacted: whether secrets were redacted.
        created_at: UTC ISO-8601 creation timestamp.

    """

    reproduction_id: str
    finding_id: str
    request: str = ""
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    parameters: dict[str, str] = field(default_factory=dict)
    payload_reference: str = ""
    environment: str = ""
    response_characteristics: str = ""
    timing: str = ""
    callback_evidence: str = ""
    expected_result: str = ""
    actual_result: str = ""
    redacted: bool = True


@dataclass(slots=True)
class FindingReportChecklist(TidbEntity):
    """A persisted report-readiness checklist.

    Attributes:
        finding_id: owning finding.
        checks: checklist items.
        complete: whether every mandatory check passes.
        reportable: whether the finding may become ``REPORT_READY``.
        assessed_at: UTC ISO-8601 assessment timestamp.

    """

    finding_id: str
    checks: list[dict[str, object]] = field(default_factory=list)
    complete: bool = False
    reportable: bool = False
    assessed_at: str = ""


@dataclass(slots=True)
class FindingStateTransition(TidbEntity):
    """A persisted finding lifecycle transition.

    Attributes:
        transition_id: transition identifier.
        finding_id: owning finding.
        from_state / to_state: lifecycle states.
        allowed: whether the transition was granted.
        missing_purposes: evidence purposes that blocked the transition.
        reason: explainable reason.
        transitioned_at: UTC ISO-8601 transition timestamp.

    """

    transition_id: str
    finding_id: str
    from_state: str = ""
    to_state: str = ""
    allowed: bool = False
    missing_purposes: list[str] = field(default_factory=list)
    reason: str = ""
    transitioned_at: str = ""


@dataclass(slots=True)
class FindingPackageRecord(TidbEntity):
    """A persisted consolidated report package.

    Attributes:
        package_id: package identifier.
        finding_id: owning finding.
        finding_state: final finding state.
        package_json: JSON-safe package payload (redacted).
        checklist_id: report-readiness checklist identifier.
        created_at: UTC ISO-8601 package timestamp.

    """

    package_id: str
    finding_id: str
    finding_state: str = "candidate"
    package_json: dict[str, object] = field(default_factory=dict)
    checklist_id: str = ""
