# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability Proof & PoC TIDB entities.

System-of-record entities for the Wave 15 vulnerability proof & PoC capability:
vulnerability proofs, proof contracts, proof plans and steps, proof executions,
structured PoCs, replays, proof-linked evidence, proof policy decisions, impact
assessments, confidence assessments, proof quality, finding lifecycle
transitions and temporal proof history. Every proof fact that matters is
persisted here — never only in memory, logs or reports.

Security boundary: these tables store safe-proof metadata, canonical observations
and redacted evidence only — never exploit payloads, never credentials, never
unrestricted executable PoC scripts and never out-of-scope request material.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class VulnerabilityProof(TidbEntity):
    """A persisted vulnerability proof."""

    proof_id: str
    finding_id: str = ""
    hypothesis_id: str = ""
    validation_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    vulnerability_id: str = ""
    proof_type: str = "behavioral_proof"
    proof_strategy: str = ""
    proof_status: str = "candidate"
    reproducibility_status: str = "not_assessed"
    safety_class: str = "controlled"
    scope: dict[str, object] = field(default_factory=dict)
    preconditions: list[str] = field(default_factory=list)
    steps: list[dict[str, object]] = field(default_factory=list)
    inputs: dict[str, object] = field(default_factory=dict)
    expected_behavior: str = ""
    observed_behavior: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    impact_evidence_ids: list[str] = field(default_factory=list)
    replay_count: int = 0
    successful_replays: int = 0
    failed_replays: int = 0
    confidence: float = 0.0
    validated_at: str | None = None
    analysis_version: str = "1.0.0"
    proof_version: str = "1.0.0"
    provenance: dict[str, object] = field(default_factory=dict)
    created_by: str = "vulnerability.proof"


@dataclass(slots=True)
class ProofContract(TidbEntity):
    """A persisted proof contract."""

    contract_id: str
    vulnerability_class: str = "sql_injection"
    proof_types: list[str] = field(default_factory=list)
    poc_formats: list[str] = field(default_factory=list)
    required_preconditions: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    expected_result: str = ""
    failure_conditions: list[str] = field(default_factory=list)
    inconclusive_conditions: list[str] = field(default_factory=list)
    replay_requirements: dict[str, object] = field(default_factory=dict)
    impact_requirements: list[str] = field(default_factory=list)
    minimum_confidence: float = 0.6
    safety_class: str = "controlled"
    scope_requirements: list[str] = field(default_factory=list)
    permits_confirmation: bool = False
    reportable: bool = True
    contract_version: str = "1.0.0"


@dataclass(slots=True)
class ProofPlan(TidbEntity):
    """A persisted proof plan."""

    proof_plan_id: str
    proof_id: str = ""
    finding_id: str = ""
    hypothesis_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    vulnerability_id: str = ""
    preconditions: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    scope: dict[str, object] = field(default_factory=dict)
    safety_policy: str = "default"
    expected_observations: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    abort_conditions: list[str] = field(default_factory=list)
    replay_requirements: dict[str, object] = field(default_factory=dict)
    impact_requirements: list[str] = field(default_factory=list)
    status: str = "pending"


@dataclass(slots=True)
class ProofStep(TidbEntity):
    """A persisted proof step."""

    step_id: str
    plan_id: str = ""
    proof_id: str = ""
    order: int = 0
    action: str = ""
    tool_id: str = ""
    parameters: dict[str, object] = field(default_factory=dict)
    expected_observations: list[str] = field(default_factory=list)
    timeout: float = 30.0
    retryable: bool = False
    rate_limit: float = 0.0
    safety_class: str = "controlled"


@dataclass(slots=True)
class ProofExecution(TidbEntity):
    """A persisted proof execution."""

    execution_id: str
    proof_id: str = ""
    plan_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    tool_id: str = ""
    sdk_execution_id: str = ""
    status: str = "pending"
    phase: str = "scope_validation"
    phases_completed: list[str] = field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int = 0
    correlation_id: str = ""
    analysis_version: str = "1.0.0"


@dataclass(slots=True)
class ProofOfConcept(TidbEntity):
    """A persisted structured Proof of Concept."""

    poc_id: str
    proof_id: str = ""
    finding_id: str = ""
    format: str = "request_response"
    description: str = ""
    preconditions: list[str] = field(default_factory=list)
    scope: dict[str, object] = field(default_factory=dict)
    steps: list[dict[str, object]] = field(default_factory=list)
    inputs: dict[str, object] = field(default_factory=dict)
    expected_result: str = ""
    observed_result: str = ""
    evidence: list[str] = field(default_factory=list)
    replay_policy: dict[str, object] = field(default_factory=dict)
    safety_policy: str = "default"
    poc_version: str = "1.0.0"
    parent_version: str = ""
    reason: str = ""
    changes: list[str] = field(default_factory=list)
    status: str = "candidate"
    validated_at: str | None = None


@dataclass(slots=True)
class ProofReplay(TidbEntity):
    """A persisted proof replay."""

    replay_id: str
    proof_id: str = ""
    poc_id: str = ""
    poc_version: str = "1.0.0"
    proof_version: str = "1.0.0"
    tool_id: str = ""
    tool_version: str = ""
    target_state: str = ""
    input_hash: str = ""
    configuration_hash: str = ""
    evidence_hash: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    result: str = "not_run"
    verdict: str = "inconclusive"
    duration_ms: int = 0


@dataclass(slots=True)
class ProofEvidence(TidbEntity):
    """A persisted proof↔evidence link."""

    link_id: str
    proof_id: str = ""
    replay_id: str = ""
    evidence_id: str = ""
    role: str = "proof"
    kind: str = "external"


@dataclass(slots=True)
class ProofPolicyDecision(TidbEntity):
    """A persisted proof gate decision."""

    decision_id: str
    proof_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    kind: str = "scope"
    allowed: bool = False
    reason: str = ""
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ImpactAssessment(TidbEntity):
    """A persisted evidence-backed impact assessment."""

    impact_id: str
    finding_id: str = ""
    proof_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    impact_type: str = "confidentiality"
    impact_level: str = "none"
    evidence_ids: list[str] = field(default_factory=list)
    reasoning: str = ""
    confidence: float = 0.0
    scope: dict[str, object] = field(default_factory=dict)
    assessment_version: str = "1.0.0"


@dataclass(slots=True)
class ConfidenceAssessment(TidbEntity):
    """A persisted evidence-driven confidence assessment."""

    confidence_id: str
    proof_id: str = ""
    finding_id: str = ""
    confidence: float = 0.0
    state: str = "low"
    factor_scores: dict[str, object] = field(default_factory=dict)
    weights: dict[str, object] = field(default_factory=dict)
    confidence_policy_id: str = "confidence-policy/1.0.0"
    calculation_version: str = "1.0.0"
    evidence_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ProofQuality(TidbEntity):
    """A persisted explainable proof quality score."""

    quality_id: str
    proof_id: str = ""
    score: float = 0.0
    factors: dict[str, object] = field(default_factory=dict)
    analysis_version: str = "1.0.0"


@dataclass(slots=True)
class FindingStateTransition(TidbEntity):
    """A persisted finding lifecycle transition."""

    transition_id: str
    finding_id: str = ""
    hypothesis_id: str = ""
    proof_id: str = ""
    from_state: str = "detected"
    to_state: str = "detected"
    reason: str = ""
    confidence: float = 0.0


@dataclass(slots=True)
class ProofHistory(TidbEntity):
    """A persisted temporal proof history record."""

    history_id: str
    proof_id: str = ""
    finding_id: str = ""
    hypothesis_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    vulnerability_id: str = ""
    state: str = "candidate"
    verified: bool = False
