# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability Proof Strategy Library TIDB entities.

System-of-record entities for the Sprint 022 strategy intelligence layer:
proof strategies and their versions, strategy requirements, evidence rules,
tool requirements, strategy candidates (novel), proof validation results and
manual proof instructions.

Security boundary: these tables store strategy contracts, canonical evidence
rules and validation results — never exploit payloads, never credentials,
never unrestricted executable PoC scripts and never out-of-scope request
material.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class ProofStrategy(TidbEntity):
    """A persisted proof strategy contract."""

    strategy_id: str
    strategy_version: str = "1.0.0"
    vulnerability_class: str = "unknown_behavior"
    security_property: str = ""
    description: str = ""
    preconditions: list[str] = field(default_factory=list)
    required_inputs: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    optional_evidence: list[str] = field(default_factory=list)
    expected_observations: list[str] = field(default_factory=list)
    negative_observations: list[str] = field(default_factory=list)
    inconclusive_conditions: list[str] = field(default_factory=list)
    confirmation_conditions: list[str] = field(default_factory=list)
    replay_requirements: dict[str, int] = field(default_factory=dict)
    impact_requirements: list[str] = field(default_factory=list)
    required_capabilities: list[str] = field(default_factory=list)
    preferred_tools: list[str] = field(default_factory=list)
    fallback_strategies: list[str] = field(default_factory=list)
    safety_class: str = "benign_marker"
    scope_requirements: list[str] = field(default_factory=list)
    confidence_policy: str = "evidence-dominated"
    stop_conditions: list[str] = field(default_factory=list)
    abort_conditions: list[str] = field(default_factory=list)
    provenance: dict[str, str] = field(default_factory=dict)
    status: str = "active"
    permits_confirmation: bool = True
    reportable: bool = True
    execution: str = "executable"


@dataclass(slots=True)
class ProofStrategyVersion(TidbEntity):
    """A persisted proof strategy version (audit of strategy evolution)."""

    strategy_id: str
    strategy_version: str = "1.0.0"
    vulnerability_class: str = "unknown_behavior"
    strategy_checksum: str = ""
    reason: str = ""
    previous_version: str = ""
    superseded_by: str = ""
    registered_at: str = ""


@dataclass(slots=True)
class ProofStrategyRequirement(TidbEntity):
    """A persisted strategy requirement (precondition, input or condition)."""

    strategy_id: str = ""
    strategy_version: str = "1.0.0"
    requirement_type: str = "precondition"
    requirement: str = ""
    required: bool = True


@dataclass(slots=True)
class ProofStrategyEvidenceRule(TidbEntity):
    """A persisted evidence rule belonging to a strategy."""

    strategy_id: str = ""
    strategy_version: str = "1.0.0"
    rule_type: str = "minimum_required"
    evidence_kind: str = ""
    confirmation_rule: str = ""


@dataclass(slots=True)
class ProofStrategyToolRequirement(TidbEntity):
    """A persisted tool-capability requirement of a strategy."""

    strategy_id: str = ""
    strategy_version: str = "1.0.0"
    capability: str = ""
    sdk_capabilities: list[str] = field(default_factory=list)
    preferred_tool: str = ""
    optional: bool = False


@dataclass(slots=True)
class ProofStrategyCandidate(TidbEntity):
    """A persisted novel strategy candidate awaiting review."""

    candidate_id: str
    vulnerability_class: str = "unknown_behavior"
    observed_behavior: str = ""
    evidence: list[str] = field(default_factory=list)
    proposed_strategy_id: str = ""
    proposed_strategy: dict[str, object] = field(default_factory=dict)
    reasoning: str = ""
    source_findings: list[str] = field(default_factory=list)
    confidence: float = 0.0
    status: str = "proposed"
    review_required: bool = True


@dataclass(slots=True)
class ProofValidationResult(TidbEntity):
    """A persisted proof validation result."""

    proof_id: str
    strategy_id: str = ""
    strategy_version: str = "1.0.0"
    verdict: str = "insufficient_evidence"
    score: float = 0.0
    proof_quality_level: str = "p0_candidate"
    required_evidence: list[str] = field(default_factory=list)
    present_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    contradictory_evidence: list[str] = field(default_factory=list)
    disqualifying_evidence: list[str] = field(default_factory=list)
    scope_result: dict[str, object] = field(default_factory=dict)
    safety_result: dict[str, object] = field(default_factory=dict)
    replay_result: dict[str, object] = field(default_factory=dict)
    impact_result: dict[str, object] = field(default_factory=dict)
    reproducibility_result: dict[str, object] = field(default_factory=dict)
    evidence_covered: list[str] = field(default_factory=list)
    evidence_contract_ok: bool = False
    reasoning: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    validator_version: str = "1.0.0"


@dataclass(slots=True)
class ProofManualInstruction(TidbEntity):
    """A persisted manual proof instruction."""

    instruction_id: str
    proof_id: str = ""
    strategy_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    objective: str = ""
    preconditions: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    expected_observation: str = ""
    evidence_to_capture: list[str] = field(default_factory=list)
    safety_notes: list[str] = field(default_factory=list)
    scope: dict[str, str] = field(default_factory=dict)
    completion_criteria: list[str] = field(default_factory=list)
    status: str = "open"
