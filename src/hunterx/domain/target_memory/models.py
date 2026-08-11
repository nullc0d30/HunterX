# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Memory & Campaign Intelligence — pure domain models.

Sprint 030. Canonical, storage-agnostic models for the historical
intelligence layer. The layer is deliberately NOT a replacement for Target
Intelligence, TIDB, Finding, Evidence, Mission, Knowledge, Correlation or PoC
systems: it is a *historical intelligence layer that references canonical
entities*.

Every persistent observation exposes first/last seen tracking, the first/last
mission and source, an observation count and a current state classification.
Snapshots are reproducible from stored observations; diffs are deterministic
(same snapshot pair ⇒ same diff). Historical evidence is preserved — memory is
untrusted input guarded by confidence, corroboration, freshness and
contradiction handling.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.target_memory.enums import (
    CampaignStatus,
    ChangeSignificance,
    CoverageGapKind,
    DiffChangeKind,
    FreshnessState,
    HypothesisOutcome,
    MemoryContradictionState,
    MemoryObservationState,
    MemoryValidity,
    RecurrenceKind,
    RevalidationPriority,
    RiskLevel,
)
from hunterx.shared.ids import generate_content_id, generate_id
from hunterx.shared.time import utcnow_iso

# ==========================================================================
# 1. MEMORY OBSERVATION (HISTORICAL TRACKING)
# ==========================================================================


@dataclass(frozen=True, slots=True)
class MemoryObservation:
    """A persistent, history-tracked observation of a target.

    This is the canonical unit of Target Memory. It aggregates every raw
    observation that shares a canonical key into a single record with
    first/last seen tracking, the first/last owning mission and source, a
    count, and a classified current state.

    Attributes:
        observation_key: canonical key (``observation_type:normalized_value``).
        target_id: owning target.
        mission_id: most recent owning mission.
        observation_type: :class:`ObservationType`-style string.
        value: the observed value.
        normalized_value: canonical normalized value.
        asset_key: related asset key (``""`` when unlinked).
        tool: most recent producing tool.
        first_seen: UTC ISO-8601 first observation stamp.
        last_seen: UTC ISO-8601 most recent observation stamp.
        observation_count: number of raw observations aggregated.
        first_mission: mission that first observed the value.
        last_mission: mission that most recently observed the value.
        first_source: source of the first observation.
        last_source: source of the most recent observation.
        current_state: :class:`MemoryObservationState`.
        freshness: :class:`FreshnessState`.
        confidence: aggregate confidence in ``[0, 1]``.
        source_reliability: reliability label of the most reliable source.
        corroboration_count: number of independent sources confirming.
        contradiction_state: :class:`MemoryContradictionState` or ``""``.
        validity: :class:`MemoryValidity`.
        expires_at: UTC ISO-8601 expiry (``None`` = no expiry).
        provenance: provenance metadata (JSON-safe).

    """

    observation_key: str
    target_id: str
    observation_type: str
    value: str
    normalized_value: str
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 1
    first_mission: str = ""
    last_mission: str = ""
    first_source: str = ""
    last_source: str = ""
    current_state: MemoryObservationState = MemoryObservationState.KNOWN_CURRENT
    freshness: FreshnessState = FreshnessState.UNKNOWN
    mission_id: str = ""
    asset_key: str = ""
    tool: str = ""
    confidence: float = 1.0
    source_reliability: str = "unknown"
    corroboration_count: int = 0
    contradiction_state: str = ""
    validity: MemoryValidity = MemoryValidity.VALID
    expires_at: str | None = None
    provenance: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "observation_key": self.observation_key,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "observation_type": self.observation_type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "tool": self.tool,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observation_count": self.observation_count,
            "first_mission": self.first_mission,
            "last_mission": self.last_mission,
            "first_source": self.first_source,
            "last_source": self.last_source,
            "current_state": self.current_state.value,
            "freshness": self.freshness.value,
            "confidence": self.confidence,
            "source_reliability": self.source_reliability,
            "corroboration_count": self.corroboration_count,
            "contradiction_state": self.contradiction_state,
            "validity": self.validity.value,
            "expires_at": self.expires_at,
            "provenance": dict(self.provenance),
        }


# ==========================================================================
# 2. TARGET MEMORY AGGREGATE
# ==========================================================================


@dataclass(slots=True)
class TargetMemory:
    """The canonical, queryable historical understanding of one target.

    Attributes:
        target_id: owning target.
        observations: memory observations keyed by ``observation_key``.
        coverage: per ``asset_key:capability`` coverage map.
        findings: finding lifecycle records keyed by ``finding_id``.
        gaps: coverage gaps.
        recommendations: next-action recommendations.
        contradictions: preserved memory contradictions.
        changed_at: UTC ISO-8601 last-update stamp.
        mission_id: most recent owning mission.

    """

    target_id: str = ""
    observations: dict[str, MemoryObservation] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    findings: dict[str, FindingMemory] = field(default_factory=dict)
    gaps: list[CoverageGap] = field(default_factory=list)
    recommendations: list[NextActionRecommendation] = field(default_factory=list)
    contradictions: list[MemoryContradiction] = field(default_factory=list)
    changed_at: str = field(default_factory=utcnow_iso)
    mission_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "observation_count": len(self.observations),
            "coverage_count": len(self.coverage),
            "finding_count": len(self.findings),
            "gap_count": len(self.gaps),
            "contradiction_count": len(self.contradictions),
            "observations": [obs.to_dict() for obs in sorted(self.observations.values(), key=lambda o: o.observation_key)],
            "findings": [f.to_dict() for f in self.findings.values()],
            "gaps": [g.to_dict() for g in self.gaps],
            "recommendations": [r.to_dict() for r in self.recommendations],
            "changed_at": self.changed_at,
        }


# ==========================================================================
# 3. SNAPSHOT
# ==========================================================================


def _stable_state(state: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied state dict with recursively sorted keys.

    Ensures that identical states serialize identically regardless of
    insertion order, which is required for deterministic hashing.
    """
    if isinstance(state, dict):
        return {str(k): _stable_state(v) for k, v in sorted(state.items())}
    if isinstance(state, list):
        return [_stable_state(item) for item in state]
    if isinstance(state, tuple):
        return [_stable_state(item) for item in state]
    return state


@dataclass(frozen=True, slots=True)
class TargetSnapshot:
    """A reproducible representation of the known target state at a point in time.

    Attributes:
        snapshot_id: stable snapshot identifier.
        target_id: owning target.
        mission_id: owning mission.
        created_at: UTC ISO-8601 creation stamp.
        schema_version: snapshot schema version.
        observation_count: number of memory observations captured.
        state_hash: deterministic SHA-256 of the serialized state.
        state: canonical state map (``assets``, ``observations``, ``findings``).

    """

    snapshot_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)
    schema_version: int = 1
    observation_count: int = 0
    state_hash: str = ""
    state: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Derive the deterministic state hash from the stable state."""
        if not self.state_hash:
            canonical = _stable_state(self.state)
            digest = hashlib.sha256(
                json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            object.__setattr__(self, "state_hash", digest)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping (excludes the raw state by default)."""
        return {
            "snapshot_id": self.snapshot_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
            "observation_count": self.observation_count,
            "state_hash": self.state_hash,
        }

    def with_state(self) -> dict[str, Any]:
        """Return the full serialized snapshot including the canonical state."""
        payload = self.to_dict()
        payload["state"] = _stable_state(self.state)
        return payload


# ==========================================================================
# 4. DIFF
# ==========================================================================


@dataclass(frozen=True, slots=True)
class TargetChange:
    """A single structured change detected between two snapshots.

    Attributes:
        key: canonical key of the changed entity.
        kind: :class:`DiffChangeKind`.
        significance: :class:`ChangeSignificance`.
        asset_key: related asset key.
        field: changed field name.
        previous: previous canonical value.
        current: new canonical value.
        description: human-readable explanation.
        evidence_ref: evidence reference backing the change.
        confidence: confidence of the evidence backing the change in ``[0, 1]``
            (caps the significance classification).

    """

    key: str
    kind: DiffChangeKind = DiffChangeKind.ADDED
    significance: ChangeSignificance = ChangeSignificance.LOW
    asset_key: str = ""
    field: str = ""
    previous: Any = None
    current: Any = None
    description: str = ""
    evidence_ref: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "key": self.key,
            "kind": self.kind.value,
            "significance": self.significance.value,
            "asset_key": self.asset_key,
            "field": self.field,
            "previous": self.previous,
            "current": self.current,
            "description": self.description,
            "evidence_ref": self.evidence_ref,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class TargetDiff:
    """A deterministic diff between two target snapshots.

    Attributes:
        diff_id: stable diff identifier.
        target_id: owning target.
        snapshot_a_id: base snapshot identifier.
        snapshot_b_id: later snapshot identifier.
        created_at: UTC ISO-8601 creation stamp.
        state_hash_a: state hash of snapshot A.
        state_hash_b: state hash of snapshot B.
        changes: ordered list of :class:`TargetChange`.
        deterministic: always ``True``; same inputs ⇒ same output.

    """

    diff_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    snapshot_a_id: str = ""
    snapshot_b_id: str = ""
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)
    state_hash_a: str = ""
    state_hash_b: str = ""
    changes: tuple[TargetChange, ...] = ()
    deterministic: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "diff_id": self.diff_id,
            "target_id": self.target_id,
            "snapshot_a_id": self.snapshot_a_id,
            "snapshot_b_id": self.snapshot_b_id,
            "created_at": self.created_at,
            "state_hash_a": self.state_hash_a,
            "state_hash_b": self.state_hash_b,
            "change_count": len(self.changes),
            "changes": [change.to_dict() for change in self.changes],
            "deterministic": self.deterministic,
        }


# ==========================================================================
# 5. MISSION MEMORY
# ==========================================================================


@dataclass(slots=True)
class MissionMemory:
    """Historical context of a completed mission against a target.

    References canonical entities by id (never duplicates them): tools used,
    assets/findings/PoCs discovered, hypotheses, blocked tests, tool failures
    and coverage achieved/gaps.
    """

    mission_id: str = ""
    target_id: str = ""
    scope: str = ""
    status: str = "completed"
    started_at: str = ""
    ended_at: str = ""
    tools_used: list[str] = field(default_factory=list)
    assets_discovered: list[str] = field(default_factory=list)
    findings_discovered: list[str] = field(default_factory=list)
    findings_validated: list[str] = field(default_factory=list)
    pocs_generated: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    successful_hypotheses: list[str] = field(default_factory=list)
    failed_hypotheses: list[str] = field(default_factory=list)
    blocked_tests: list[str] = field(default_factory=list)
    tool_failures: list[str] = field(default_factory=list)
    coverage_achieved: dict[str, float] = field(default_factory=dict)
    coverage_gaps: list[str] = field(default_factory=list)
    tenant: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "scope": self.scope,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "tools_used": list(self.tools_used),
            "assets_discovered": list(self.assets_discovered),
            "findings_discovered": list(self.findings_discovered),
            "findings_validated": list(self.findings_validated),
            "pocs_generated": list(self.pocs_generated),
            "hypotheses": list(self.hypotheses),
            "successful_hypotheses": list(self.successful_hypotheses),
            "failed_hypotheses": list(self.failed_hypotheses),
            "blocked_tests": list(self.blocked_tests),
            "tool_failures": list(self.tool_failures),
            "coverage_achieved": dict(self.coverage_achieved),
            "coverage_gaps": list(self.coverage_gaps),
            "tenant": self.tenant,
        }


# ==========================================================================
# 6. HYPOTHESIS MEMORY
# ==========================================================================


@dataclass(frozen=True, slots=True)
class HypothesisMemory:
    """Historical record of a tested hypothesis.

    Remembers *what* was tested, *why* (the hypothesis), *which tool* was
    used, *what evidence* was observed, *why validation failed/succeeded*,
    *when* and *under what conditions*. Successful records also retain the
    reusable pattern (vulnerability type, asset type, technology, endpoint /
    parameter patterns, authentication context, tool, validation strategy,
    PoC strategy and evidence pattern) as historical intelligence.
    """

    memory_id: str = field(default_factory=generate_id, kw_only=True)
    hypothesis_id: str = ""
    target_id: str = ""
    mission_id: str = ""
    statement: str = ""
    hypothesis_type: str = ""
    outcome: HypothesisOutcome = HypothesisOutcome.INCONCLUSIVE
    tool: str = ""
    tool_version: str = ""
    evidence_observed: str = ""
    reason: str = ""
    tested_at: str = field(default_factory=utcnow_iso, kw_only=True)
    conditions: dict[str, Any] = field(default_factory=dict)
    vulnerability_type: str = ""
    asset_type: str = ""
    technology: str = ""
    endpoint_pattern: str = ""
    parameter_pattern: str = ""
    authentication_context: str = ""
    validation_strategy: str = ""
    poc_strategy: str = ""
    evidence_pattern: str = ""
    confidence: float = 0.0
    tenant: str = ""

    @property
    def succeeded(self) -> bool:
        """Return ``True`` when the hypothesis was validated/proven."""
        return self.outcome == HypothesisOutcome.SUCCEEDED

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "memory_id": self.memory_id,
            "hypothesis_id": self.hypothesis_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "statement": self.statement,
            "hypothesis_type": self.hypothesis_type,
            "outcome": self.outcome.value,
            "succeeded": self.succeeded,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "evidence_observed": self.evidence_observed,
            "reason": self.reason,
            "tested_at": self.tested_at,
            "conditions": dict(self.conditions),
            "vulnerability_type": self.vulnerability_type,
            "asset_type": self.asset_type,
            "technology": self.technology,
            "endpoint_pattern": self.endpoint_pattern,
            "parameter_pattern": self.parameter_pattern,
            "authentication_context": self.authentication_context,
            "validation_strategy": self.validation_strategy,
            "poc_strategy": self.poc_strategy,
            "evidence_pattern": self.evidence_pattern,
            "confidence": self.confidence,
            "tenant": self.tenant,
        }


# ==========================================================================
# 7. TOOL OBSERVATION
# ==========================================================================


@dataclass(frozen=True, slots=True)
class ToolObservation:
    """Historical provenance of a meaningful tool result.

    Retains the normalized result and references (never the raw output):
    tool + version, execution id, target, scope, timestamp, normalized
    result, evidence references, derived entity keys, confidence and
    provenance.
    """

    tool: str = ""
    tool_version: str = ""
    execution_id: str = ""
    target_id: str = ""
    scope: str = ""
    timestamp: str = field(default_factory=utcnow_iso, kw_only=True)
    normalized_result: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    derived_entities: list[str] = field(default_factory=list)
    confidence: float = 1.0
    provenance: dict[str, str] = field(default_factory=dict)
    tenant: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "tool": self.tool,
            "tool_version": self.tool_version,
            "execution_id": self.execution_id,
            "target_id": self.target_id,
            "scope": self.scope,
            "timestamp": self.timestamp,
            "normalized_result": dict(self.normalized_result),
            "evidence_refs": list(self.evidence_refs),
            "derived_entities": list(self.derived_entities),
            "confidence": self.confidence,
            "provenance": dict(self.provenance),
            "tenant": self.tenant,
        }


# ==========================================================================
# 8. RISK HISTORY
# ==========================================================================


@dataclass(frozen=True, slots=True)
class TargetRiskEntry:
    """A point-in-time target risk assessment.

    Risk history is append-only: historical risk is never overwritten.
    """

    risk_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    campaign_id: str = ""
    mission_id: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    previous_risk_level: RiskLevel | None = None
    reason: str = ""
    detected_at: str = field(default_factory=utcnow_iso, kw_only=True)
    driving_changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "risk_id": self.risk_id,
            "target_id": self.target_id,
            "campaign_id": self.campaign_id,
            "mission_id": self.mission_id,
            "risk_level": self.risk_level.value,
            "previous_risk_level": self.previous_risk_level.value if self.previous_risk_level else None,
            "reason": self.reason,
            "detected_at": self.detected_at,
            "driving_changes": list(self.driving_changes),
        }


# ==========================================================================
# 9. FINDING MEMORY & RECURRENCE
# ==========================================================================


@dataclass(frozen=True, slots=True)
class FindingMemory:
    """Lifecycle history of a single finding.

    References the canonical finding by ``finding_id`` and tracks the
    lifecycle facts the canonical record does not: first/last validation,
    remediation/retest state, reopen count, affected assets/endpoints, root
    cause and recurrence count.
    """

    finding_id: str = ""
    target_id: str = ""
    mission_id: str = ""
    title: str = ""
    vulnerability_class: str = ""
    severity: str = "info"
    status: str = "candidate"
    first_detected: str = ""
    first_validated: str = ""
    last_validated: str = ""
    last_observed: str = ""
    remediation_state: str = "open"
    retest_state: str = ""
    reopened_count: int = 0
    closed_at: str = ""
    affected_assets: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    root_cause: str = ""
    recurrence_count: int = 0
    tenant: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "finding_id": self.finding_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "title": self.title,
            "vulnerability_class": self.vulnerability_class,
            "severity": self.severity,
            "status": self.status,
            "first_detected": self.first_detected,
            "first_validated": self.first_validated,
            "last_validated": self.last_validated,
            "last_observed": self.last_observed,
            "remediation_state": self.remediation_state,
            "retest_state": self.retest_state,
            "reopened_count": self.reopened_count,
            "closed_at": self.closed_at,
            "affected_assets": list(self.affected_assets),
            "affected_endpoints": list(self.affected_endpoints),
            "root_cause": self.root_cause,
            "recurrence_count": self.recurrence_count,
            "tenant": self.tenant,
        }


@dataclass(frozen=True, slots=True)
class FindingRecurrence:
    """A detected recurrence of a previously remediated vulnerability.

    Recognizes the same root-cause family appearing at a new location
    (potential regression) without assuming compromise.
    """

    recurrence_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    campaign_id: str = ""
    original_finding_id: str = ""
    new_finding_id: str = ""
    vulnerability_class: str = ""
    root_cause: str = ""
    previous_location: str = ""
    new_location: str = ""
    kind: RecurrenceKind = RecurrenceKind.NEW_LOCATION
    detected_at: str = field(default_factory=utcnow_iso, kw_only=True)
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "recurrence_id": self.recurrence_id,
            "target_id": self.target_id,
            "campaign_id": self.campaign_id,
            "original_finding_id": self.original_finding_id,
            "new_finding_id": self.new_finding_id,
            "vulnerability_class": self.vulnerability_class,
            "root_cause": self.root_cause,
            "previous_location": self.previous_location,
            "new_location": self.new_location,
            "kind": self.kind.value,
            "detected_at": self.detected_at,
            "confidence": self.confidence,
        }


# ==========================================================================
# 10. COVERAGE GAP
# ==========================================================================


@dataclass(frozen=True, slots=True)
class CoverageGap:
    """A concrete, actionable coverage gap.

    Each gap describes *what* was never covered (asset, capability) and why,
    so the next mission knows exactly which deficiency to close.
    """

    gap_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    campaign_id: str = ""
    asset_key: str = ""
    capability: str = ""
    kind: CoverageGapKind = CoverageGapKind.DISCOVERED_UNTESTED
    description: str = ""
    significance: ChangeSignificance = ChangeSignificance.MEDIUM
    status: str = "open"
    detected_at: str = field(default_factory=utcnow_iso, kw_only=True)
    resolved_at: str | None = None
    candidate_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "gap_id": self.gap_id,
            "target_id": self.target_id,
            "campaign_id": self.campaign_id,
            "asset_key": self.asset_key,
            "capability": self.capability,
            "kind": self.kind.value,
            "description": self.description,
            "significance": self.significance.value,
            "status": self.status,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
            "candidate_tools": list(self.candidate_tools),
        }


# ==========================================================================
# 11. REVALIDATION
# ==========================================================================


@dataclass(frozen=True, slots=True)
class RevalidationItem:
    """A single observation identified for revalidation.

    Attributes:
        observation_key: canonical observation key.
        target_id: owning target.
        asset_key: related asset key.
        observation_type: observation type string.
        freshness: :class:`FreshnessState`.
        last_seen: UTC ISO-8601 last observation stamp.
        reason: why revalidation is needed.
        priority: :class:`RevalidationPriority`.

    """

    observation_key: str
    target_id: str = ""
    asset_key: str = ""
    observation_type: str = ""
    freshness: FreshnessState = FreshnessState.STALE
    last_seen: str = ""
    reason: str = ""
    priority: RevalidationPriority = RevalidationPriority.MEDIUM

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "observation_key": self.observation_key,
            "target_id": self.target_id,
            "asset_key": self.asset_key,
            "observation_type": self.observation_type,
            "freshness": self.freshness.value,
            "last_seen": self.last_seen,
            "reason": self.reason,
            "priority": self.priority.value,
        }


@dataclass(frozen=True, slots=True)
class RevalidationPlan:
    """A prioritized plan of observations requiring revalidation."""

    plan_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)
    items: tuple[RevalidationItem, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "plan_id": self.plan_id,
            "target_id": self.target_id,
            "created_at": self.created_at,
            "item_count": len(self.items),
            "items": [item.to_dict() for item in self.items],
        }


# ==========================================================================
# 12. ATTACK-PATH HISTORY
# ==========================================================================


@dataclass(frozen=True, slots=True)
class AttackPathMemory:
    """A persistent historical attack-path observation.

    Theoretical paths are never treated as confirmed compromise: the record
    keeps confidence, status and evidence references distinct.
    """

    path_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    campaign_id: str = ""
    mission_id: str = ""
    nodes: list[str] = field(default_factory=list)
    edges: list[dict[str, str]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    status: str = "theoretical"
    changes: list[str] = field(default_factory=list)
    tenant: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "path_id": self.path_id,
            "target_id": self.target_id,
            "campaign_id": self.campaign_id,
            "mission_id": self.mission_id,
            "nodes": list(self.nodes),
            "edges": list(self.edges),
            "evidence_refs": list(self.evidence_refs),
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status,
            "changes": list(self.changes),
            "tenant": self.tenant,
        }


# ==========================================================================
# 13. CONTRADICTION
# ==========================================================================


@dataclass(frozen=True, slots=True)
class MemoryContradiction:
    """A preserved contradiction between observations or tools.

    Both observations are preserved; the current state is classified rather
    than overwritten. A contradiction is never averaged.
    """

    contradiction_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    asset_key: str = ""
    observation_key: str = ""
    observations: list[dict[str, Any]] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    state: MemoryContradictionState = MemoryContradictionState.OPEN
    resolution: str = ""
    detected_at: str = field(default_factory=utcnow_iso, kw_only=True)
    resolved_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "contradiction_id": self.contradiction_id,
            "target_id": self.target_id,
            "asset_key": self.asset_key,
            "observation_key": self.observation_key,
            "observations": list(self.observations),
            "tools": list(self.tools),
            "state": self.state.value,
            "resolution": self.resolution,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
        }


# ==========================================================================
# 14. NEXT-ACTION RECOMMENDATION
# ==========================================================================


@dataclass(frozen=True, slots=True)
class NextActionRecommendation:
    """A structured next-action recommendation derived from memory.

    Recommendations are advisory only: the mission planner decides whether to
    execute. Memory never executes actions directly.
    """

    recommendation_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    campaign_id: str = ""
    action: str = ""
    reason: str = ""
    priority: ChangeSignificance = ChangeSignificance.MEDIUM
    required_tool_capabilities: list[str] = field(default_factory=list)
    evidence_required: list[str] = field(default_factory=list)
    expected_outcome: str = ""
    historical_context: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "recommendation_id": self.recommendation_id,
            "target_id": self.target_id,
            "campaign_id": self.campaign_id,
            "action": self.action,
            "reason": self.reason,
            "priority": self.priority.value,
            "required_tool_capabilities": list(self.required_tool_capabilities),
            "evidence_required": list(self.evidence_required),
            "expected_outcome": self.expected_outcome,
            "historical_context": list(self.historical_context),
        }


# ==========================================================================
# 15. CAMPAIGN
# ==========================================================================


@dataclass(slots=True)
class Campaign:
    """A campaign groups related missions against a target or target set.

    Attributes:
        campaign_id: stable campaign identifier.
        name: human label.
        objective: campaign objective.
        scope: authorized scope.
        status: :class:`CampaignStatus`.
        target_ids: authorized target ids.
        mission_ids: missions in the campaign.
        started_at / ended_at: time range.
        risk_history: list of :class:`TargetRiskEntry`.
        findings: finding ids discovered during the campaign.
        coverage: coverage map.
        changes: change summaries.
        attack_paths: attack-path ids observed.
        tenant: isolation key.

    """

    campaign_id: str = field(default_factory=generate_id, kw_only=True)
    name: str = ""
    objective: str = ""
    scope: str = ""
    status: CampaignStatus = CampaignStatus.PLANNED
    target_ids: list[str] = field(default_factory=list)
    mission_ids: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utcnow_iso, kw_only=True)
    ended_at: str | None = None
    risk_history: list[TargetRiskEntry] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    coverage: dict[str, str] = field(default_factory=dict)
    changes: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    tenant: str = ""

    def start(self) -> None:
        """Transition the campaign to ``active``."""
        self.status = CampaignStatus.ACTIVE

    def add_mission(self, mission_id: str) -> None:
        """Add a mission to the campaign."""
        if mission_id not in self.mission_ids:
            self.mission_ids.append(mission_id)

    def complete(self) -> None:
        """Transition the campaign to ``completed`` and stamp the end time."""
        self.status = CampaignStatus.COMPLETED
        self.ended_at = utcnow_iso()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "objective": self.objective,
            "scope": self.scope,
            "status": self.status.value,
            "target_ids": list(self.target_ids),
            "mission_ids": list(self.mission_ids),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "risk_history": [risk.to_dict() for risk in self.risk_history],
            "findings": list(self.findings),
            "coverage": dict(self.coverage),
            "changes": list(self.changes),
            "attack_paths": list(self.attack_paths),
            "tenant": self.tenant,
        }


# ==========================================================================
# 16. CAMPAIGN INTELLIGENCE
# ==========================================================================


@dataclass(frozen=True, slots=True)
class CampaignIntelligence:
    """Answer the campaign intelligence questions.

    What changed, was discovered, was validated, remains untested, failed,
    was fixed, regressed, and what should be tested next.
    """

    campaign_id: str = ""
    changed: list[dict[str, Any]] = field(default_factory=list)
    discovered: list[str] = field(default_factory=list)
    validated: list[str] = field(default_factory=list)
    untested: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    regressed: list[str] = field(default_factory=list)
    next: list[NextActionRecommendation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "campaign_id": self.campaign_id,
            "changed": list(self.changed),
            "discovered": list(self.discovered),
            "validated": list(self.validated),
            "untested": list(self.untested),
            "failed": list(self.failed),
            "fixed": list(self.fixed),
            "regressed": list(self.regressed),
            "next": [rec.to_dict() for rec in self.next],
        }


def memory_observation_key(observation_type: str, normalized_value: str) -> str:
    """Return the canonical memory observation key for a type+value pair."""
    return f"{observation_type}:{normalized_value}"


def campaign_key(*parts: Any) -> str:
    """Return a stable content key for campaign intelligence records."""
    return generate_content_id(*parts)


__all__ = [
    "AttackPathMemory",
    "Campaign",
    "CampaignIntelligence",
    "CoverageGap",
    "FindingMemory",
    "FindingRecurrence",
    "HypothesisMemory",
    "MemoryContradiction",
    "MemoryObservation",
    "MissionMemory",
    "NextActionRecommendation",
    "RevalidationItem",
    "RevalidationPlan",
    "TargetChange",
    "TargetDiff",
    "TargetMemory",
    "TargetRiskEntry",
    "TargetSnapshot",
    "ToolObservation",
    "campaign_key",
    "memory_observation_key",
]
