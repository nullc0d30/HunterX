# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Memory & Campaign Intelligence TIDB entities.

Sprint 030. System-of-record entities for the historical intelligence layer.
The layer persists normalized historical records (never raw tool output) so
first/last seen tracking, observation history, snapshots, diffs, campaigns,
coverage gaps, hypothesis history, risk history, revalidation state,
finding history, attack-path history and preserved contradictions stay
queryable.

Each entity mirrors the pure domain model in ``hunterx.domain.target_memory``;
the application service maps between them. Envelope (id, timestamps,
versioning, soft-delete) comes from :class:`TidbEntity`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class MemoryObservationRecord(TidbEntity):
    """A persistent, history-tracked observation of a target.

    Attributes:
        observation_key: canonical key (``observation_type:normalized_value``).
        target_id: owning target.
        mission_id: most recent owning mission.
        observation_type: observation type string.
        value: the observed value.
        normalized_value: canonical normalized value.
        asset_key: related asset key.
        tool: most recent producing tool.
        first_seen / last_seen: UTC ISO-8601 tracking stamps.
        observation_count: number of raw observations aggregated.
        first_mission / last_mission: first and most recent owning mission.
        first_source / last_source: first and most recent source.
        current_state: memory observation state string.
        freshness: freshness state string.
        confidence: aggregate confidence in ``[0, 1]``.
        source_reliability: reliability label.
        corroboration_count: independent source count.
        contradiction_state: contradiction state string or ``""``.
        validity: memory validity string.
        expires_at: UTC ISO-8601 expiry (``None`` = no expiry).
        provenance: provenance metadata (JSON).

    """

    observation_key: str = ""
    target_id: str = ""
    mission_id: str = ""
    observation_type: str = "other"
    value: str = ""
    normalized_value: str = ""
    asset_key: str = ""
    tool: str = ""
    first_seen: str = ""
    last_seen: str = ""
    observation_count: int = 1
    first_mission: str = ""
    last_mission: str = ""
    first_source: str = ""
    last_source: str = ""
    current_state: str = "known_current"
    freshness: str = "unknown"
    confidence: float = 1.0
    source_reliability: str = "unknown"
    corroboration_count: int = 0
    contradiction_state: str = ""
    validity: str = "valid"
    expires_at: str | None = None
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class TargetSnapshotRecord(TidbEntity):
    """A reproducible target state snapshot at a point in time.

    Attributes:
        snapshot_id: stable snapshot identifier.
        target_id: owning target.
        mission_id: owning mission.
        schema_version: snapshot schema version.
        observation_count: number of memory observations captured.
        state_hash: deterministic SHA-256 of the serialized state.
        state: canonical state map (JSON).

    """

    snapshot_id: str = ""
    target_id: str = ""
    mission_id: str = ""
    schema_version: int = 1
    observation_count: int = 0
    state_hash: str = ""
    state: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class TargetDiffRecord(TidbEntity):
    """A deterministic diff between two target snapshots.

    Attributes:
        diff_id: stable diff identifier.
        target_id: owning target.
        snapshot_a_id: base snapshot identifier.
        snapshot_b_id: later snapshot identifier.
        state_hash_a: state hash of snapshot A.
        state_hash_b: state hash of snapshot B.
        changes: serialized change list (JSON).
        deterministic: whether the diff is deterministic (always ``True``).

    """

    diff_id: str = ""
    target_id: str = ""
    snapshot_a_id: str = ""
    snapshot_b_id: str = ""
    state_hash_a: str = ""
    state_hash_b: str = ""
    changes: list[dict[str, object]] = field(default_factory=list)
    deterministic: bool = True


@dataclass(slots=True)
class MissionMemoryRecord(TidbEntity):
    """Historical context of a mission against a target.

    References canonical entities by id — never duplicates them.
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


@dataclass(slots=True)
class HypothesisMemoryRecord(TidbEntity):
    """Historical record of a tested hypothesis.

    Covers both failed and successful hypothesis memory: the record keeps the
    hypothesis, tool, observed evidence, reason, conditions and the reusable
    success pattern.
    """

    memory_id: str = ""
    hypothesis_id: str = ""
    target_id: str = ""
    mission_id: str = ""
    statement: str = ""
    hypothesis_type: str = ""
    outcome: str = "inconclusive"
    tool: str = ""
    tool_version: str = ""
    evidence_observed: str = ""
    reason: str = ""
    tested_at: str = ""
    conditions: dict[str, object] = field(default_factory=dict)
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


@dataclass(slots=True)
class ToolObservationRecord(TidbEntity):
    """Historical provenance of a meaningful tool result.

    Retains the normalized result and references — never raw output.
    """

    tool: str = ""
    tool_version: str = ""
    execution_id: str = ""
    target_id: str = ""
    scope: str = ""
    timestamp: str = ""
    normalized_result: dict[str, object] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    derived_entities: list[str] = field(default_factory=list)
    confidence: float = 1.0
    provenance: dict[str, str] = field(default_factory=dict)
    tenant: str = ""


@dataclass(slots=True)
class TargetRiskRecord(TidbEntity):
    """A point-in-time target risk assessment (append-only history)."""

    risk_id: str = ""
    target_id: str = ""
    campaign_id: str = ""
    mission_id: str = ""
    risk_level: str = "low"
    previous_risk_level: str | None = None
    reason: str = ""
    detected_at: str = ""
    driving_changes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FindingMemoryRecord(TidbEntity):
    """Lifecycle history of a single finding.

    References the canonical finding by ``finding_id`` and tracks lifecycle
    facts the canonical record does not.
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


@dataclass(slots=True)
class FindingRecurrenceRecord(TidbEntity):
    """A detected recurrence of a previously remediated vulnerability."""

    recurrence_id: str = ""
    target_id: str = ""
    campaign_id: str = ""
    original_finding_id: str = ""
    new_finding_id: str = ""
    vulnerability_class: str = ""
    root_cause: str = ""
    previous_location: str = ""
    new_location: str = ""
    kind: str = "new_location"
    detected_at: str = ""
    confidence: float = 0.5


@dataclass(slots=True)
class CampaignRecord(TidbEntity):
    """A campaign grouping related missions against a target or target set."""

    campaign_id: str = ""
    name: str = ""
    objective: str = ""
    scope: str = ""
    status: str = "planned"
    target_ids: list[str] = field(default_factory=list)
    mission_ids: list[str] = field(default_factory=list)
    started_at: str = ""
    ended_at: str | None = None
    risk_history: list[dict[str, object]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    coverage: dict[str, str] = field(default_factory=dict)
    changes: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    tenant: str = ""


@dataclass(slots=True)
class CoverageGapRecord(TidbEntity):
    """A concrete, actionable coverage gap."""

    gap_id: str = ""
    target_id: str = ""
    campaign_id: str = ""
    asset_key: str = ""
    capability: str = ""
    kind: str = "discovered_untested"
    description: str = ""
    significance: str = "medium"
    status: str = "open"
    detected_at: str = ""
    resolved_at: str | None = None
    candidate_tools: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RevalidationRecord(TidbEntity):
    """A single observation identified for revalidation."""

    plan_id: str = ""
    observation_key: str = ""
    target_id: str = ""
    asset_key: str = ""
    observation_type: str = ""
    freshness: str = "stale"
    last_seen: str = ""
    reason: str = ""
    priority: str = "medium"
    status: str = "open"
    completed_at: str | None = None


@dataclass(slots=True)
class AttackPathMemoryRecord(TidbEntity):
    """A persistent historical attack-path observation.

    Theoretical paths are never treated as confirmed compromise.
    """

    path_id: str = ""
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


@dataclass(slots=True)
class MemoryContradictionRecord(TidbEntity):
    """A preserved contradiction between observations or tools."""

    contradiction_id: str = ""
    target_id: str = ""
    asset_key: str = ""
    observation_key: str = ""
    observations: list[dict[str, object]] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    state: str = "open"
    resolution: str = ""
    detected_at: str = ""
    resolved_at: str | None = None


@dataclass(slots=True)
class NextActionRecord(TidbEntity):
    """An advisory next-action recommendation derived from memory."""

    recommendation_id: str = ""
    target_id: str = ""
    campaign_id: str = ""
    action: str = ""
    reason: str = ""
    priority: str = "medium"
    required_tool_capabilities: list[str] = field(default_factory=list)
    evidence_required: list[str] = field(default_factory=list)
    expected_outcome: str = ""
    historical_context: list[str] = field(default_factory=list)


__all__ = [
    "AttackPathMemoryRecord",
    "CampaignRecord",
    "CoverageGapRecord",
    "FindingMemoryRecord",
    "FindingRecurrenceRecord",
    "HypothesisMemoryRecord",
    "MemoryContradictionRecord",
    "MemoryObservationRecord",
    "MissionMemoryRecord",
    "NextActionRecord",
    "RevalidationRecord",
    "TargetDiffRecord",
    "TargetRiskRecord",
    "TargetSnapshotRecord",
    "ToolObservationRecord",
]
