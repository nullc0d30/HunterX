# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Target Intelligence — canonical models.

Sprint 026. Pure, read-only data contracts for the target intelligence layer:
the intelligence target, its assets, immutable observations, evidence records,
history entries, changes, coverage entries/matrix, information gaps,
hypotheses, proposed actions, explainable decisions, negative results,
conflicts and the explainable intelligence score.

These models are deliberately free of I/O and storage; the TIDB
``target_intelligence`` entities are the persistence projection and the
application service is the only orchestration surface. Provenance is
first-class on every record so all decisions remain reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.target_intelligence.enums import (
    ActionStatus,
    ActionType,
    ChangeKind,
    ConflictState,
    CoverageCapability,
    CoverageState,
    HypothesisStatus,
    HypothesisType,
    InformationGapCategory,
    IntelligencePhase,
    IntelligenceTargetKind,
    IntelligenceTargetStatus,
    ObservationType,
    StopCondition,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.shared.ids import generate_content_id, generate_id
from hunterx.shared.time import utcnow_iso

#: Analysis version stamped on every record this capability produces.
ANALYSIS_VERSION = "1.0.0"

#: Default ranking policy id; weights are loaded from policy, never hard-coded
#: in ranking logic.
DEFAULT_RANKING_POLICY_ID = "target-intelligence/ranking/1.0.0"

#: Deduplication key prefixes.
OBSERVATION_KEY_PREFIX = "ti:obs"
ASSET_KEY_PREFIX = "ti:asset"


def observation_key(*, target_id: str, tool: str, observation_type: str, value: str) -> str:
    """Return the stable dedup key of an observation."""
    return generate_content_id(OBSERVATION_KEY_PREFIX, target_id, tool, observation_type, value)


def _coerce_float(value: object, *, default: float = 0.0) -> float:
    """Coerce ``value`` to a bounded float in ``[0, 1]``."""
    try:
        parsed = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))


def _coerce_str(value: object, *, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _coerce_enum(enum_cls: type, value: object, default: Any) -> Any:
    """Coerce ``value`` to ``enum_cls``, returning ``default`` on failure.

    Accepts enum members and their string values (StrEnum) so persisted TIDB
    records can be rehydrated without a second mapping layer.
    """
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value))
    except (ValueError, TypeError):
        return default


# ==========================================================================
# 1. TARGET MODEL
# ==========================================================================


@dataclass(frozen=True, slots=True)
class IntelligenceTarget:
    """A canonical intelligence target.

    A target is NOT equivalent to a hostname. It is the authorized objective of
    a mission — an organization, program, domain tree, network range, cloud
    account or repository — that the mission is allowed to interrogate.

    Attributes:
        target_id: stable target identifier.
        mission_id: owning mission.
        scope: scope identifier the target belongs to.
        identity: human label of the target.
        classification: target classification (e.g. ``web``, ``api``, ``cloud``).
        criticality: business criticality label (``low``/``medium``/``high``/``critical``).
        kind: :class:`IntelligenceTargetKind`.
        value: canonical target value (domain, CIDR, account id, ...).
        discovered_at: when the target first entered the intelligence graph.
        first_seen / last_seen: state-time observation stamps.
        status: :class:`IntelligenceTargetStatus`.
        confidence: aggregate confidence in ``[0, 1]``.
        metadata: free-form attributes.
        phase: current :class:`IntelligencePhase`.
        intelligence_state: per-category intelligence state map.
        coverage_state: per-dimension coverage summary.
        tenant: isolation key (``""`` = default tenant).
        analysis_version: analysis version that produced this record.

    """

    target_id: str = field(default_factory=generate_id, kw_only=True)
    mission_id: str = ""
    scope: str = ""
    identity: str = ""
    classification: str = ""
    criticality: str = "medium"
    kind: IntelligenceTargetKind = IntelligenceTargetKind.DOMAIN
    value: str = ""
    discovered_at: str = field(default_factory=utcnow_iso, kw_only=True)
    first_seen: str = field(default_factory=utcnow_iso, kw_only=True)
    last_seen: str = field(default_factory=utcnow_iso, kw_only=True)
    status: IntelligenceTargetStatus = IntelligenceTargetStatus.ACTIVE
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    phase: IntelligencePhase = IntelligencePhase.DISCOVERY
    intelligence_state: dict[str, Any] = field(default_factory=dict)
    coverage_state: dict[str, float] = field(default_factory=dict)
    tenant: str = ""
    analysis_version: str = ANALYSIS_VERSION

    def __post_init__(self) -> None:
        if not self.value and not self.identity:
            raise ValueError("intelligence target requires a value or identity")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("intelligence target confidence must be in [0, 1]")
        object.__setattr__(self, "kind", _coerce_enum(IntelligenceTargetKind, self.kind, IntelligenceTargetKind.DOMAIN))
        object.__setattr__(
            self,
            "status",
            _coerce_enum(IntelligenceTargetStatus, self.status, IntelligenceTargetStatus.ACTIVE),
        )
        object.__setattr__(self, "phase", _coerce_enum(IntelligencePhase, self.phase, IntelligencePhase.DISCOVERY))

    @property
    def key(self) -> str:
        """Return the canonical scope key (``kind:value``)."""
        return f"{self.kind.value}:{self.value}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "scope": self.scope,
            "identity": self.identity,
            "classification": self.classification,
            "criticality": self.criticality,
            "kind": self.kind.value,
            "value": self.value,
            "key": self.key,
            "discovered_at": self.discovered_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status.value,
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
            "phase": self.phase.value,
            "intelligence_state": dict(self.intelligence_state),
            "coverage_state": dict(self.coverage_state),
            "tenant": self.tenant,
            "analysis_version": self.analysis_version,
        }


# ==========================================================================
# 2. ASSET MODEL
# ==========================================================================


@dataclass(frozen=True, slots=True)
class IntelligenceAsset:
    """A discovered asset represented independently from the target.

    Assets are canonical graph nodes (subdomain, ip, port, service, url,
    endpoint, parameter, api, graphql, certificate, cloud resource, ...). They
    reuse the topology :class:`EntityKind` vocabulary so the target
    intelligence graph composes with the attack-surface topology.

    Attributes:
        asset_id: stable asset identifier.
        target_id: owning target.
        mission_id: owning mission.
        kind: :class:`EntityKind`.
        name: canonical asset value.
        key: canonical node key (``kind:name``).
        label: human label.
        properties: free-form attributes.
        confidence: asset confidence in ``[0, 1]``.
        in_scope: whether the asset falls inside the authorized scope.
        source: provenance label (tool or ``tidb``).
        first_seen / last_seen: state-time observation stamps.
        parent_key: canonical key of the parent asset when known.
        observed_by: tools that observed the asset.

    """

    asset_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    kind: EntityKind | str = EntityKind.ASSET
    name: str = ""
    key: str = ""
    label: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    in_scope: bool = True
    source: str = ""
    first_seen: str = field(default_factory=utcnow_iso, kw_only=True)
    last_seen: str = field(default_factory=utcnow_iso, kw_only=True)
    parent_key: str = ""
    observed_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        kind = self.kind.value if isinstance(self.kind, EntityKind) else str(self.kind)
        if not self.key:
            from hunterx.domain.topology.keys import entity_key

            object.__setattr__(self, "key", entity_key(kind, self.name or self.label))
        if not self.name:
            object.__setattr__(self, "name", self.label)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("asset confidence must be in [0, 1]")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "asset_id": self.asset_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "kind": self.kind.value if isinstance(self.kind, EntityKind) else str(self.kind),
            "name": self.name,
            "key": self.key,
            "label": self.label,
            "properties": dict(self.properties),
            "confidence": self.confidence,
            "in_scope": self.in_scope,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "parent_key": self.parent_key,
            "observed_by": list(self.observed_by),
        }


# ==========================================================================
# 3. OBSERVATION MODEL
# ==========================================================================


@dataclass(frozen=True, slots=True)
class Observation:
    """An immutable, provenance-carrying intelligence observation.

    Observations answer "what did we learn?". They are immutable: corrections
    produce new observations that supersede older ones. Every observation
    retains provenance back to the tool, capability, raw artifact and scope.

    Attributes:
        observation_id: stable observation identifier.
        target_id: owning target.
        mission_id: owning mission.
        tool: producing tool id.
        tool_version: producing tool version.
        capability: canonical capability id (see CoverageCapability).
        timestamp: UTC ISO-8601 observation stamp.
        observation_type: :class:`ObservationType`.
        value: the observed value.
        normalized_value: canonical normalized value.
        confidence: observation confidence in ``[0, 1]``.
        source: source label (tool/parser/normalizer).
        provenance: provenance metadata map.
        scope: scope the observation was collected under.
        raw_artifact_ref: reference to the preserved raw output.
        evidence_ref: reference to persisted evidence when captured.
        expires_at: UTC ISO-8601 expiry (``None`` = no expiry).
        first_seen / last_seen: state-time stamps.
        asset_key: canonical key of the related asset (``""`` when not linked).
        dedup_key: stable deduplication key.
        supersedes: observation id this observation corrects (``""`` when new).

    """

    observation_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    tool: str = ""
    tool_version: str = ""
    capability: str = ""
    timestamp: str = field(default_factory=utcnow_iso, kw_only=True)
    observation_type: ObservationType = ObservationType.OTHER
    value: str = ""
    normalized_value: str = ""
    confidence: float = 1.0
    source: str = ""
    provenance: dict[str, str] = field(default_factory=dict)
    scope: str = ""
    raw_artifact_ref: str = ""
    evidence_ref: str = ""
    expires_at: str | None = None
    first_seen: str = field(default_factory=utcnow_iso, kw_only=True)
    last_seen: str = field(default_factory=utcnow_iso, kw_only=True)
    asset_key: str = ""
    dedup_key: str = ""
    supersedes: str = ""

    def __post_init__(self) -> None:
        if not self.dedup_key:
            object.__setattr__(
                self,
                "dedup_key",
                observation_key(
                    target_id=self.target_id,
                    tool=self.tool,
                    observation_type=self.observation_type.value,
                    value=self.value,
                ),
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("observation confidence must be in [0, 1]")
        object.__setattr__(
            self,
            "observation_type",
            _coerce_enum(ObservationType, self.observation_type, ObservationType.OTHER),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "observation_id": self.observation_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "capability": self.capability,
            "timestamp": self.timestamp,
            "observation_type": self.observation_type.value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "confidence": self.confidence,
            "source": self.source,
            "provenance": dict(self.provenance),
            "scope": self.scope,
            "raw_artifact_ref": self.raw_artifact_ref,
            "evidence_ref": self.evidence_ref,
            "expires_at": self.expires_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "asset_key": self.asset_key,
            "dedup_key": self.dedup_key,
            "supersedes": self.supersedes,
        }


# ==========================================================================
# 4. EVIDENCE MODEL
# ==========================================================================


@dataclass(frozen=True, slots=True)
class IntelligenceEvidence:
    """Evidence answering WHAT, WHERE, WHEN, HOW, SOURCE, WHY_TRUST and REPRODUCIBILITY.

    Evidence retains provenance back to the tool, the command/configuration,
    the raw artifact, the parser version, the normalizer version, the target
    and the mission so validation and proof can be replayed.

    Attributes:
        evidence_id: stable evidence identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        what: what was observed.
        where: where it was observed (URL/host/resource).
        when: when it was observed (UTC ISO-8601).
        how: how it was observed (capability + method).
        source: producing tool/component.
        why_trust: explanation of why the evidence is trustworthy.
        reproducibility: reproducibility label.
        tool / tool_version: producing tool and version.
        command_configuration: structured command/configuration snapshot.
        raw_artifact_ref: reference to the preserved raw artifact.
        parser_version / normalizer_version: parsing pipeline versions.
        confidence: evidence confidence in ``[0, 1]``.
        created_at: UTC ISO-8601 creation stamp.

    """

    evidence_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    what: str = ""
    where: str = ""
    when: str = ""
    how: str = ""
    source: str = ""
    why_trust: str = ""
    reproducibility: str = "not_assessed"
    tool: str = ""
    tool_version: str = ""
    command_configuration: dict[str, Any] = field(default_factory=dict)
    raw_artifact_ref: str = ""
    parser_version: str = ""
    normalizer_version: str = ""
    confidence: float = 1.0
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)

    def __post_init__(self) -> None:
        if not self.what:
            raise ValueError("evidence requires a 'what' description")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("evidence confidence must be in [0, 1]")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "evidence_id": self.evidence_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "what": self.what,
            "where": self.where,
            "when": self.when,
            "how": self.how,
            "source": self.source,
            "why_trust": self.why_trust,
            "reproducibility": self.reproducibility,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "command_configuration": dict(self.command_configuration),
            "raw_artifact_ref": self.raw_artifact_ref,
            "parser_version": self.parser_version,
            "normalizer_version": self.normalizer_version,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }


# ==========================================================================
# 7. TARGET HISTORY & CHANGE DETECTION
# ==========================================================================


@dataclass(frozen=True, slots=True)
class TargetHistoryEntry:
    """A point-in-time fact in the target's historical state.

    Attributes:
        history_id: stable history identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key (``""`` for target-level facts).
        attribute: the field that changed (e.g. ``asset``, ``technology``).
        kind: :class:`ChangeKind`.
        previous_value: prior canonical value (JSON-ish).
        new_value: new canonical value (JSON-ish).
        source: provenance label.
        confidence: confidence of the new value.
        changed_at: UTC ISO-8601 change stamp.
        correlation_id: producing run correlation id.

    """

    history_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    attribute: str = ""
    kind: ChangeKind = ChangeKind.NEW
    previous_value: str = ""
    new_value: str = ""
    source: str = ""
    confidence: float = 1.0
    changed_at: str = field(default_factory=utcnow_iso, kw_only=True)
    correlation_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _coerce_enum(ChangeKind, self.kind, ChangeKind.NEW))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "history_id": self.history_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "attribute": self.attribute,
            "kind": self.kind.value,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "source": self.source,
            "confidence": self.confidence,
            "changed_at": self.changed_at,
            "correlation_id": self.correlation_id,
        }


@dataclass(frozen=True, slots=True)
class IntelligenceChange:
    """A detected change in the target's intelligence state.

    Changes influence future mission planning: a newly discovered subdomain or
    a changed technology re-opens discovery/analysis actions.

    Attributes:
        change_id: stable change identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        kind: :class:`ChangeKind`.
        previous: prior state map (JSON-safe).
        current: new state map (JSON-safe).
        source: provenance label.
        confidence: confidence of the change.
        detected_at: UTC ISO-8601 detection stamp.

    """

    change_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    kind: ChangeKind = ChangeKind.NEW
    previous: dict[str, Any] = field(default_factory=dict)
    current: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    confidence: float = 1.0
    detected_at: str = field(default_factory=utcnow_iso, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _coerce_enum(ChangeKind, self.kind, ChangeKind.NEW))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "change_id": self.change_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "kind": self.kind.value,
            "previous": dict(self.previous),
            "current": dict(self.current),
            "source": self.source,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
        }


# ==========================================================================
# 10. COVERAGE MATRIX
# ==========================================================================


@dataclass(frozen=True, slots=True)
class CoverageEntry:
    """A single (asset, capability) cell of the coverage matrix.

    Attributes:
        target_id: owning target.
        asset_key: canonical asset key (``""`` for target-level cells).
        capability: :class:`CoverageCapability`.
        state: :class:`CoverageState`.
        tool: tool that last exercised the capability.
        confidence: confidence of the recorded state.
        tested_at: UTC ISO-8601 test stamp.
        evidence_refs: evidence references supporting the cell.
        notes: free-form notes (e.g. negative-result conditions).
        record_id: stable coverage record id.

    """

    target_id: str
    asset_key: str
    capability: CoverageCapability
    state: CoverageState = CoverageState.NOT_ASSESSED
    tool: str = ""
    confidence: float = 0.0
    tested_at: str = ""
    evidence_refs: tuple[str, ...] = ()
    notes: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        if isinstance(self.capability, str):
            object.__setattr__(self, "capability", CoverageCapability(self.capability))
        if isinstance(self.state, str):
            object.__setattr__(self, "state", CoverageState(self.state))

    @property
    def cell_key(self) -> str:
        """Return the stable cell key (``asset|capability``)."""
        return f"{self.asset_key}|{self.capability.value}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "record_id": self.record_id,
            "target_id": self.target_id,
            "asset_key": self.asset_key,
            "capability": self.capability.value,
            "state": self.state.value,
            "tool": self.tool,
            "confidence": self.confidence,
            "tested_at": self.tested_at,
            "evidence_refs": list(self.evidence_refs),
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class CoverageMatrix:
    """The machine-readable coverage matrix: Target × Asset × Capability × Tool × State.

    Attributes:
        target_id: owning target.
        entries: all coverage cells for the target.
        updated_at: UTC ISO-8601 last-update stamp.

    """

    target_id: str
    entries: tuple[CoverageEntry, ...] = ()
    updated_at: str = field(default_factory=utcnow_iso, kw_only=True)
    _index_cache: dict[str, CoverageEntry] | None = field(default=None, init=False, repr=False, compare=False)

    def _index(self) -> dict[str, CoverageEntry]:
        cache = self._index_cache
        if cache is None:
            cache = {entry.cell_key: entry for entry in self.entries}
            object.__setattr__(self, "_index_cache", cache)
        return cache

    def state(self, asset_key: str, capability: CoverageCapability | str) -> CoverageState:
        """Return the coverage state of a cell (``NOT_ASSESSED`` when absent)."""
        if isinstance(capability, str):
            capability = CoverageCapability(capability)
        return self._index().get(f"{asset_key}|{capability.value}", CoverageEntry(
            target_id=self.target_id, asset_key=asset_key, capability=capability
        )).state

    def cell(self, asset_key: str, capability: CoverageCapability | str) -> CoverageEntry | None:
        """Return the coverage cell or ``None``."""
        if isinstance(capability, str):
            capability = CoverageCapability(capability)
        return self._index().get(f"{asset_key}|{capability.value}")

    def assets(self) -> tuple[str, ...]:
        """Return the sorted set of asset keys in the matrix."""
        return tuple(sorted({entry.asset_key for entry in self.entries}))

    def capabilities(self) -> tuple[CoverageCapability, ...]:
        """Return the sorted set of capabilities in the matrix."""
        return tuple(sorted({entry.capability for entry in self.entries}, key=lambda c: c.value))

    def by_asset(self, asset_key: str) -> tuple[CoverageEntry, ...]:
        """Return the coverage cells of one asset."""
        return tuple(sorted(
            (entry for entry in self.entries if entry.asset_key == asset_key),
            key=lambda e: e.capability.value,
        ))

    def by_capability(self, capability: CoverageCapability | str) -> tuple[CoverageEntry, ...]:
        """Return the coverage cells of one capability."""
        if isinstance(capability, str):
            capability = CoverageCapability(capability)
        return tuple(entry for entry in self.entries if entry.capability is capability)

    def uncovered(self, capability: CoverageCapability | str | None = None) -> tuple[CoverageEntry, ...]:
        """Return cells that still need action (UNKNOWN/NOT_ASSESSED/CANDIDATE)."""
        cells = self.entries
        if capability is not None:
            cells = self.by_capability(capability)
        return tuple(entry for entry in cells if entry.state.uncovered())

    def coverage_ratio(self, capability: CoverageCapability | str | None = None) -> float:
        """Return the fraction of cells in a terminal assessed state in ``[0, 1]``."""
        cells = self.entries
        if capability is not None:
            cells = self.by_capability(capability)
        if not cells:
            return 0.0
        assessed = sum(1 for entry in cells if not entry.state.uncovered())
        return round(assessed / len(cells), 4)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "target_id": self.target_id,
            "updated_at": self.updated_at,
            "assets": list(self.assets()),
            "capabilities": [c.value for c in self.capabilities()],
            "coverage_ratio": self.coverage_ratio(),
            "entries": [entry.to_dict() for entry in self.entries],
        }


# ==========================================================================
# 12. INFORMATION GAPS
# ==========================================================================


@dataclass(frozen=True, slots=True)
class InformationGap:
    """A concrete, actionable information gap.

    Each unknown becomes an :class:`InformationGap` that carries the question,
    its importance, the capability required to close it and candidate tools, so
    the next-action engine can select the smallest justified tool set.

    Attributes:
        gap_id: stable gap identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key (``""`` for target-level gaps).
        category: :class:`InformationGapCategory`.
        question: the concrete question to answer.
        importance: importance in ``[0, 1]``.
        confidence: confidence that the gap is real in ``[0, 1]``.
        required_capability: :class:`CoverageCapability` required.
        candidate_tools: candidate tool ids.
        estimated_cost: estimated execution cost.
        risk: risk label of closing the gap.
        blocking: whether the gap blocks dependent analysis.
        created_at: UTC ISO-8601 creation stamp.

    """

    gap_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    category: InformationGapCategory = InformationGapCategory.ASSET_DISCOVERY
    question: str = ""
    importance: float = 0.5
    confidence: float = 0.5
    required_capability: CoverageCapability = CoverageCapability.ASSET_DISCOVERY
    candidate_tools: tuple[str, ...] = ()
    estimated_cost: float = 0.0
    risk: str = "passive"
    blocking: bool = False
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "category",
            _coerce_enum(InformationGapCategory, self.category, InformationGapCategory.ASSET_DISCOVERY),
        )
        object.__setattr__(
            self,
            "required_capability",
            _coerce_enum(CoverageCapability, self.required_capability, CoverageCapability.ASSET_DISCOVERY),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "gap_id": self.gap_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "category": self.category.value,
            "question": self.question,
            "importance": self.importance,
            "confidence": self.confidence,
            "required_capability": self.required_capability.value,
            "candidate_tools": list(self.candidate_tools),
            "estimated_cost": self.estimated_cost,
            "risk": self.risk,
            "blocking": self.blocking,
            "created_at": self.created_at,
        }


# ==========================================================================
# 15. HYPOTHESIS MODEL
# ==========================================================================


@dataclass(frozen=True, slots=True)
class Hypothesis:
    """A conjecture to validate — never a conclusion.

    Attributes:
        hypothesis_id: stable hypothesis identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        category: :class:`HypothesisType`.
        statement: the concrete conjecture.
        supporting_observations: observation ids that support it.
        contradicting_observations: observation ids that contradict it.
        required_evidence: evidence kinds required for validation.
        validation_strategy: how to validate (capability/tool family).
        proof_strategy: proof strategy id (Sprint 021/022).
        confidence: current confidence in ``[0, 1]``.
        priority: priority in ``[0, 1]``.
        status: :class:`HypothesisStatus`.
        created_at / updated_at: UTC ISO-8601 stamps.
        provenance: provenance metadata map.

    """

    hypothesis_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    category: HypothesisType = HypothesisType.UNKNOWN_BEHAVIOR
    statement: str = ""
    supporting_observations: tuple[str, ...] = ()
    contradicting_observations: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    validation_strategy: str = ""
    proof_strategy: str = ""
    confidence: float = 0.0
    priority: float = 0.0
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)
    updated_at: str = field(default_factory=utcnow_iso, kw_only=True)
    provenance: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.statement:
            raise ValueError("hypothesis requires a statement")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("hypothesis confidence must be in [0, 1]")
        if not 0.0 <= self.priority <= 1.0:
            raise ValueError("hypothesis priority must be in [0, 1]")
        object.__setattr__(
            self,
            "category",
            _coerce_enum(HypothesisType, self.category, HypothesisType.UNKNOWN_BEHAVIOR),
        )
        object.__setattr__(self, "status", _coerce_enum(HypothesisStatus, self.status, HypothesisStatus.PROPOSED))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "category": self.category.value,
            "statement": self.statement,
            "supporting_observations": list(self.supporting_observations),
            "contradicting_observations": list(self.contradicting_observations),
            "required_evidence": list(self.required_evidence),
            "validation_strategy": self.validation_strategy,
            "proof_strategy": self.proof_strategy,
            "confidence": self.confidence,
            "priority": self.priority,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provenance": dict(self.provenance),
        }


# ==========================================================================
# 17. ACTION MODEL
# ==========================================================================


@dataclass(frozen=True, slots=True)
class IntelligenceAction:
    """A proposed next action produced by the next-action engine.

    Every action is explainable: it carries the objective, target, asset,
    required capability, selected tool, reason, expected information gain,
    expected evidence, cost, risk, scope status, preconditions, stop
    conditions, fallback and priority.

    Attributes:
        action_id: stable action identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        objective: what the action accomplishes.
        action_type: :class:`ActionType`.
        required_capability: :class:`CoverageCapability` required.
        tool: selected tool id (``""`` when undecided).
        reason: human-readable justification.
        expected_information_gain: expected gain in ``[0, 1]``.
        expected_evidence: evidence kinds the action should produce.
        estimated_cost: estimated execution cost.
        risk: risk label.
        scope_status: scope status of the action.
        preconditions: preconditions that must hold.
        stop_conditions: :class:`StopCondition` values.
        fallback: fallback action/description.
        priority: ranking priority in ``[0, 1]`` (higher = sooner).
        status: :class:`ActionStatus`.
        decision_id: producing decision id (``""`` when direct).
        candidates: alternative tool ids considered.
        created_at: UTC ISO-8601 creation stamp.

    """

    action_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    objective: str = ""
    action_type: ActionType = ActionType.DISCOVER
    required_capability: CoverageCapability = CoverageCapability.ASSET_DISCOVERY
    tool: str = ""
    reason: str = ""
    expected_information_gain: float = 0.0
    expected_evidence: tuple[str, ...] = ()
    estimated_cost: float = 0.0
    risk: str = "passive"
    scope_status: str = "in_scope"
    preconditions: tuple[str, ...] = ()
    stop_conditions: tuple[StopCondition, ...] = ()
    fallback: str = ""
    priority: float = 0.0
    status: ActionStatus = ActionStatus.PROPOSED
    decision_id: str = ""
    candidates: tuple[str, ...] = ()
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)

    def __post_init__(self) -> None:
        if not self.objective:
            raise ValueError("action requires an objective")
        if not 0.0 <= self.priority <= 1.0:
            raise ValueError("action priority must be in [0, 1]")
        object.__setattr__(self, "action_type", _coerce_enum(ActionType, self.action_type, ActionType.DISCOVER))
        object.__setattr__(
            self,
            "required_capability",
            _coerce_enum(CoverageCapability, self.required_capability, CoverageCapability.ASSET_DISCOVERY),
        )
        object.__setattr__(self, "status", _coerce_enum(ActionStatus, self.status, ActionStatus.PROPOSED))
        coerced_stops = tuple(
            _coerce_enum(StopCondition, item, item) if isinstance(item, str) else item for item in self.stop_conditions
        )
        object.__setattr__(self, "stop_conditions", coerced_stops)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "action_id": self.action_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "objective": self.objective,
            "action_type": self.action_type.value,
            "required_capability": self.required_capability.value,
            "tool": self.tool,
            "reason": self.reason,
            "expected_information_gain": self.expected_information_gain,
            "expected_evidence": list(self.expected_evidence),
            "estimated_cost": self.estimated_cost,
            "risk": self.risk,
            "scope_status": self.scope_status,
            "preconditions": list(self.preconditions),
            "stop_conditions": [s.value for s in self.stop_conditions],
            "fallback": self.fallback,
            "priority": self.priority,
            "status": self.status.value,
            "decision_id": self.decision_id,
            "candidates": list(self.candidates),
            "created_at": self.created_at,
        }


# ==========================================================================
# 36. EXPLAINABLE DECISIONS
# ==========================================================================


@dataclass(frozen=True, slots=True)
class IntelligenceDecision:
    """An explainable adaptive decision.

    Attributes:
        decision_id: stable decision identifier.
        target_id: owning target.
        mission_id: owning mission.
        kind: decision kind (``next-action``, ``tool-selection``, ``stop``...).
        payload: decision payload (JSON-safe).
        rationale: ordered reasons for the decision.
        evidence: evidence references used.
        alternatives: alternatives considered and rejected.
        why_alternatives_rejected: reasons alternatives were rejected.
        policy_applied: policy ids applied to the decision.
        created_at: UTC ISO-8601 creation stamp.
        ai_assisted: whether AI contributed (advisory only).
        ai_overridden: whether AI was overridden by policy.

    """

    decision_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    kind: str = "next-action"
    payload: dict[str, Any] = field(default_factory=dict)
    rationale: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()
    why_alternatives_rejected: tuple[str, ...] = ()
    policy_applied: tuple[str, ...] = ()
    created_at: str = field(default_factory=utcnow_iso, kw_only=True)
    ai_assisted: bool = False
    ai_overridden: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "decision_id": self.decision_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "kind": self.kind,
            "payload": dict(self.payload),
            "rationale": list(self.rationale),
            "evidence": list(self.evidence),
            "alternatives": list(self.alternatives),
            "why_alternatives_rejected": list(self.why_alternatives_rejected),
            "policy_applied": list(self.policy_applied),
            "created_at": self.created_at,
            "ai_assisted": self.ai_assisted,
            "ai_overridden": self.ai_overridden,
        }


# ==========================================================================
# 25. NEGATIVE KNOWLEDGE
# ==========================================================================


@dataclass(frozen=True, slots=True)
class NegativeResult:
    """A carefully-scoped negative result.

    ``Tool A found no SQLi`` means *Tool A produced no SQLi evidence under its
    test conditions* — it never means *SQLi does not exist*. Negative results
    record the capability, tool, scope, conditions, coverage and confidence so
    the semantics stay precise.

    Attributes:
        result_id: stable result identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        tested_capability: :class:`CoverageCapability` tested.
        tool: tool that produced the negative result.
        scope: scope under which the test ran.
        conditions: recorded test conditions.
        coverage: what the test actually covered.
        result: ``"no_evidence"`` or ``"not_vulnerable"`` (scoped).
        confidence: confidence in ``[0, 1]``.
        tested_at: UTC ISO-8601 test stamp.

    """

    result_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    tested_capability: CoverageCapability = CoverageCapability.VULNERABILITY_SCANNING
    tool: str = ""
    scope: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)
    coverage: str = ""
    result: str = "no_evidence"
    confidence: float = 0.5
    tested_at: str = field(default_factory=utcnow_iso, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "tested_capability",
            _coerce_enum(CoverageCapability, self.tested_capability, CoverageCapability.VULNERABILITY_SCANNING),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "result_id": self.result_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "tested_capability": self.tested_capability.value,
            "tool": self.tool,
            "scope": self.scope,
            "conditions": dict(self.conditions),
            "coverage": self.coverage,
            "result": self.result,
            "confidence": self.confidence,
            "tested_at": self.tested_at,
        }


# ==========================================================================
# 26. CONFLICTS
# ==========================================================================


@dataclass(frozen=True, slots=True)
class IntelligenceConflict:
    """A preserved contradiction between observations/tools.

    Conflicting tool results are never averaged — the conflict is preserved and
    triggers additional validation or higher-quality evidence collection.

    Attributes:
        conflict_id: stable conflict identifier.
        target_id: owning target.
        mission_id: owning mission.
        asset_key: related asset key.
        capability: capability the conflict concerns.
        observations: the disagreeing observations.
        tools: the tools that disagree.
        state: :class:`ConflictState`.
        resolution: resolution note (``""`` while open).
        detected_at: UTC ISO-8601 detection stamp.
        resolved_at: UTC ISO-8601 resolution stamp (``None`` while open).

    """

    conflict_id: str = field(default_factory=generate_id, kw_only=True)
    target_id: str = ""
    mission_id: str = ""
    asset_key: str = ""
    capability: CoverageCapability = CoverageCapability.VULNERABILITY_SCANNING
    observations: tuple[dict[str, Any], ...] = ()
    tools: tuple[str, ...] = ()
    state: ConflictState = ConflictState.OPEN
    resolution: str = ""
    detected_at: str = field(default_factory=utcnow_iso, kw_only=True)
    resolved_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "capability",
            _coerce_enum(CoverageCapability, self.capability, CoverageCapability.VULNERABILITY_SCANNING),
        )
        object.__setattr__(self, "state", _coerce_enum(ConflictState, self.state, ConflictState.OPEN))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "conflict_id": self.conflict_id,
            "target_id": self.target_id,
            "mission_id": self.mission_id,
            "asset_key": self.asset_key,
            "capability": self.capability.value,
            "observations": [dict(o) for o in self.observations],
            "tools": list(self.tools),
            "state": self.state.value,
            "resolution": self.resolution,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
        }


# ==========================================================================
# 29. INTELLIGENCE SCORE
# ==========================================================================


@dataclass(frozen=True, slots=True)
class IntelligenceScore:
    """An explainable multi-dimension intelligence score.

    Scores are never a single opaque number: each :class:`IntelligenceDimension`
    is reported, and the aggregate is a weighted combination whose weights are
    recorded for explainability.

    Attributes:
        target_id: owning target.
        dimensions: dimension → score in ``[0, 1]``.
        aggregate: overall score in ``[0, 1]``.
        weights: dimension → weight (records explainability).
        computed_at: UTC ISO-8601 computation stamp.
        policy_id: ranking/weight policy id applied.

    """

    target_id: str
    dimensions: dict[str, float] = field(default_factory=dict)
    aggregate: float = 0.0
    weights: dict[str, float] = field(default_factory=dict)
    computed_at: str = field(default_factory=utcnow_iso, kw_only=True)
    policy_id: str = DEFAULT_RANKING_POLICY_ID

    def explainable(self) -> dict[str, Any]:
        """Return an explainable breakdown of the score."""
        return {
            "target_id": self.target_id,
            "aggregate": round(self.aggregate, 4),
            "policy_id": self.policy_id,
            "weights": {k: round(v, 4) for k, v in self.weights.items()},
            "dimensions": {k: round(v, 4) for k, v in self.dimensions.items()},
            "computed_at": self.computed_at,
        }


# ==========================================================================
# TARGET INTELLIGENCE STATE
# ==========================================================================


@dataclass(frozen=True, slots=True)
class TargetIntelligenceState:
    """A point-in-time snapshot of everything known about a target.

    The state is a read-mostly aggregate; high-volume stores (observations,
    evidence) are referenced by summary rather than embedded so the in-memory
    footprint stays bounded.

    Attributes:
        target: the :class:`IntelligenceTarget`.
        assets: known assets.
        coverage: :class:`CoverageMatrix`.
        gaps: open information gaps.
        hypotheses: open hypotheses.
        evidence_count / observation_count: store sizes.
        negative_results: recorded negative results.
        conflicts: open conflicts.
        history: recent history entries.
        score: :class:`IntelligenceScore`.
        updated_at: UTC ISO-8601 stamp.

    """

    target: IntelligenceTarget
    assets: tuple[IntelligenceAsset, ...] = ()
    coverage: CoverageMatrix = field(default_factory=lambda: CoverageMatrix(target_id=""))
    gaps: tuple[InformationGap, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    observation_count: int = 0
    evidence_count: int = 0
    negative_results: tuple[NegativeResult, ...] = ()
    conflicts: tuple[IntelligenceConflict, ...] = ()
    history: tuple[TargetHistoryEntry, ...] = ()
    score: IntelligenceScore | None = None
    updated_at: str = field(default_factory=utcnow_iso, kw_only=True)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "target": self.target.to_dict(),
            "assets": [asset.to_dict() for asset in self.assets],
            "coverage": self.coverage.to_dict(),
            "gaps": [gap.to_dict() for gap in self.gaps],
            "hypotheses": [hypothesis.to_dict() for hypothesis in self.hypotheses],
            "observation_count": self.observation_count,
            "evidence_count": self.evidence_count,
            "negative_results": [negative.to_dict() for negative in self.negative_results],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "history": [entry.to_dict() for entry in self.history],
            "score": self.score.explainable() if self.score is not None else None,
            "updated_at": self.updated_at,
        }


__all__ = [
    "ANALYSIS_VERSION",
    "ASSET_KEY_PREFIX",
    "CoverageEntry",
    "CoverageMatrix",
    "DEFAULT_RANKING_POLICY_ID",
    "Hypothesis",
    "InformationGap",
    "IntelligenceAction",
    "IntelligenceAsset",
    "IntelligenceChange",
    "IntelligenceConflict",
    "IntelligenceDecision",
    "IntelligenceEvidence",
    "IntelligenceScore",
    "IntelligenceTarget",
    "NegativeResult",
    "OBSERVATION_KEY_PREFIX",
    "Observation",
    "TargetHistoryEntry",
    "TargetIntelligenceState",
    "observation_key",
]
