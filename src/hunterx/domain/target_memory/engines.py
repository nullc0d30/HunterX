# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Memory & Campaign Intelligence — pure domain engines.

Sprint 030. Deterministic, I/O-free engines that assemble, classify, diff and
reason about historical target memory. Engines never read or write storage and
never execute tools: they produce classified state and advisory
recommendations that the application layer persists and the mission planner
consumes.

Design rules enforced here:

* Determinism — the same snapshot pair always yields the same diff.
* No overwrite — contradictions and stale observations are preserved.
* Memory is untrusted — confidence, source reliability, corroboration and
  freshness always gate what memory is allowed to redefine.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from hunterx.domain.target_memory.enums import (
    ChangeSignificance,
    CoverageGapKind,
    DiffChangeKind,
    FreshnessState,
    HypothesisOutcome,
    MemoryContradictionState,
    MemoryObservationState,
    RecurrenceKind,
    RevalidationPriority,
    RiskLevel,
)
from hunterx.domain.target_memory.models import (
    Campaign,
    CampaignIntelligence,
    CoverageGap,
    FindingMemory,
    FindingRecurrence,
    MemoryContradiction,
    MemoryObservation,
    NextActionRecommendation,
    RevalidationItem,
    RevalidationPlan,
    TargetChange,
    TargetDiff,
    TargetMemory,
    TargetRiskEntry,
    TargetSnapshot,
    memory_observation_key,
)
from hunterx.shared.time import to_utc_datetime, utcnow_iso


@runtime_checkable
class RawObservation(Protocol):
    """Structural contract for observations the memory layer can ingest.

    Matches the ``Observation`` model of Target Intelligence (Sprint 026) and
    any other provenance-carrying observation producer without forcing a
    dependency between domain packages.
    """

    target_id: str
    mission_id: str
    timestamp: str
    observation_type: str
    value: str
    normalized_value: str
    tool: str
    source: str
    confidence: float
    asset_key: str
    expires_at: str | None


def _field(observation: RawObservation | dict[str, Any], name: str, default: Any = "") -> Any:
    """Read a field from an attribute-based or mapping-based observation."""
    if isinstance(observation, dict):
        return observation.get(name, default)
    return getattr(observation, name, default)


#: Default freshness window (seconds) per observation type. ``0``/absent means
#: the observation is a persistent historical record that never expires on its
#: own (for example historical findings).
_DEFAULT_FRESHNESS_SECONDS: dict[str, int] = {
    "dns_record": 6 * 3600,
    "host": 6 * 3600,
    "ip": 6 * 3600,
    "port": 12 * 3600,
    "service": 24 * 3600,
    "technology": 7 * 24 * 3600,
    "url": 24 * 3600,
    "endpoint": 24 * 3600,
    "parameter": 24 * 3600,
    "cloud_resource": 6 * 3600,
    "secret": 4 * 3600,
    "certificate": 7 * 24 * 3600,
    "saas": 12 * 3600,
    "asset": 24 * 3600,
    "subdomain": 24 * 3600,
}

#: Sentinel for "persistent record" (never auto-expires).
_PERSISTENT = 0

#: Observation types that elevate revalidation priority.
_HIGH_RISK_TYPES = frozenset({"secret", "cloud_resource", "authentication_surface", "endpoint"})


class ObservationFreshnessEngine:
    """Classify observation freshness against per-type policies.

    Freshness is configurable by observation type: DNS/IP are short-lived,
    technology fingerprints moderate, historical findings persistent, cloud
    configuration short.
    """

    def __init__(self, policies: dict[str, int] | None = None) -> None:
        """Initialize the engine with optional per-type TTL policies (seconds)."""
        merged = dict(_DEFAULT_FRESHNESS_SECONDS)
        if policies:
            merged.update(policies)
        self._policies = merged

    def ttl_for(self, observation_type: str) -> int:
        """Return the freshness window (seconds) for an observation type."""
        return self._policies.get(observation_type, _PERSISTENT)

    def classify(self, observation_type: str, last_seen: str, now: str | None = None, *, expires_at: str | None = None) -> FreshnessState:
        """Classify an observation's freshness at ``now``.

        Args:
            observation_type: observation type string.
            last_seen: UTC ISO-8601 last-observation stamp.
            now: reference time; defaults to the current time.
            expires_at: optional explicit expiry stamp that overrides the
                type-level policy.

        """
        reference = to_utc_datetime(now)
        seen = to_utc_datetime(last_seen)
        age_seconds = max(0.0, (reference - seen).total_seconds())

        if expires_at:
            if reference >= to_utc_datetime(expires_at):
                return FreshnessState.EXPIRED
            return FreshnessState.FRESH

        ttl = self.ttl_for(observation_type)
        if ttl <= _PERSISTENT:
            return FreshnessState.FRESH
        if age_seconds < ttl * 0.8:
            return FreshnessState.FRESH
        if age_seconds < ttl:
            return FreshnessState.AGING
        if age_seconds < ttl * 2:
            return FreshnessState.STALE
        return FreshnessState.EXPIRED


class TargetMemoryAssembler:
    """Assemble memory observations from raw observations.

    Aggregates every raw observation sharing a canonical key into a single
    :class:`MemoryObservation` with first/last seen tracking, first/last
    mission and source, an observation count, and a classified current state.
    """

    def __init__(
        self,
        *,
        freshness: ObservationFreshnessEngine | None = None,
        now: str | None = None,
    ) -> None:
        """Initialize the assembler with an optional freshness engine."""
        self._freshness = freshness or ObservationFreshnessEngine()
        self._now = now or utcnow_iso()

    def assemble(self, observations: Sequence[RawObservation]) -> list[MemoryObservation]:
        """Aggregate raw observations into memory observations.

        Records are ordered by their canonical key for deterministic output.
        """
        grouped: dict[str, list[RawObservation]] = defaultdict(list)
        for observation in observations:
            key = memory_observation_key(
                str(_field(observation, "observation_type")),
                str(_field(observation, "normalized_value") or _field(observation, "value")),
            )
            grouped[key].append(observation)

        result: list[MemoryObservation] = []
        for key in sorted(grouped):
            result.append(self._assemble_key(key, grouped[key]))
        return result

    def _assemble_key(self, key: str, items: list[RawObservation]) -> MemoryObservation:
        ordered = sorted(items, key=lambda obs: to_utc_datetime(str(_field(obs, "timestamp"))))
        first = ordered[0]
        latest = ordered[-1]
        last_mission = str(_field(latest, "mission_id"))
        last_source = str(_field(latest, "source"))

        observation_type = str(_field(first, "observation_type"))
        freshness = self._freshness.classify(
            observation_type,
            str(_field(latest, "timestamp")),
            now=self._now,
            expires_at=_field(latest, "expires_at", None),
        )
        current_state = self._state_from_freshness(freshness, _field(latest, "expires_at", None))
        confidence = min(1.0, max(0.0, sum(float(_field(o, "confidence", 1.0)) for o in ordered) / len(ordered)))

        return MemoryObservation(
            observation_key=key,
            target_id=str(_field(first, "target_id")),
            observation_type=observation_type,
            value=str(_field(first, "value")),
            normalized_value=str(_field(first, "normalized_value") or _field(first, "value")),
            first_seen=str(_field(first, "timestamp")),
            last_seen=str(_field(latest, "timestamp")),
            observation_count=len(ordered),
            first_mission=str(_field(first, "mission_id")),
            last_mission=last_mission,
            first_source=str(_field(first, "source")),
            last_source=last_source,
            current_state=current_state,
            freshness=freshness,
            mission_id=last_mission,
            asset_key=str(_field(latest, "asset_key")),
            tool=str(_field(latest, "tool")),
            confidence=confidence,
            expires_at=_field(latest, "expires_at", None),
        )

    @staticmethod
    def _state_from_freshness(freshness: FreshnessState, expires_at: str | None) -> MemoryObservationState:
        if freshness in (FreshnessState.STALE, FreshnessState.EXPIRED) or expires_at:
            return MemoryObservationState.NEEDS_REVALIDATION
        if freshness == FreshnessState.UNKNOWN:
            return MemoryObservationState.UNKNOWN
        return MemoryObservationState.KNOWN_CURRENT


class TargetDiffEngine:
    """Compute a deterministic diff between two target snapshots.

    The same snapshot pair always yields the same diff: every comparison
    iterates over sorted canonical keys and the output is ordered. The
    optional ``baseline`` snapshot distinguishes ``REAPPEARED`` (present in
    the baseline, absent in A, present in B) from plain ``ADDED``.
    """

    def diff(self, snapshot_a: TargetSnapshot, snapshot_b: TargetSnapshot, *, baseline: TargetSnapshot | None = None) -> TargetDiff:
        """Return the deterministic diff between two snapshots.

        Args:
            snapshot_a: base snapshot.
            snapshot_b: later snapshot.
            baseline: optional earlier snapshot used to detect reappearance.

        """
        state_a = snapshot_a.state
        state_b = snapshot_b.state
        prior_keys = set((baseline.state or {}).get("observations", {}).keys()) if baseline else set()

        observations_a = _section(state_a, "observations")
        observations_b = _section(state_b, "observations")
        findings_a = _section(state_a, "findings")
        findings_b = _section(state_b, "findings")

        changes: list[TargetChange] = []

        all_obs_keys = sorted(set(observations_a) | set(observations_b))
        for key in all_obs_keys:
            changes.append(self._diff_observation(key, observations_a, observations_b, prior_keys))

        all_finding_keys = sorted(set(findings_a) | set(findings_b))
        for key in all_finding_keys:
            changes.append(self._diff_finding(key, findings_a, findings_b))

        return TargetDiff(
            target_id=snapshot_b.target_id,
            snapshot_a_id=snapshot_a.snapshot_id,
            snapshot_b_id=snapshot_b.snapshot_id,
            state_hash_a=snapshot_a.state_hash,
            state_hash_b=snapshot_b.state_hash,
            changes=tuple(changes),
            deterministic=True,
        )

    @staticmethod
    def _diff_observation(
        key: str,
        observations_a: dict[str, Any],
        observations_b: dict[str, Any],
        prior_keys: set[str],
    ) -> TargetChange:
        if key not in observations_a and key in observations_b:
            if key in prior_keys:
                return TargetChange(
                    key=key,
                    kind=DiffChangeKind.REAPPEARED,
                    field="observation",
                    current=_value(observations_b[key]),
                    description=f"observation {key} reappeared",
                )
            return TargetChange(
                key=key,
                kind=DiffChangeKind.ADDED,
                field="observation",
                current=_value(observations_b[key]),
                description=f"observation {key} appeared",
            )
        if key in observations_a and key not in observations_b:
            kind = DiffChangeKind.DISAPPEARED if key in prior_keys else DiffChangeKind.REMOVED
            return TargetChange(
                key=key,
                kind=kind,
                field="observation",
                previous=_value(observations_a[key]),
                description=f"observation {key} no longer present",
            )
        value_a = _value(observations_a[key])
        value_b = _value(observations_b[key])
        if value_a != value_b:
            return TargetChange(
                key=key,
                kind=DiffChangeKind.CHANGED,
                field="observation",
                previous=value_a,
                current=value_b,
                description=f"observation {key} changed",
            )
        return TargetChange(key=key, kind=DiffChangeKind.UNCHANGED, field="observation", current=value_b)

    @staticmethod
    def _diff_finding(key: str, findings_a: dict[str, Any], findings_b: dict[str, Any]) -> TargetChange:
        if key not in findings_a and key in findings_b:
            return TargetChange(
                key=key,
                kind=DiffChangeKind.ADDED,
                field="finding",
                current=_value(findings_b[key]),
                description=f"finding {key} appeared",
            )
        if key in findings_a and key not in findings_b:
            return TargetChange(
                key=key,
                kind=DiffChangeKind.REMOVED,
                field="finding",
                previous=_value(findings_a[key]),
                description=f"finding {key} no longer present",
            )
        status_a = _finding_status(findings_a[key])
        status_b = _finding_status(findings_b[key])
        value_a = _value(findings_a[key])
        value_b = _value(findings_b[key])
        if status_a != status_b:
            if _is_open(status_b) and not _is_open(status_a):
                return TargetChange(
                    key=key,
                    kind=DiffChangeKind.REOPENED,
                    field="finding.status",
                    previous=status_a,
                    current=status_b,
                    description=f"finding {key} reopened",
                )
            if _is_open(status_a) and not _is_open(status_b):
                return TargetChange(
                    key=key,
                    kind=DiffChangeKind.REMEDIATED,
                    field="finding.status",
                    previous=status_a,
                    current=status_b,
                    description=f"finding {key} remediated",
                )
        if value_a != value_b:
            return TargetChange(
                key=key,
                kind=DiffChangeKind.CHANGED,
                field="finding",
                previous=value_a,
                current=value_b,
                description=f"finding {key} changed",
            )
        return TargetChange(key=key, kind=DiffChangeKind.UNCHANGED, field="finding", current=value_b)


def _section(state: dict[str, Any], name: str) -> dict[str, Any]:
    section = state.get(name, {})
    return dict(section) if isinstance(section, dict) else {}


def _value(record: Any) -> Any:
    if isinstance(record, dict):
        return record.get("value", record.get("status", record))
    return record


def _finding_status(record: Any) -> str:
    if isinstance(record, dict):
        return str(record.get("remediation_state", record.get("status", "")))
    return str(record)


def _is_open(status: str) -> bool:
    return status in {"open", "reopened", "candidate", "validating", "validated", "proved", "report_ready"}


class ChangeSignificanceEngine:
    """Classify the significance of a target change.

    Severity stays evidence-backed: the classified significance is always
    capped by the confidence of the evidence backing the change.
    """

    _CRITICAL_MARKERS = ("secret", "credential", "token", "password", "api_key", "private_key")
    _HIGH_MARKERS = ("admin", "identity", "authentication_surface", "auth_surface")

    def classify(self, change: TargetChange) -> ChangeSignificance:
        """Return the significance class of a change."""
        haystack = f"{change.key} {change.asset_key} {change.field} {change.current} {change.previous}".lower()

        if any(marker in haystack for marker in self._CRITICAL_MARKERS):
            significance = ChangeSignificance.CRITICAL
        elif change.kind == DiffChangeKind.REOPENED or any(marker in haystack for marker in self._HIGH_MARKERS):
            significance = ChangeSignificance.HIGH
        elif change.kind in (DiffChangeKind.ADDED, DiffChangeKind.REAPPEARED, DiffChangeKind.CHANGED):
            if "endpoint" in change.key or "admin" in haystack:
                significance = ChangeSignificance.HIGH
            elif "service" in change.key or "port" in change.key:
                significance = ChangeSignificance.MEDIUM
            elif "subdomain" in change.key or "url:" in change.key:
                significance = ChangeSignificance.LOW
            else:
                significance = ChangeSignificance.MEDIUM
        elif change.kind in (DiffChangeKind.REMOVED, DiffChangeKind.DISAPPEARED):
            significance = ChangeSignificance.LOW
        else:
            significance = ChangeSignificance.INFORMATIONAL

        return self._cap_by_confidence(significance, change.confidence)

    @staticmethod
    def _cap_by_confidence(significance: ChangeSignificance, confidence: float) -> ChangeSignificance:
        confidence = max(0.0, min(1.0, confidence))
        if confidence < 0.5 and significance.rank > ChangeSignificance.LOW.rank:
            return ChangeSignificance.LOW
        if confidence < 0.75 and significance.rank > ChangeSignificance.MEDIUM.rank:
            return ChangeSignificance.MEDIUM
        return significance


class RevalidationPlanner:
    """Build a prioritized revalidation plan from target memory.

    High-risk, high-change, stale, contradicted, previously-unstable and
    security-sensitive observations are prioritized.
    """

    def __init__(self, freshness: ObservationFreshnessEngine | None = None) -> None:
        """Initialize the planner with an optional freshness engine."""
        self._freshness = freshness or ObservationFreshnessEngine()

    def plan(self, memory: TargetMemory, *, now: str | None = None) -> RevalidationPlan:
        """Return the prioritized revalidation plan for a target."""
        reference = now or utcnow_iso()
        items: list[RevalidationItem] = []
        for observation in sorted(memory.observations.values(), key=lambda obs: obs.observation_key):
            freshness = self._freshness.classify(
                observation.observation_type,
                observation.last_seen,
                now=reference,
                expires_at=observation.expires_at,
            )
            if freshness not in (FreshnessState.STALE, FreshnessState.EXPIRED) and not observation.expires_at:
                continue
            priority = self._priority(observation, freshness)
            items.append(
                RevalidationItem(
                    observation_key=observation.observation_key,
                    target_id=observation.target_id,
                    asset_key=observation.asset_key,
                    observation_type=observation.observation_type,
                    freshness=freshness,
                    last_seen=observation.last_seen,
                    reason=self._reason(observation, freshness),
                    priority=priority,
                )
            )
        items.sort(key=lambda item: (-item.priority.rank, item.observation_key))
        return RevalidationPlan(target_id=memory.target_id, items=tuple(items))

    @staticmethod
    def _priority(observation: MemoryObservation, freshness: FreshnessState) -> RevalidationPriority:
        if observation.current_state == MemoryObservationState.CONTRADICTED:
            return RevalidationPriority.HIGH
        if observation.observation_type in _HIGH_RISK_TYPES or freshness == FreshnessState.EXPIRED:
            return RevalidationPriority.HIGH
        if freshness == FreshnessState.STALE:
            return RevalidationPriority.MEDIUM
        return RevalidationPriority.LOW

    @staticmethod
    def _reason(observation: MemoryObservation, freshness: FreshnessState) -> str:
        if observation.current_state == MemoryObservationState.CONTRADICTED:
            return "contradicted by preserved observations; requires higher-quality evidence"
        return f"observation {freshness.value}; last seen {observation.last_seen}"


class CoverageGapEngine:
    """Detect concrete coverage gaps from memory observations and coverage.

    Coverage cells are keyed ``asset_key::capability``; a missing cell for a
    known asset is a gap. Distinct gap kinds are produced for untested assets,
    new assets, stale observations, authentication surfaces and cloud
    resources.
    """

    _AUTH_TYPES = frozenset({"authentication_surface", "auth_surface", "auth_endpoint"})
    _CLOUD_TYPES = frozenset({"cloud_resource", "saas", "cloud_identity"})

    def detect(
        self,
        *,
        target_id: str,
        campaign_id: str = "",
        observations: Sequence[MemoryObservation],
        coverage: dict[str, str],
        now: str | None = None,
    ) -> list[CoverageGap]:
        """Return coverage gaps for the given observations and coverage cells."""
        reference = to_utc_datetime(now or utcnow_iso())
        gaps: list[CoverageGap] = []
        by_asset: dict[str, list[MemoryObservation]] = defaultdict(list)
        for observation in observations:
            by_asset[observation.asset_key or observation.observation_key].append(observation)

        for asset_key in sorted(by_asset):
            asset_observations = by_asset[asset_key]
            covered = any(f"{asset_key}::{cap}" in coverage for cap in ("asset_discovery", "port_discovery", "endpoint_enumeration", "technology_fingerprint", "service_detection"))
            first_seen = min((to_utc_datetime(obs.first_seen) for obs in asset_observations), default=reference)
            is_new = (reference - first_seen).total_seconds() < 24 * 3600

            stale = any(obs.freshness in (FreshnessState.STALE, FreshnessState.EXPIRED) or obs.expires_at for obs in asset_observations)
            if stale:
                gaps.append(self._gap(target_id, campaign_id, asset_key, "", CoverageGapKind.STALE_OBSERVATION, "observation(s) require revalidation"))
            if not covered and is_new:
                gaps.append(self._gap(target_id, campaign_id, asset_key, "", CoverageGapKind.NEW_ASSET, "new asset never assessed"))
            if not covered and not is_new:
                gaps.append(self._gap(target_id, campaign_id, asset_key, "", CoverageGapKind.DISCOVERED_UNTESTED, "discovered but untested"))
            for observation in asset_observations:
                if observation.observation_type in self._AUTH_TYPES and f"{asset_key}::authentication_analysis" not in coverage:
                    gaps.append(self._gap(target_id, campaign_id, asset_key, "authentication_analysis", CoverageGapKind.UNTESTED_AUTH, "authenticated surface never tested"))
                if observation.observation_type in self._CLOUD_TYPES and f"{asset_key}::cloud_ownership_mapping" not in coverage:
                    gaps.append(self._gap(target_id, campaign_id, asset_key, "cloud_ownership_mapping", CoverageGapKind.UNVALIDATED_CONFIG, "cloud resource without configuration validation"))
        return gaps

    @staticmethod
    def _gap(target_id: str, campaign_id: str, asset_key: str, capability: str, kind: CoverageGapKind, description: str) -> CoverageGap:
        return CoverageGap(
            target_id=target_id,
            campaign_id=campaign_id,
            asset_key=asset_key,
            capability=capability,
            kind=kind,
            description=description,
        )


class FindingRecurrenceDetector:
    """Detect recurrences of previously remediated vulnerabilities.

    Recognizes the same root-cause family at a new location (potential
    regression) and same-location regressions of a previously closed finding.
    """

    def detect(self, findings: Sequence[FindingMemory]) -> list[FindingRecurrence]:
        """Return recurrences detected across the given finding memories."""
        recurrences: list[FindingRecurrence] = []
        closed: dict[tuple[str, str], list[FindingMemory]] = defaultdict(list)
        for finding in findings:
            if finding.remediation_state in {"closed", "fix_verified", "resolved"}:
                closed[(finding.vulnerability_class, finding.root_cause)].append(finding)

        for finding in findings:
            if finding.remediation_state in {"open", "reopened", "candidate"}:
                for prior in closed.get((finding.vulnerability_class, finding.root_cause), []):
                    same_location = self._shares_location(finding, prior)
                    recurrences.append(
                        FindingRecurrence(
                            target_id=finding.target_id,
                            original_finding_id=prior.finding_id,
                            new_finding_id=finding.finding_id,
                            vulnerability_class=finding.vulnerability_class,
                            root_cause=finding.root_cause or finding.vulnerability_class,
                            previous_location=self._location(prior),
                            new_location=self._location(finding),
                            kind=RecurrenceKind.SAME_LOCATION if same_location else RecurrenceKind.NEW_LOCATION,
                            confidence=0.7 if same_location else 0.55,
                        )
                    )
            if finding.reopened_count > 0 and finding.remediation_state == "reopened":
                recurrences.append(
                    FindingRecurrence(
                        target_id=finding.target_id,
                        original_finding_id=finding.finding_id,
                        new_finding_id=finding.finding_id,
                        vulnerability_class=finding.vulnerability_class,
                        root_cause=finding.root_cause or finding.vulnerability_class,
                        previous_location=self._location(finding),
                        new_location=self._location(finding),
                        kind=RecurrenceKind.ROOT_CAUSE_REGRESSION,
                        confidence=0.8,
                    )
                )
        return recurrences

    @staticmethod
    def _shares_location(finding: FindingMemory, prior: FindingMemory) -> bool:
        current = set(finding.affected_endpoints)
        previous = set(prior.affected_endpoints)
        return bool(current & previous)

    @staticmethod
    def _location(finding: FindingMemory) -> str:
        return finding.affected_endpoints[0] if finding.affected_endpoints else finding.affected_assets[0] if finding.affected_assets else ""


class ContradictionDetector:
    """Detect and preserve contradictions between observations.

    Both sides of a contradiction are preserved; the current state is
    classified (never averaged, never silently overwritten).
    """

    def detect(self, observations: Sequence[RawObservation]) -> list[MemoryContradiction]:
        """Return preserved contradictions among the given observations.

        Contradictions occur when observations share an observation type but
        disagree on the canonical value.
        """
        by_type: dict[str, list[RawObservation]] = defaultdict(list)
        for observation in observations:
            by_type[str(_field(observation, "observation_type"))].append(observation)

        contradictions: list[MemoryContradiction] = []
        for observation_type in sorted(by_type):
            by_value: dict[str, list[RawObservation]] = defaultdict(list)
            for observation in by_type[observation_type]:
                by_value[str(_field(observation, "normalized_value") or _field(observation, "value"))].append(observation)
            if len(by_value) < 2:
                continue
            all_items = [obs for group in by_value.values() for obs in group]
            contradictions.append(
                MemoryContradiction(
                    target_id=str(_field(all_items[0], "target_id")),
                    asset_key=str(_field(all_items[0], "asset_key")),
                    observation_key=memory_observation_key(observation_type, "?"),
                    observations=[
                        {
                            "observation_type": str(_field(obs, "observation_type")),
                            "value": str(_field(obs, "value")),
                            "normalized_value": str(_field(obs, "normalized_value")),
                            "tool": str(_field(obs, "tool")),
                            "source": str(_field(obs, "source")),
                            "timestamp": str(_field(obs, "timestamp")),
                        }
                        for obs in sorted(all_items, key=lambda obs: str(_field(obs, "timestamp")))
                    ],
                    tools=sorted({str(_field(obs, "tool")) for obs in all_items}),
                    state=MemoryContradictionState.OPEN,
                )
            )
        return contradictions


class MemoryConfidenceEngine:
    """Compute and gate the confidence of memory items.

    Confidence combines the observation confidence, source reliability,
    freshness, corroboration count and contradiction state. Memory poisoning
    defense: low-confidence or contradicted items may never silently redefine
    target state.
    """

    _RELIABILITY_WEIGHT = {
        "high": 1.0,
        "verified": 1.0,
        "medium": 0.85,
        "low": 0.6,
        "unverified": 0.4,
        "unknown": 0.5,
    }

    def evaluate(self, observation: MemoryObservation) -> float:
        """Return the effective confidence of a memory observation in ``[0, 1]``."""
        base = max(0.0, min(1.0, observation.confidence))
        reliability = self._RELIABILITY_WEIGHT.get(observation.source_reliability, 0.5)
        freshness_factor = 1.0 - 0.3 * (observation.freshness.value in ("stale", "expired"))
        corroboration = min(1.0, 0.6 + 0.2 * max(0, observation.corroboration_count - 1))
        if observation.contradiction_state == MemoryContradictionState.OPEN.value:
            contradiction_factor = 0.4
        elif observation.contradiction_state == MemoryContradictionState.RESOLVED.value:
            contradiction_factor = 0.8
        else:
            contradiction_factor = 1.0
        return round(base * reliability * freshness_factor * corroboration * contradiction_factor, 4)

    def is_poisoned(self, observation: MemoryObservation, *, threshold: float = 0.35) -> bool:
        """Return ``True`` when the observation is too untrusted to redefine state."""
        return self.evaluate(observation) < threshold


class NextActionRecommender:
    """Derive advisory next-action recommendations from target memory.

    Recommendations are advisory only: the mission planner decides execution.
    """

    def recommend(self, memory: TargetMemory, *, campaign_id: str = "") -> list[NextActionRecommendation]:
        """Return prioritized next-action recommendations for a target."""
        recommendations: list[NextActionRecommendation] = []

        for gap in memory.gaps:
            recommendations.append(
                NextActionRecommendation(
                    target_id=memory.target_id,
                    campaign_id=campaign_id,
                    action="test",
                    reason=f"coverage gap: {gap.description} ({gap.asset_key})",
                    priority=gap.significance,
                    required_tool_capabilities=[gap.capability] if gap.capability else [],
                    evidence_required=["validation_evidence"],
                    expected_outcome="close the coverage gap and record a negative or validated result",
                    historical_context=[f"gap kind: {gap.kind.value}"],
                )
            )

        for observation in memory.observations.values():
            if observation.current_state == MemoryObservationState.CONTRADICTED:
                recommendations.append(
                    NextActionRecommendation(
                        target_id=memory.target_id,
                        campaign_id=campaign_id,
                        action="revalidate",
                        reason=f"contradicted observation {observation.observation_key} requires higher-quality evidence",
                        priority=ChangeSignificance.HIGH,
                        required_tool_capabilities=[self._capability_for(observation.observation_type)],
                        evidence_required=["contradiction_resolution"],
                        expected_outcome="resolve or preserve the contradiction with corroborated evidence",
                        historical_context=[f"observed by: {observation.tool}", f"first seen: {observation.first_seen}"],
                    )
                )
            elif observation.freshness in ("stale", "expired") or observation.expires_at:
                recommendations.append(
                    NextActionRecommendation(
                        target_id=memory.target_id,
                        campaign_id=campaign_id,
                        action="revalidate",
                        reason=f"observation {observation.observation_key} is {observation.freshness.value}",
                        priority=ChangeSignificance.MEDIUM,
                        required_tool_capabilities=[self._capability_for(observation.observation_type)],
                        evidence_required=["observation_evidence"],
                        expected_outcome="refresh the observation or confirm it is unchanged",
                        historical_context=[f"last seen: {observation.last_seen}"],
                    )
                )

        for finding in memory.findings.values():
            if finding.remediation_state in {"open", "reopened", "candidate"}:
                recommendations.append(
                    NextActionRecommendation(
                        target_id=memory.target_id,
                        campaign_id=campaign_id,
                        action="validate",
                        reason=f"open finding {finding.title} requires validation or revalidation",
                        priority=ChangeSignificance.HIGH,
                        required_tool_capabilities=[finding.vulnerability_class or "vulnerability_scanning"],
                        evidence_required=["validation_evidence", "proof_evidence"],
                        expected_outcome="validate the finding and move it toward report-ready",
                        historical_context=[f"first detected: {finding.first_detected}", f"root cause: {finding.root_cause or 'unassigned'}"],
                    )
                )

        recommendations.sort(key=lambda rec: (-rec.priority.rank, rec.reason))
        return recommendations

    @staticmethod
    def _capability_for(observation_type: str) -> str:
        mapping = {
            "secret": "secret_detection",
            "cloud_resource": "cloud_ownership_mapping",
            "authentication_surface": "authentication_analysis",
            "endpoint": "endpoint_enumeration",
            "technology": "technology_fingerprint",
            "service": "service_detection",
            "port": "port_discovery",
            "dns_record": "dns_enumeration",
        }
        return mapping.get(observation_type, "asset_discovery")


class CampaignIntelligenceEngine:
    """Answer the campaign intelligence questions.

    What changed, was discovered, was validated, remains untested, failed,
    was fixed, regressed, and what should be tested next.
    """

    def analyze(
        self,
        *,
        campaign: Campaign,
        diffs: Sequence[TargetDiff] = (),
        findings: Sequence[FindingMemory] = (),
        gaps: Sequence[CoverageGap] = (),
        hypotheses: Sequence[Any] = (),
        recurrences: Sequence[FindingRecurrence] = (),
        memory: TargetMemory | None = None,
    ) -> CampaignIntelligence:
        """Return the campaign intelligence summary."""
        changed: list[dict[str, Any]] = []
        for diff in diffs:
            for change in diff.changes:
                if change.kind != DiffChangeKind.UNCHANGED:
                    changed.append(
                        {
                            "key": change.key,
                            "kind": change.kind.value,
                            "significance": change.significance.value,
                            "target_id": diff.target_id,
                        }
                    )

        discovered = [finding.finding_id for finding in findings if not finding.first_validated]
        validated = [finding.finding_id for finding in findings if finding.first_validated]
        untested = [gap.asset_key or gap.description for gap in gaps if gap.status == "open"]
        failed = [getattr(h, "hypothesis_id", "") or str(h) for h in hypotheses if getattr(h, "outcome", HypothesisOutcome.INCONCLUSIVE) == HypothesisOutcome.FAILED]
        fixed = [finding.finding_id for finding in findings if finding.remediation_state in {"closed", "fix_verified", "resolved"}]
        regressed = [rec.new_finding_id for rec in recurrences]
        next_actions = list(memory.recommendations) if memory is not None else []

        return CampaignIntelligence(
            campaign_id=campaign.campaign_id,
            changed=changed,
            discovered=discovered,
            validated=validated,
            untested=untested,
            failed=failed,
            fixed=fixed,
            regressed=regressed,
            next=next_actions,
        )


class TargetRiskEvaluator:
    """Derive point-in-time risk from memory and findings.

    Risk history is append-only: this engine produces a *new* entry that
    references the previous level; it never mutates historical entries.
    """

    def evaluate(
        self,
        *,
        target_id: str,
        campaign_id: str,
        mission_id: str,
        findings: Sequence[FindingMemory],
        changes: Sequence[TargetChange],
        previous: RiskLevel | None = None,
    ) -> TargetRiskEntry:
        """Return a new risk entry derived from current findings and changes."""
        severity_rank = 0
        for finding in findings:
            if finding.remediation_state in {"open", "reopened", "candidate"}:
                severity_rank = max(severity_rank, {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(finding.severity, 0))

        has_critical_change = any(change.significance == ChangeSignificance.CRITICAL for change in changes)
        has_high_change = any(change.significance in (ChangeSignificance.HIGH, ChangeSignificance.CRITICAL) for change in changes)

        if severity_rank >= 4 or has_critical_change:
            level = RiskLevel.CRITICAL
        elif severity_rank == 3 or has_high_change:
            level = RiskLevel.HIGH
        elif severity_rank == 2:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        reason_parts: list[str] = []
        if severity_rank >= 3:
            reason_parts.append(f"open finding severity rank {severity_rank}")
        if has_critical_change:
            reason_parts.append("critical change detected")
        elif has_high_change:
            reason_parts.append("high-severity change detected")
        reason = "; ".join(reason_parts) or "no elevated risk signals"

        return TargetRiskEntry(
            target_id=target_id,
            campaign_id=campaign_id,
            mission_id=mission_id,
            risk_level=level,
            previous_risk_level=previous,
            reason=reason,
            driving_changes=[f"{change.key}:{change.kind.value}" for change in changes if change.significance.rank >= ChangeSignificance.MEDIUM.rank],
        )


@dataclass(frozen=True, slots=True)
class PlannerContext:
    """Memory input handed to the mission planner.

    The planner receives the known state, unknown state, stale state, changed
    state, coverage gaps, previous failures and successes, and risk priorities
    — never raw tool output.
    """

    target_id: str
    known_state: list[dict[str, Any]] = field(default_factory=list)
    unknown_state: list[str] = field(default_factory=list)
    stale_state: list[dict[str, Any]] = field(default_factory=list)
    changed_state: list[dict[str, Any]] = field(default_factory=list)
    coverage_gaps: list[dict[str, Any]] = field(default_factory=list)
    previous_failures: list[str] = field(default_factory=list)
    previous_successes: list[str] = field(default_factory=list)
    risk_priorities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "target_id": self.target_id,
            "known_state": list(self.known_state),
            "unknown_state": list(self.unknown_state),
            "stale_state": list(self.stale_state),
            "changed_state": list(self.changed_state),
            "coverage_gaps": list(self.coverage_gaps),
            "previous_failures": list(self.previous_failures),
            "previous_successes": list(self.previous_successes),
            "risk_priorities": list(self.risk_priorities),
        }


class MemoryAwarePlannerContextBuilder:
    """Build the memory-aware planning context for a target.

    Integrates Target Memory with Mission Planning through a port-style plain
    object: the planner receives classified state and previous results, never
    historical raw data.
    """

    def build(
        self,
        memory: TargetMemory,
        *,
        failed_hypotheses: Sequence[Any] = (),
        successful_hypotheses: Sequence[Any] = (),
    ) -> PlannerContext:
        """Return the planner context for the given target memory."""
        known = [obs.to_dict() for obs in memory.observations.values() if obs.current_state == MemoryObservationState.KNOWN_CURRENT]
        stale = [obs.to_dict() for obs in memory.observations.values() if obs.current_state in (MemoryObservationState.KNOWN_STALE, MemoryObservationState.NEEDS_REVALIDATION)]
        changed = [obs.to_dict() for obs in memory.observations.values() if obs.current_state == MemoryObservationState.KNOWN_CHANGED]
        unknown = [f"{obs.observation_type}:{obs.observation_key}" for obs in memory.observations.values() if obs.current_state == MemoryObservationState.UNKNOWN]
        gaps = [gap.to_dict() for gap in memory.gaps]
        failures = [getattr(h, "hypothesis_id", "") or str(h) for h in failed_hypotheses]
        successes = [getattr(h, "hypothesis_id", "") or str(h) for h in successful_hypotheses]
        risk_priorities = [rec.to_dict()["action"] for rec in memory.recommendations[:10]]

        return PlannerContext(
            target_id=memory.target_id,
            known_state=known,
            unknown_state=unknown,
            stale_state=stale,
            changed_state=changed,
            coverage_gaps=gaps,
            previous_failures=failures,
            previous_successes=successes,
            risk_priorities=risk_priorities,
        )


def build_memory(observations: Sequence[RawObservation], *, freshness: ObservationFreshnessEngine | None = None, now: str | None = None) -> TargetMemory:
    """Assemble a :class:`TargetMemory` from raw observations."""
    assembler = TargetMemoryAssembler(freshness=freshness, now=now)
    target_id = str(_field(observations[0], "target_id")) if observations else ""
    memory = TargetMemory(target_id=target_id)
    for observation in assembler.assemble(observations):
        memory.observations[observation.observation_key] = observation
    return memory


__all__ = [
    "CampaignIntelligenceEngine",
    "ChangeSignificanceEngine",
    "ContradictionDetector",
    "CoverageGapEngine",
    "FindingRecurrenceDetector",
    "MemoryAwarePlannerContextBuilder",
    "MemoryConfidenceEngine",
    "NextActionRecommender",
    "ObservationFreshnessEngine",
    "PlannerContext",
    "RevalidationPlanner",
    "TargetDiffEngine",
    "TargetMemoryAssembler",
    "TargetRiskEvaluator",
    "build_memory",
]
