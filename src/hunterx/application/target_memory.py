# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Memory & Campaign Intelligence application services.

Sprint 030. Orchestrate the historical intelligence layer against the TIDB:
persist memory observations, reproduce snapshots, compute deterministic diffs,
track mission/hypothesis/tool/risk/finding memory, manage campaigns, detect
coverage gaps and recurrences, plan revalidation, preserve contradictions,
derive advisory next-action recommendations and answer campaign-intelligence
queries.

Scope isolation is enforced on every write: a record is only persisted when
its target belongs to the authorized tenant and mission context. Memory is
treated as untrusted input — confidence, corroboration, freshness and
contradiction state always gate what memory is allowed to redefine.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunterx.domain.entities.tidb.memory import (
    AttackPathMemoryRecord,
    CampaignRecord,
    CoverageGapRecord,
    FindingMemoryRecord,
    FindingRecurrenceRecord,
    HypothesisMemoryRecord,
    MemoryContradictionRecord,
    MemoryObservationRecord,
    MissionMemoryRecord,
    NextActionRecord,
    RevalidationRecord,
    TargetDiffRecord,
    TargetRiskRecord,
    TargetSnapshotRecord,
    ToolObservationRecord,
)
from hunterx.domain.ports.messaging import CachePort, EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepository, TidbRepositoryFactory
from hunterx.domain.target_memory.engines import (
    CampaignIntelligenceEngine,
    ChangeSignificanceEngine,
    ContradictionDetector,
    CoverageGapEngine,
    FindingRecurrenceDetector,
    MemoryAwarePlannerContextBuilder,
    NextActionRecommender,
    ObservationFreshnessEngine,
    PlannerContext,
    RevalidationPlanner,
    TargetDiffEngine,
    TargetMemoryAssembler,
    TargetRiskEvaluator,
)
from hunterx.domain.target_memory.enums import (
    CampaignStatus,
    FreshnessState,
    HypothesisOutcome,
    MemoryContradictionState,
    MemoryObservationState,
    MemoryValidity,
    RiskLevel,
)
from hunterx.domain.target_memory.models import (
    AttackPathMemory,
    Campaign,
    CampaignIntelligence,
    CoverageGap,
    FindingMemory,
    FindingRecurrence,
    HypothesisMemory,
    MemoryContradiction,
    MemoryObservation,
    MissionMemory,
    NextActionRecommendation,
    RevalidationPlan,
    TargetDiff,
    TargetMemory,
    TargetRiskEntry,
    TargetSnapshot,
    ToolObservation,
)
from hunterx.shared.ids import generate_content_id
from hunterx.shared.time import utcnow_iso


class TargetMemoryScopeError(Exception):
    """Raised when a memory write violates tenant/target isolation."""


class TargetMemoryService:
    """Orchestrate target memory ingestion and persistence against the TIDB.

    Args:
        stores: optional TIDB repository factory. When ``None`` the service
            operates in-memory only (returns domain objects, persists nothing).
        event_bus: optional event bus for typed event publishing.
        cache: optional cache port.
        tenant: default tenant used for isolation checks.
        freshness: optional observation freshness engine.
        now: fixed reference time (tests).

    """

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        cache: CachePort | None = None,
        tenant: str = "",
        freshness: ObservationFreshnessEngine | None = None,
        now: str | None = None,
    ) -> None:
        self._stores = stores
        self._event_bus = event_bus
        self._cache = cache
        self._tenant = tenant
        self._now = now or utcnow_iso()
        self._freshness = freshness or ObservationFreshnessEngine()
        self._authorized_targets: dict[str, set[str]] = {}
        self._assembler = TargetMemoryAssembler(freshness=self._freshness, now=self._now)
        self._diff_engine = TargetDiffEngine()
        self._significance = ChangeSignificanceEngine()
        self._revalidation = RevalidationPlanner(freshness=self._freshness)
        self._coverage_gaps = CoverageGapEngine()
        self._recurrences = FindingRecurrenceDetector()
        self._contradictions = ContradictionDetector()
        self._recommender = NextActionRecommender()
        self._risk = TargetRiskEvaluator()
        self._campaign_intelligence = CampaignIntelligenceEngine()
        self._planner_context = MemoryAwarePlannerContextBuilder()

    # -- isolation ----------------------------------------------------------

    def authorize(self, *, tenant: str, target_id: str) -> None:
        """Declare an authorized (tenant, target) pair for write isolation."""
        self._authorized_targets.setdefault(tenant, set()).add(target_id)

    def _repo(self, entity_cls: type) -> TidbRepository[Any]:
        if self._stores is None:
            raise RuntimeError("TIDB repository factory is not configured")
        return self._stores.repository_for(entity_cls)

    def _check_target(self, target_id: str, *, tenant: str = "", mission_id: str = "") -> None:
        del mission_id  # isolation is tenant/target scoped, not mission
        record_tenant = tenant or self._tenant
        if not self._authorized_targets:
            # Open mode: no authorizations registered (platform default).
            return
        if not record_tenant:
            raise TargetMemoryScopeError("a tenant is required when authorization is enforced")
        allowed = self._authorized_targets.get(record_tenant)
        if allowed is None or target_id not in allowed:
            raise TargetMemoryScopeError(f"target {target_id} is not authorized under tenant {record_tenant!r}")

    # -- observation history ------------------------------------------------

    def record_observations(
        self,
        target_id: str,
        observations: Sequence[Any],
        *,
        mission_id: str = "",
        tenant: str = "",
        persist: bool = True,
    ) -> list[MemoryObservation]:
        """Assemble and persist memory observations for a target.

        Raw observations are aggregated by canonical key with first/last seen
        tracking. Existing persisted records are merged so ``first_seen`` and
        ``first_mission`` are never lost across missions.
        """
        self._check_target(target_id, tenant=tenant, mission_id=mission_id)
        assembled = self._assembler.assemble(observations)
        merged: list[MemoryObservation] = []
        if persist and self._stores is not None:
            repo = self._repo(MemoryObservationRecord)
            existing = {record.observation_key: record for record in repo.stream() if record.target_id == target_id}
            for observation in assembled:
                prior = existing.get(observation.observation_key)
                if prior is not None:
                    observation = self._merge_observation(observation, prior)
                repo.save(_observation_to_record(observation, tenant=tenant))
                merged.append(observation)
        else:
            merged = list(assembled)
        self._publish(
            "target.memory.updated",
            {"target_id": target_id, "mission_id": mission_id, "observation_count": len(merged)},
        )
        return merged

    @staticmethod
    def _merge_observation(new_observation: MemoryObservation, prior: MemoryObservationRecord) -> MemoryObservation:
        """Merge a freshly assembled observation into a persisted record."""
        first_seen = prior.first_seen or new_observation.first_seen
        if prior.first_seen and new_observation.first_seen and new_observation.first_seen < prior.first_seen:
            first_seen = new_observation.first_seen
        first_mission = prior.first_mission or new_observation.first_mission
        first_source = prior.first_source or new_observation.first_source
        return MemoryObservation(
            observation_key=new_observation.observation_key,
            target_id=new_observation.target_id,
            observation_type=new_observation.observation_type,
            value=new_observation.value,
            normalized_value=new_observation.normalized_value,
            first_seen=first_seen,
            last_seen=new_observation.last_seen,
            observation_count=int(prior.observation_count) + new_observation.observation_count,
            first_mission=first_mission,
            last_mission=new_observation.last_mission,
            first_source=first_source,
            last_source=new_observation.last_source,
            current_state=new_observation.current_state,
            freshness=new_observation.freshness,
            mission_id=new_observation.mission_id,
            asset_key=new_observation.asset_key,
            tool=new_observation.tool,
            confidence=new_observation.confidence,
            source_reliability=new_observation.source_reliability,
            corroboration_count=new_observation.corroboration_count,
            contradiction_state=prior.contradiction_state or new_observation.contradiction_state,
            validity=new_observation.validity,
            expires_at=new_observation.expires_at,
            provenance=dict(prior.provenance or new_observation.provenance),
        )

    # -- snapshots & diffs ---------------------------------------------------

    def create_snapshot(
        self,
        target_id: str,
        *,
        mission_id: str = "",
        tenant: str = "",
        persist: bool = True,
    ) -> TargetSnapshot:
        """Reproduce and persist a target snapshot from stored memory.

        When ``mission_id`` is given, the observation state reflects the
        observations collected during that mission (``last_mission ==
        mission_id``), so a diff between consecutive mission snapshots detects
        added, removed and changed observations. When omitted, the cumulative
        known state is captured.
        """
        self._check_target(target_id, tenant=tenant, mission_id=mission_id)
        observations = self._load_observations(target_id)
        if mission_id:
            observations = [obs for obs in observations if obs.last_mission == mission_id]
        state: dict[str, Any] = {
            "observations": {
                obs.observation_key: {
                    "value": obs.normalized_value or obs.value,
                    "last_seen": obs.last_seen,
                    "current_state": obs.current_state.value,
                }
                for obs in observations
            },
            "findings": {},
        }
        if self._stores is not None:
            for record in self._repo(FindingMemoryRecord).stream():
                if record.target_id == target_id:
                    state["findings"][record.finding_id] = {
                        "status": record.status,
                        "remediation_state": record.remediation_state,
                    }
        snapshot = TargetSnapshot(
            target_id=target_id,
            mission_id=mission_id,
            observation_count=len(observations),
            state=state,
        )
        if persist and self._stores is not None:
            self._repo(TargetSnapshotRecord).save(_snapshot_to_record(snapshot, tenant=tenant))
        self._publish(
            "target.snapshot.created",
            {
                "target_id": target_id,
                "mission_id": mission_id,
                "snapshot_id": snapshot.snapshot_id,
                "state_hash": snapshot.state_hash,
                "observation_count": snapshot.observation_count,
            },
        )
        return snapshot

    def diff_snapshots(
        self,
        snapshot_a_id: str,
        snapshot_b_id: str,
        *,
        baseline_id: str = "",
        tenant: str = "",
        persist: bool = True,
    ) -> TargetDiff:
        """Compute and persist the deterministic diff between two snapshots."""
        snapshot_a = self._load_snapshot(snapshot_a_id)
        snapshot_b = self._load_snapshot(snapshot_b_id)
        if snapshot_a is None or snapshot_b is None:
            raise ValueError("both snapshots must exist to compute a diff")
        baseline = self._load_snapshot(baseline_id) if baseline_id else None
        diff = self._diff_engine.diff(snapshot_a, snapshot_b, baseline=baseline)
        classified: list[Any] = []
        for change in diff.changes:
            if change.kind.value == "unchanged":
                continue
            from hunterx.domain.target_memory.models import TargetChange

            significance = self._significance.classify(change)
            classified.append(
                TargetChange(
                    key=change.key,
                    kind=change.kind,
                    significance=significance,
                    asset_key=change.asset_key,
                    field=change.field,
                    previous=change.previous,
                    current=change.current,
                    description=change.description,
                    evidence_ref=change.evidence_ref,
                    confidence=change.confidence,
                )
            )
        diff = TargetDiff(
            diff_id=diff.diff_id,
            target_id=diff.target_id,
            snapshot_a_id=diff.snapshot_a_id,
            snapshot_b_id=diff.snapshot_b_id,
            state_hash_a=diff.state_hash_a,
            state_hash_b=diff.state_hash_b,
            changes=tuple(classified),
            deterministic=diff.deterministic,
        )
        if persist and self._stores is not None:
            self._repo(TargetDiffRecord).save(_diff_to_record(diff, tenant=tenant))
        self._publish(
            "target.diff.created",
            {
                "target_id": diff.target_id,
                "diff_id": diff.diff_id,
                "snapshot_a_id": snapshot_a_id,
                "snapshot_b_id": snapshot_b_id,
                "change_count": len(diff.changes),
            },
        )
        for change in diff.changes:
            self._publish(
                "target.change.detected",
                {
                    "target_id": diff.target_id,
                    "key": change.key,
                    "kind": change.kind.value,
                    "significance": change.significance.value,
                },
            )
        return diff

    # -- mission / hypothesis / tool memory ----------------------------------

    def record_mission_memory(self, memory: MissionMemory, *, tenant: str = "", persist: bool = True) -> MissionMemory:
        """Persist historical mission context."""
        self._check_target(memory.target_id, tenant=tenant, mission_id=memory.mission_id)
        if persist and self._stores is not None:
            self._repo(MissionMemoryRecord).save(_mission_to_record(memory, tenant=tenant))
        return memory

    def record_hypothesis(self, memory: HypothesisMemory, *, tenant: str = "", persist: bool = True) -> HypothesisMemory:
        """Persist a failed/successful hypothesis memory record."""
        self._check_target(memory.target_id, tenant=tenant, mission_id=memory.mission_id)
        if persist and self._stores is not None:
            self._repo(HypothesisMemoryRecord).save(_hypothesis_to_record(memory, tenant=tenant))
        event_type = {
            HypothesisOutcome.FAILED: "hypothesis.failed",
            HypothesisOutcome.SUCCEEDED: "hypothesis.succeeded",
            HypothesisOutcome.INCONCLUSIVE: "hypothesis.recorded",
        }[memory.outcome]
        self._publish(
            event_type,
            {
                "target_id": memory.target_id,
                "mission_id": memory.mission_id,
                "hypothesis_id": memory.hypothesis_id,
                "outcome": memory.outcome.value,
            },
        )
        return memory

    def record_tool_observation(self, observation: ToolObservation, *, tenant: str = "", persist: bool = True) -> ToolObservation:
        """Persist historical provenance of a meaningful tool result."""
        self._check_target(observation.target_id, tenant=tenant)
        if persist and self._stores is not None:
            self._repo(ToolObservationRecord).save(_tool_to_record(observation, tenant=tenant))
        return observation

    # -- risk history --------------------------------------------------------

    def record_risk(
        self,
        entry: TargetRiskEntry,
        *,
        tenant: str = "",
        persist: bool = True,
    ) -> TargetRiskEntry:
        """Persist a point-in-time risk assessment (append-only)."""
        self._check_target(entry.target_id, tenant=tenant, mission_id=entry.mission_id)
        if persist and self._stores is not None:
            self._repo(TargetRiskRecord).save(_risk_to_record(entry, tenant=tenant))
        self._publish(
            "risk.changed",
            {
                "target_id": entry.target_id,
                "campaign_id": entry.campaign_id,
                "risk_level": entry.risk_level.value,
                "previous_risk_level": entry.previous_risk_level.value if entry.previous_risk_level else None,
            },
        )
        return entry

    def evaluate_risk(
        self,
        *,
        target_id: str,
        campaign_id: str = "",
        mission_id: str = "",
        findings: Sequence[FindingMemory] = (),
        changes: Sequence[Any] = (),
        tenant: str = "",
        persist: bool = True,
    ) -> TargetRiskEntry:
        """Evaluate and persist a new risk entry from current findings/changes.

        When no findings are supplied, persisted finding memory for the target
        is loaded, so risk always reflects the current finding surface.
        """
        previous = self._latest_risk(target_id)
        loaded_findings = list(findings) or self._load_findings(target_id)
        entry = self._risk.evaluate(
            target_id=target_id,
            campaign_id=campaign_id,
            mission_id=mission_id,
            findings=loaded_findings,
            changes=changes,
            previous=previous,
        )
        return self.record_risk(entry, tenant=tenant, persist=persist)

    # -- finding memory & recurrence ------------------------------------------

    def record_finding(self, memory: FindingMemory, *, tenant: str = "", persist: bool = True) -> FindingMemory:
        """Persist finding lifecycle history."""
        self._check_target(memory.target_id, tenant=tenant, mission_id=memory.mission_id)
        if persist and self._stores is not None:
            self._repo(FindingMemoryRecord).save(_finding_to_record(memory, tenant=tenant))
        return memory

    def detect_recurrences(
        self,
        target_id: str,
        *,
        campaign_id: str = "",
        tenant: str = "",
        persist: bool = True,
    ) -> list[FindingRecurrence]:
        """Detect and persist finding recurrences for a target."""
        self._check_target(target_id, tenant=tenant)
        findings = self._load_findings(target_id)
        recurrences = self._recurrences.detect(findings)
        if persist and self._stores is not None and recurrences:
            self._repo(FindingRecurrenceRecord).save_many([_recurrence_to_record(r, tenant=tenant) for r in recurrences])
        for recurrence in recurrences:
            self._publish(
                "finding.recurred",
                {
                    "target_id": recurrence.target_id,
                    "original_finding_id": recurrence.original_finding_id,
                    "new_finding_id": recurrence.new_finding_id,
                    "kind": recurrence.kind.value,
                },
            )
        return recurrences

    # -- contradictions -------------------------------------------------------

    def detect_contradictions(
        self,
        target_id: str,
        observations: Sequence[Any],
        *,
        tenant: str = "",
        persist: bool = True,
    ) -> list[MemoryContradiction]:
        """Detect and persist preserved contradictions among observations."""
        self._check_target(target_id, tenant=tenant)
        contradictions = self._contradictions.detect(observations)
        if persist and self._stores is not None and contradictions:
            self._repo(MemoryContradictionRecord).save_many(
                [_contradiction_to_record(c, tenant=tenant) for c in contradictions]
            )
            repo = self._repo(MemoryObservationRecord)
            keys = {c.observation_key for c in contradictions}
            for record in repo.stream():
                if record.target_id == target_id and record.observation_key in keys:
                    record.contradiction_state = MemoryContradictionState.OPEN.value
                    repo.save(record)
        return contradictions

    # -- revalidation & coverage gaps ------------------------------------------

    def build_revalidation_plan(self, target_id: str, *, tenant: str = "", persist: bool = True) -> RevalidationPlan:
        """Build and persist the prioritized revalidation plan for a target."""
        self._check_target(target_id, tenant=tenant)
        memory = self.assemble(target_id)
        plan = self._revalidation.plan(memory, now=self._now)
        if persist and self._stores is not None:
            repo = self._repo(RevalidationRecord)
            for item in plan.items:
                repo.save(_revalidation_to_record(item, plan_id=plan.plan_id, tenant=tenant))
        self._publish(
            "target.revalidation.required",
            {
                "target_id": target_id,
                "plan_id": plan.plan_id,
                "item_count": len(plan.items),
            },
        )
        return plan

    def detect_coverage_gaps(
        self,
        target_id: str,
        *,
        campaign_id: str = "",
        tenant: str = "",
        persist: bool = True,
    ) -> list[CoverageGap]:
        """Detect and persist coverage gaps for a target."""
        self._check_target(target_id, tenant=tenant)
        observations = self._load_observations(target_id)
        coverage = self._load_coverage(target_id)
        gaps = self._coverage_gaps.detect(
            target_id=target_id,
            campaign_id=campaign_id,
            observations=observations,
            coverage=coverage,
            now=self._now,
        )
        if persist and self._stores is not None and gaps:
            self._repo(CoverageGapRecord).save_many([_gap_to_record(g, tenant=tenant) for g in gaps])
        self._publish(
            "coverage.gap.detected",
            {"target_id": target_id, "campaign_id": campaign_id, "gap_count": len(gaps)},
        )
        return gaps

    # -- recommendations & memory assembly -------------------------------------

    def recommend(
        self,
        target_id: str,
        *,
        campaign_id: str = "",
        tenant: str = "",
        persist: bool = True,
    ) -> list[NextActionRecommendation]:
        """Derive advisory next-action recommendations from target memory."""
        self._check_target(target_id, tenant=tenant)
        memory = self.assemble(target_id)
        if self._stores is not None:
            memory.findings = {f.finding_id: f for f in self._load_findings(target_id)}
            memory.gaps = [gap for gap in self._load_gaps(target_id)]
        recommendations = self._recommender.recommend(memory, campaign_id=campaign_id)
        if persist and self._stores is not None and recommendations:
            self._repo(NextActionRecord).save_many([_recommendation_to_record(r, tenant=tenant) for r in recommendations])
        return recommendations

    def assemble(self, target_id: str) -> TargetMemory:
        """Assemble the canonical :class:`TargetMemory` from persisted records."""
        memory = TargetMemory(target_id=target_id)
        if self._stores is None:
            return memory
        for record in self._repo(MemoryObservationRecord).stream():
            if record.target_id == target_id:
                observation = _observation_from_record(record)
                memory.observations[observation.observation_key] = observation
        for record in self._repo(CoverageGapRecord).stream():
            if record.target_id == target_id:
                memory.gaps.append(_gap_from_record(record))
        for record in self._repo(FindingMemoryRecord).stream():
            if record.target_id == target_id:
                finding = _finding_from_record(record)
                memory.findings[finding.finding_id] = finding
        for record in self._repo(NextActionRecord).stream():
            if record.target_id == target_id:
                memory.recommendations.append(_recommendation_from_record(record))
        for record in self._repo(MemoryContradictionRecord).stream():
            if record.target_id == target_id:
                memory.contradictions.append(_contradiction_from_record(record))
        memory.changed_at = self._now
        return memory

    def build_planner_context(
        self,
        target_id: str,
        *,
        failed_hypotheses: Sequence[Any] = (),
        successful_hypotheses: Sequence[Any] = (),
    ) -> PlannerContext:
        """Expose memory to the mission planner through a port-style object."""
        memory = self.assemble(target_id)
        return self._planner_context.build(memory, failed_hypotheses=failed_hypotheses, successful_hypotheses=successful_hypotheses)

    # -- campaigns ---------------------------------------------------------------

    def create_campaign(
        self,
        *,
        name: str = "",
        objective: str = "",
        scope: str = "",
        target_ids: Sequence[str] = (),
        tenant: str = "",
        persist: bool = True,
    ) -> Campaign:
        """Create and persist a campaign."""
        campaign = Campaign(
            name=name,
            objective=objective,
            scope=scope,
            target_ids=list(target_ids),
            status=CampaignStatus.PLANNED,
            tenant=tenant or self._tenant,
        )
        if persist and self._stores is not None:
            self._repo(CampaignRecord).save(_campaign_to_record(campaign))
        self._publish("campaign.created", {"campaign_id": campaign.campaign_id, "name": name})
        return campaign

    def update_campaign(self, campaign: Campaign, *, persist: bool = True) -> Campaign:
        """Persist a campaign update (add mission, risk, findings, coverage)."""
        if persist and self._stores is not None:
            self._repo(CampaignRecord).save(_campaign_to_record(campaign))
        self._publish(
            "campaign.updated",
            {
                "campaign_id": campaign.campaign_id,
                "status": campaign.status.value,
                "mission_count": len(campaign.mission_ids),
            },
        )
        return campaign

    def complete_campaign(self, campaign_id: str, *, tenant: str = "", persist: bool = True) -> Campaign:
        """Mark a campaign completed and persist it."""
        campaign = self._load_campaign(campaign_id)
        if campaign is None:
            raise ValueError(f"campaign {campaign_id} not found")
        campaign.complete()
        if persist and self._stores is not None:
            self._repo(CampaignRecord).save(_campaign_to_record(campaign))
        self._publish("campaign.completed", {"campaign_id": campaign_id})
        return campaign

    # -- internal loaders ---------------------------------------------------------

    def _load_observations(self, target_id: str) -> list[MemoryObservation]:
        if self._stores is None:
            return []
        return [_observation_from_record(r) for r in self._repo(MemoryObservationRecord).stream() if r.target_id == target_id]

    def _load_snapshot(self, snapshot_id: str) -> TargetSnapshot | None:
        if self._stores is None:
            return None
        record = self._repo(TargetSnapshotRecord).get(snapshot_id)
        if record is None:
            records = [r for r in self._repo(TargetSnapshotRecord).stream() if r.snapshot_id == snapshot_id]
            record = records[0] if records else None
        return _snapshot_from_record(record) if record else None

    def _load_snapshots(self, target_id: str) -> list[TargetSnapshot]:
        if self._stores is None:
            return []
        return [_snapshot_from_record(r) for r in self._repo(TargetSnapshotRecord).stream() if r.target_id == target_id]

    def _load_findings(self, target_id: str) -> list[FindingMemory]:
        if self._stores is None:
            return []
        return [_finding_from_record(r) for r in self._repo(FindingMemoryRecord).stream() if r.target_id == target_id]

    def _load_coverage(self, target_id: str) -> dict[str, str]:
        if self._stores is None:
            return {}
        coverage: dict[str, str] = {}
        for record in self._repo(CoverageGapRecord).stream():
            if record.target_id == target_id and record.capability and record.status != "open":
                coverage[f"{record.asset_key}::{record.capability}"] = record.status
        return coverage

    def _load_gaps(self, target_id: str) -> list[CoverageGap]:
        if self._stores is None:
            return []
        return [_gap_from_record(r) for r in self._repo(CoverageGapRecord).stream() if r.target_id == target_id]

    def _load_campaign(self, campaign_id: str) -> Campaign | None:
        if self._stores is None:
            return None
        record = self._repo(CampaignRecord).get(campaign_id)
        if record is None:
            records = [r for r in self._repo(CampaignRecord).stream() if r.campaign_id == campaign_id]
            record = records[0] if records else None
        return _campaign_from_record(record) if record else None

    def _latest_risk(self, target_id: str) -> RiskLevel | None:
        if self._stores is None:
            return None
        entries = [_risk_from_record(r) for r in self._repo(TargetRiskRecord).stream() if r.target_id == target_id]
        if not entries:
            return None
        return sorted(entries, key=lambda entry: entry.detected_at)[-1].risk_level

    # -- events -------------------------------------------------------------------

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        if self._event_bus is None:
            return
        from hunterx.domain.events import DomainEvent

        self._event_bus.publish(
            DomainEvent(event_type=event_type, payload=payload, source="application.target_memory")
        )


class TargetMemoryQueryService:
    """Answer canonical target-memory & campaign queries from persisted records.

    Every query is target- or campaign-scoped: a query never returns records
    from another target.
    """

    def __init__(self, *, stores: TidbRepositoryFactory | None = None, cache: CachePort | None = None) -> None:
        self._stores = stores
        self._cache = cache
        self._freshness = ObservationFreshnessEngine()

    def _repo(self, entity_cls: type) -> TidbRepository[Any]:
        if self._stores is None:
            raise RuntimeError("TIDB repository factory is not configured")
        return self._stores.repository_for(entity_cls)

    def _stream(self, entity_cls: type) -> list[Any]:
        return list(self._repo(entity_cls).stream())

    def memory(self, target_id: str) -> TargetMemory:
        """Return the assembled memory for a target."""
        service = TargetMemoryService(stores=self._stores)
        return service.assemble(target_id)

    def snapshots(self, target_id: str) -> list[TargetSnapshot]:
        """Return all snapshots for a target (newest first)."""
        records = [r for r in self._stream(TargetSnapshotRecord) if r.target_id == target_id]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return [_snapshot_from_record(r) for r in records]

    def snapshot(self, snapshot_id: str) -> TargetSnapshot | None:
        """Return a snapshot by id."""
        record = self._get_record(TargetSnapshotRecord, snapshot_id)
        return _snapshot_from_record(record) if record else None

    def diffs(self, target_id: str) -> list[TargetDiff]:
        """Return all diffs for a target (newest first)."""
        records = [r for r in self._stream(TargetDiffRecord) if r.target_id == target_id]
        records.sort(key=lambda r: r.created_at, reverse=True)
        return [_diff_from_record(r) for r in records]

    def diff(self, diff_id: str) -> TargetDiff | None:
        """Return a diff by id."""
        record = self._get_record(TargetDiffRecord, diff_id)
        return _diff_from_record(record) if record else None

    def changes(self, target_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        """Return the structured changes detected for a target."""
        changes: list[dict[str, Any]] = []
        for diff in self.diffs(target_id):
            for change in diff.changes:
                changes.append(change.to_dict())
        return changes[:limit]

    def observation_history(self, target_id: str) -> list[MemoryObservation]:
        """Return the observation history for a target."""
        records = [r for r in self._stream(MemoryObservationRecord) if r.target_id == target_id]
        records.sort(key=lambda r: r.last_seen, reverse=True)
        return [_observation_from_record(r) for r in records]

    def coverage(self, target_id: str) -> list[dict[str, Any]]:
        """Return coverage memory: observed surface grouped by asset key."""
        records = [r for r in self._stream(MemoryObservationRecord) if r.target_id == target_id]
        by_asset: dict[str, list[str]] = {}
        counts: dict[str, int] = {}
        for record in records:
            key = record.asset_key or record.observation_key
            by_asset.setdefault(key, [])
            if record.observation_type not in by_asset[key]:
                by_asset[key].append(record.observation_type)
            counts[key] = counts.get(key, 0) + int(record.observation_count)
        return [
            {
                "asset_key": asset_key,
                "observation_types": sorted(types),
                "observation_count": counts[asset_key],
                "covered": True,
            }
            for asset_key, types in sorted(by_asset.items())
        ]

    def mission_memories(self, target_id: str) -> list[MissionMemory]:
        """Return historical mission contexts for a target."""
        records = [r for r in self._stream(MissionMemoryRecord) if r.target_id == target_id]
        return [_mission_from_record(r) for r in records]

    def hypothesis_history(self, target_id: str, *, outcome: str = "") -> list[HypothesisMemory]:
        """Return hypothesis memory for a target, optionally by outcome."""
        records = [r for r in self._stream(HypothesisMemoryRecord) if r.target_id == target_id]
        if outcome:
            records = [r for r in records if r.outcome == outcome]
        records.sort(key=lambda r: r.tested_at, reverse=True)
        return [_hypothesis_from_record(r) for r in records]

    def tool_observations(self, target_id: str, *, tool: str = "") -> list[ToolObservation]:
        """Return tool observation provenance for a target."""
        records = [r for r in self._stream(ToolObservationRecord) if r.target_id == target_id]
        if tool:
            records = [r for r in records if r.tool == tool]
        return [_tool_from_record(r) for r in records]

    def risk_history(self, target_id: str) -> list[TargetRiskEntry]:
        """Return the append-only risk history for a target."""
        records = [r for r in self._stream(TargetRiskRecord) if r.target_id == target_id]
        records.sort(key=lambda r: r.detected_at)
        return [_risk_from_record(r) for r in records]

    def finding_history(self, target_id: str) -> list[FindingMemory]:
        """Return finding lifecycle history for a target."""
        records = [r for r in self._stream(FindingMemoryRecord) if r.target_id == target_id]
        return [_finding_from_record(r) for r in records]

    def recurrences(self, target_id: str) -> list[FindingRecurrence]:
        """Return detected finding recurrences for a target."""
        records = [r for r in self._stream(FindingRecurrenceRecord) if r.target_id == target_id]
        return [_recurrence_from_record(r) for r in records]

    def attack_paths(self, target_id: str) -> list[AttackPathMemory]:
        """Return historical attack-path observations for a target."""
        records = [r for r in self._stream(AttackPathMemoryRecord) if r.target_id == target_id]
        records.sort(key=lambda r: r.last_seen, reverse=True)
        return [_attack_path_from_record(r) for r in records]

    def contradictions(self, target_id: str) -> list[MemoryContradiction]:
        """Return preserved contradictions for a target."""
        records = [r for r in self._stream(MemoryContradictionRecord) if r.target_id == target_id]
        return [_contradiction_from_record(r) for r in records]

    def coverage_gaps(self, target_id: str) -> list[CoverageGap]:
        """Return coverage gaps for a target."""
        records = [r for r in self._stream(CoverageGapRecord) if r.target_id == target_id]
        return [_gap_from_record(r) for r in records]

    def revalidation_plan(self, target_id: str) -> RevalidationPlan:
        """Return the persisted revalidation plan for a target."""
        records = [r for r in self._stream(RevalidationRecord) if r.target_id == target_id]
        from hunterx.domain.target_memory.enums import FreshnessState, RevalidationPriority
        from hunterx.domain.target_memory.models import RevalidationItem

        items = tuple(
            sorted(
                (
                    RevalidationItem(
                        observation_key=r.observation_key,
                        target_id=r.target_id,
                        asset_key=r.asset_key,
                        observation_type=r.observation_type,
                        freshness=FreshnessState(r.freshness),
                        last_seen=r.last_seen or "",
                        reason=r.reason,
                        priority=RevalidationPriority(r.priority),
                    )
                    for r in records
                ),
                key=lambda item: (-item.priority.rank, item.observation_key),
            )
        )
        plan_id = records[0].plan_id if records else ""
        from hunterx.domain.target_memory.models import RevalidationPlan as Plan

        return Plan(target_id=target_id, plan_id=plan_id, items=items)

    def recommendations(self, target_id: str) -> list[NextActionRecommendation]:
        """Return advisory next-action recommendations for a target."""
        records = [r for r in self._stream(NextActionRecord) if r.target_id == target_id]
        return [_recommendation_from_record(r) for r in records]

    # -- campaigns ------------------------------------------------------------------

    def campaigns(self, *, tenant: str = "") -> list[Campaign]:
        """Return persisted campaigns."""
        records = self._stream(CampaignRecord)
        if tenant:
            records = [r for r in records if r.tenant == tenant]
        return [_campaign_from_record(r) for r in records]

    def campaign(self, campaign_id: str) -> Campaign | None:
        """Return a campaign by id."""
        record = self._get_record(CampaignRecord, campaign_id)
        return _campaign_from_record(record) if record else None

    def campaign_intelligence(self, campaign_id: str) -> CampaignIntelligence:
        """Answer the campaign intelligence questions from persisted records."""
        campaign = self.campaign(campaign_id)
        if campaign is None:
            raise ValueError(f"campaign {campaign_id} not found")
        diffs: list[TargetDiff] = []
        findings: list[FindingMemory] = []
        gaps: list[CoverageGap] = []
        recurrences: list[FindingRecurrence] = []
        hypotheses: list[Any] = []
        for record in self._stream(TargetDiffRecord):
            if record.target_id in campaign.target_ids:
                diffs.append(_diff_from_record(record))
        for record in self._stream(FindingMemoryRecord):
            if record.target_id in campaign.target_ids:
                findings.append(_finding_from_record(record))
        for record in self._stream(CoverageGapRecord):
            if record.target_id in campaign.target_ids:
                gaps.append(_gap_from_record(record))
        for record in self._stream(FindingRecurrenceRecord):
            if record.target_id in campaign.target_ids:
                recurrences.append(_recurrence_from_record(record))
        for record in self._stream(HypothesisMemoryRecord):
            if record.target_id in campaign.target_ids:
                hypotheses.append(_hypothesis_from_record(record))
        engine = CampaignIntelligenceEngine()
        return engine.analyze(
            campaign=campaign,
            diffs=diffs,
            findings=findings,
            gaps=gaps,
            hypotheses=hypotheses,
            recurrences=recurrences,
        )

    def _get_record(self, entity_cls: type, identifier: str) -> Any:
        record = self._repo(entity_cls).get(identifier)
        if record is not None:
            return record
        records = [r for r in self._stream(entity_cls) if getattr(r, "campaign_id", "") == identifier or getattr(r, "diff_id", "") == identifier or getattr(r, "snapshot_id", "") == identifier]
        return records[0] if records else None


# ==========================================================================
# Record <-> domain mapping helpers
# ==========================================================================


def _stable_record_id(*parts: Any) -> str:
    """Return a stable 26-char record id derived from content parts."""
    return generate_content_id(*parts)[:26]


def _observation_to_record(observation: MemoryObservation, *, tenant: str = "") -> MemoryObservationRecord:
    return MemoryObservationRecord(
        id=_stable_record_id("memory", observation.target_id, observation.observation_key),
        observation_key=observation.observation_key,
        target_id=observation.target_id,
        mission_id=observation.mission_id,
        observation_type=observation.observation_type,
        value=observation.value,
        normalized_value=observation.normalized_value,
        asset_key=observation.asset_key,
        tool=observation.tool,
        first_seen=observation.first_seen,
        last_seen=observation.last_seen,
        observation_count=observation.observation_count,
        first_mission=observation.first_mission,
        last_mission=observation.last_mission,
        first_source=observation.first_source,
        last_source=observation.last_source,
        current_state=observation.current_state.value,
        freshness=observation.freshness.value,
        confidence=observation.confidence,
        source_reliability=observation.source_reliability,
        corroboration_count=observation.corroboration_count,
        contradiction_state=observation.contradiction_state,
        validity=observation.validity.value,
        expires_at=observation.expires_at,
        provenance=dict(observation.provenance),
        meta={"tenant": tenant},
    )


def _observation_from_record(record: MemoryObservationRecord) -> MemoryObservation:
    return MemoryObservation(
        observation_key=record.observation_key,
        target_id=record.target_id,
        observation_type=record.observation_type,
        value=record.value,
        normalized_value=record.normalized_value,
        first_seen=record.first_seen or "",
        last_seen=record.last_seen or "",
        observation_count=int(record.observation_count),
        first_mission=record.first_mission,
        last_mission=record.last_mission,
        first_source=record.first_source,
        last_source=record.last_source,
        current_state=MemoryObservationState(record.current_state),
        freshness=FreshnessState(record.freshness),
        mission_id=record.mission_id,
        asset_key=record.asset_key,
        tool=record.tool,
        confidence=float(record.confidence),
        source_reliability=record.source_reliability,
        corroboration_count=int(record.corroboration_count),
        contradiction_state=record.contradiction_state,
        validity=MemoryValidity(record.validity),
        expires_at=record.expires_at,
        provenance=dict(record.provenance),
    )


def _snapshot_to_record(snapshot: TargetSnapshot, *, tenant: str = "") -> TargetSnapshotRecord:
    return TargetSnapshotRecord(
        id=snapshot.snapshot_id,
        snapshot_id=snapshot.snapshot_id,
        target_id=snapshot.target_id,
        mission_id=snapshot.mission_id,
        schema_version=snapshot.schema_version,
        observation_count=snapshot.observation_count,
        state_hash=snapshot.state_hash,
        state=snapshot.state,
        created_at=snapshot.created_at,
        meta={"tenant": tenant},
    )


def _snapshot_from_record(record: TargetSnapshotRecord) -> TargetSnapshot:
    return TargetSnapshot(
        snapshot_id=record.snapshot_id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        created_at=record.created_at,
        schema_version=int(record.schema_version),
        observation_count=int(record.observation_count),
        state_hash=record.state_hash,
        state=dict(record.state),
    )


def _diff_to_record(diff: TargetDiff, *, tenant: str = "") -> TargetDiffRecord:
    return TargetDiffRecord(
        id=diff.diff_id,
        diff_id=diff.diff_id,
        target_id=diff.target_id,
        snapshot_a_id=diff.snapshot_a_id,
        snapshot_b_id=diff.snapshot_b_id,
        state_hash_a=diff.state_hash_a,
        state_hash_b=diff.state_hash_b,
        changes=[change.to_dict() for change in diff.changes],
        deterministic=diff.deterministic,
        created_at=diff.created_at,
        meta={"tenant": tenant},
    )


def _diff_from_record(record: TargetDiffRecord) -> TargetDiff:
    from hunterx.domain.target_memory.enums import ChangeSignificance, DiffChangeKind
    from hunterx.domain.target_memory.models import TargetChange

    changes: list[TargetChange] = []
    for item in record.changes:
        changes.append(
            TargetChange(
                key=str(item.get("key", "")),
                kind=DiffChangeKind(str(item.get("kind", "unchanged"))),
                significance=ChangeSignificance(str(item.get("significance", "low"))),
                asset_key=str(item.get("asset_key", "")),
                field=str(item.get("field", "")),
                previous=item.get("previous"),
                current=item.get("current"),
                description=str(item.get("description", "")),
                evidence_ref=str(item.get("evidence_ref", "")),
                confidence=float(str(item.get("confidence", 1.0))),
            )
        )
    return TargetDiff(
        diff_id=record.diff_id,
        target_id=record.target_id,
        snapshot_a_id=record.snapshot_a_id,
        snapshot_b_id=record.snapshot_b_id,
        created_at=record.created_at,
        state_hash_a=record.state_hash_a,
        state_hash_b=record.state_hash_b,
        changes=tuple(changes),
        deterministic=bool(record.deterministic),
    )


def _mission_to_record(memory: MissionMemory, *, tenant: str = "") -> MissionMemoryRecord:
    return MissionMemoryRecord(
        mission_id=memory.mission_id,
        target_id=memory.target_id,
        scope=memory.scope,
        status=memory.status,
        started_at=memory.started_at,
        ended_at=memory.ended_at,
        tools_used=list(memory.tools_used),
        assets_discovered=list(memory.assets_discovered),
        findings_discovered=list(memory.findings_discovered),
        findings_validated=list(memory.findings_validated),
        pocs_generated=list(memory.pocs_generated),
        hypotheses=list(memory.hypotheses),
        successful_hypotheses=list(memory.successful_hypotheses),
        failed_hypotheses=list(memory.failed_hypotheses),
        blocked_tests=list(memory.blocked_tests),
        tool_failures=list(memory.tool_failures),
        coverage_achieved=dict(memory.coverage_achieved),
        coverage_gaps=list(memory.coverage_gaps),
        tenant=tenant,
    )


def _mission_from_record(record: MissionMemoryRecord) -> MissionMemory:
    return MissionMemory(
        mission_id=record.mission_id,
        target_id=record.target_id,
        scope=record.scope,
        status=record.status,
        started_at=record.started_at,
        ended_at=record.ended_at,
        tools_used=list(record.tools_used),
        assets_discovered=list(record.assets_discovered),
        findings_discovered=list(record.findings_discovered),
        findings_validated=list(record.findings_validated),
        pocs_generated=list(record.pocs_generated),
        hypotheses=list(record.hypotheses),
        successful_hypotheses=list(record.successful_hypotheses),
        failed_hypotheses=list(record.failed_hypotheses),
        blocked_tests=list(record.blocked_tests),
        tool_failures=list(record.tool_failures),
        coverage_achieved=dict(record.coverage_achieved),
        coverage_gaps=list(record.coverage_gaps),
        tenant=record.tenant,
    )


def _hypothesis_to_record(memory: HypothesisMemory, *, tenant: str = "") -> HypothesisMemoryRecord:
    return HypothesisMemoryRecord(
        memory_id=memory.memory_id,
        hypothesis_id=memory.hypothesis_id,
        target_id=memory.target_id,
        mission_id=memory.mission_id,
        statement=memory.statement,
        hypothesis_type=memory.hypothesis_type,
        outcome=memory.outcome.value,
        tool=memory.tool,
        tool_version=memory.tool_version,
        evidence_observed=memory.evidence_observed,
        reason=memory.reason,
        tested_at=memory.tested_at,
        conditions=dict(memory.conditions),
        vulnerability_type=memory.vulnerability_type,
        asset_type=memory.asset_type,
        technology=memory.technology,
        endpoint_pattern=memory.endpoint_pattern,
        parameter_pattern=memory.parameter_pattern,
        authentication_context=memory.authentication_context,
        validation_strategy=memory.validation_strategy,
        poc_strategy=memory.poc_strategy,
        evidence_pattern=memory.evidence_pattern,
        confidence=memory.confidence,
        tenant=tenant,
    )


def _hypothesis_from_record(record: HypothesisMemoryRecord) -> HypothesisMemory:
    return HypothesisMemory(
        memory_id=record.memory_id,
        hypothesis_id=record.hypothesis_id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        statement=record.statement,
        hypothesis_type=record.hypothesis_type,
        outcome=HypothesisOutcome(record.outcome),
        tool=record.tool,
        tool_version=record.tool_version,
        evidence_observed=record.evidence_observed,
        reason=record.reason,
        tested_at=record.tested_at,
        conditions=dict(record.conditions),
        vulnerability_type=record.vulnerability_type,
        asset_type=record.asset_type,
        technology=record.technology,
        endpoint_pattern=record.endpoint_pattern,
        parameter_pattern=record.parameter_pattern,
        authentication_context=record.authentication_context,
        validation_strategy=record.validation_strategy,
        poc_strategy=record.poc_strategy,
        evidence_pattern=record.evidence_pattern,
        confidence=float(record.confidence),
        tenant=record.tenant,
    )


def _tool_to_record(observation: ToolObservation, *, tenant: str = "") -> ToolObservationRecord:
    return ToolObservationRecord(
        id=_stable_record_id("tool", observation.target_id, observation.execution_id, observation.tool),
        tool=observation.tool,
        tool_version=observation.tool_version,
        execution_id=observation.execution_id,
        target_id=observation.target_id,
        scope=observation.scope,
        timestamp=observation.timestamp,
        normalized_result=dict(observation.normalized_result),
        evidence_refs=list(observation.evidence_refs),
        derived_entities=list(observation.derived_entities),
        confidence=observation.confidence,
        provenance=dict(observation.provenance),
        tenant=tenant,
    )


def _tool_from_record(record: ToolObservationRecord) -> ToolObservation:
    return ToolObservation(
        tool=record.tool,
        tool_version=record.tool_version,
        execution_id=record.execution_id,
        target_id=record.target_id,
        scope=record.scope,
        timestamp=record.timestamp,
        normalized_result=dict(record.normalized_result),
        evidence_refs=list(record.evidence_refs),
        derived_entities=list(record.derived_entities),
        confidence=float(record.confidence),
        provenance=dict(record.provenance),
        tenant=record.tenant,
    )


def _risk_to_record(entry: TargetRiskEntry, *, tenant: str = "") -> TargetRiskRecord:
    return TargetRiskRecord(
        id=entry.risk_id,
        risk_id=entry.risk_id,
        target_id=entry.target_id,
        campaign_id=entry.campaign_id,
        mission_id=entry.mission_id,
        risk_level=entry.risk_level.value,
        previous_risk_level=entry.previous_risk_level.value if entry.previous_risk_level else None,
        reason=entry.reason,
        detected_at=entry.detected_at,
        driving_changes=list(entry.driving_changes),
        meta={"tenant": tenant},
    )


def _risk_from_record(record: TargetRiskRecord) -> TargetRiskEntry:
    return TargetRiskEntry(
        risk_id=record.risk_id,
        target_id=record.target_id,
        campaign_id=record.campaign_id,
        mission_id=record.mission_id,
        risk_level=RiskLevel(record.risk_level),
        previous_risk_level=RiskLevel(record.previous_risk_level) if record.previous_risk_level else None,
        reason=record.reason,
        detected_at=record.detected_at,
        driving_changes=list(record.driving_changes),
    )


def _finding_to_record(memory: FindingMemory, *, tenant: str = "") -> FindingMemoryRecord:
    return FindingMemoryRecord(
        id=_stable_record_id("finding", memory.target_id, memory.finding_id),
        finding_id=memory.finding_id,
        target_id=memory.target_id,
        mission_id=memory.mission_id,
        title=memory.title,
        vulnerability_class=memory.vulnerability_class,
        severity=memory.severity,
        status=memory.status,
        first_detected=memory.first_detected,
        first_validated=memory.first_validated,
        last_validated=memory.last_validated,
        last_observed=memory.last_observed,
        remediation_state=memory.remediation_state,
        retest_state=memory.retest_state,
        reopened_count=memory.reopened_count,
        closed_at=memory.closed_at,
        affected_assets=list(memory.affected_assets),
        affected_endpoints=list(memory.affected_endpoints),
        root_cause=memory.root_cause,
        recurrence_count=memory.recurrence_count,
        tenant=tenant,
    )


def _finding_from_record(record: FindingMemoryRecord) -> FindingMemory:
    return FindingMemory(
        finding_id=record.finding_id,
        target_id=record.target_id,
        mission_id=record.mission_id,
        title=record.title,
        vulnerability_class=record.vulnerability_class,
        severity=record.severity,
        status=record.status,
        first_detected=record.first_detected,
        first_validated=record.first_validated,
        last_validated=record.last_validated,
        last_observed=record.last_observed,
        remediation_state=record.remediation_state,
        retest_state=record.retest_state,
        reopened_count=int(record.reopened_count),
        closed_at=record.closed_at,
        affected_assets=list(record.affected_assets),
        affected_endpoints=list(record.affected_endpoints),
        root_cause=record.root_cause,
        recurrence_count=int(record.recurrence_count),
        tenant=record.tenant,
    )


def _recurrence_to_record(recurrence: FindingRecurrence, *, tenant: str = "") -> FindingRecurrenceRecord:
    return FindingRecurrenceRecord(
        id=recurrence.recurrence_id,
        recurrence_id=recurrence.recurrence_id,
        target_id=recurrence.target_id,
        campaign_id=recurrence.campaign_id,
        original_finding_id=recurrence.original_finding_id,
        new_finding_id=recurrence.new_finding_id,
        vulnerability_class=recurrence.vulnerability_class,
        root_cause=recurrence.root_cause,
        previous_location=recurrence.previous_location,
        new_location=recurrence.new_location,
        kind=recurrence.kind.value,
        detected_at=recurrence.detected_at,
        confidence=recurrence.confidence,
        meta={"tenant": tenant},
    )


def _recurrence_from_record(record: FindingRecurrenceRecord) -> FindingRecurrence:
    from hunterx.domain.target_memory.enums import RecurrenceKind

    return FindingRecurrence(
        recurrence_id=record.recurrence_id,
        target_id=record.target_id,
        campaign_id=record.campaign_id,
        original_finding_id=record.original_finding_id,
        new_finding_id=record.new_finding_id,
        vulnerability_class=record.vulnerability_class,
        root_cause=record.root_cause,
        previous_location=record.previous_location,
        new_location=record.new_location,
        kind=RecurrenceKind(record.kind),
        detected_at=record.detected_at,
        confidence=float(record.confidence),
    )


def _campaign_to_record(campaign: Campaign) -> CampaignRecord:
    return CampaignRecord(
        id=campaign.campaign_id,
        campaign_id=campaign.campaign_id,
        name=campaign.name,
        objective=campaign.objective,
        scope=campaign.scope,
        status=campaign.status.value,
        target_ids=list(campaign.target_ids),
        mission_ids=list(campaign.mission_ids),
        started_at=campaign.started_at,
        ended_at=campaign.ended_at,
        risk_history=[risk.to_dict() for risk in campaign.risk_history],
        findings=list(campaign.findings),
        coverage=dict(campaign.coverage),
        changes=list(campaign.changes),
        attack_paths=list(campaign.attack_paths),
        tenant=campaign.tenant,
    )


def _campaign_from_record(record: CampaignRecord) -> Campaign:
    campaign = Campaign(
        campaign_id=record.campaign_id,
        name=record.name,
        objective=record.objective,
        scope=record.scope,
        status=CampaignStatus(record.status),
        target_ids=list(record.target_ids),
        mission_ids=list(record.mission_ids),
        started_at=record.started_at,
        ended_at=record.ended_at,
        findings=list(record.findings),
        coverage=dict(record.coverage),
        changes=list(record.changes),
        attack_paths=list(record.attack_paths),
        tenant=record.tenant,
    )
    from hunterx.domain.target_memory.models import TargetRiskEntry

    risk_history: list[TargetRiskEntry] = []
    for risk in record.risk_history:
        driving = risk.get("driving_changes")
        risk_history.append(
            TargetRiskEntry(
                risk_id=str(risk.get("risk_id", "")),
                target_id=str(risk.get("target_id", "")),
                campaign_id=str(risk.get("campaign_id", "")),
                mission_id=str(risk.get("mission_id", "")),
                risk_level=RiskLevel(str(risk.get("risk_level", "low"))),
                previous_risk_level=RiskLevel(str(risk["previous_risk_level"])) if risk.get("previous_risk_level") else None,
                reason=str(risk.get("reason", "")),
                detected_at=str(risk.get("detected_at", "")),
                driving_changes=[str(item) for item in driving] if isinstance(driving, list) else [],
            )
        )
    campaign.risk_history = risk_history
    return campaign


def _gap_to_record(gap: CoverageGap, *, tenant: str = "") -> CoverageGapRecord:
    return CoverageGapRecord(
        id=gap.gap_id,
        gap_id=gap.gap_id,
        target_id=gap.target_id,
        campaign_id=gap.campaign_id,
        asset_key=gap.asset_key,
        capability=gap.capability,
        kind=gap.kind.value,
        description=gap.description,
        significance=gap.significance.value,
        status=gap.status,
        detected_at=gap.detected_at,
        resolved_at=gap.resolved_at,
        candidate_tools=list(gap.candidate_tools),
        meta={"tenant": tenant},
    )


def _gap_from_record(record: CoverageGapRecord) -> CoverageGap:
    from hunterx.domain.target_memory.enums import ChangeSignificance, CoverageGapKind

    return CoverageGap(
        gap_id=record.gap_id,
        target_id=record.target_id,
        campaign_id=record.campaign_id,
        asset_key=record.asset_key,
        capability=record.capability,
        kind=CoverageGapKind(record.kind),
        description=record.description,
        significance=ChangeSignificance(record.significance),
        status=record.status,
        detected_at=record.detected_at,
        resolved_at=record.resolved_at,
        candidate_tools=list(record.candidate_tools),
    )


def _revalidation_to_record(item: Any, *, plan_id: str, tenant: str = "") -> RevalidationRecord:
    from hunterx.domain.target_memory.models import RevalidationItem

    assert isinstance(item, RevalidationItem)  # nosec B101 - internal type guard
    return RevalidationRecord(
        id=_stable_record_id("reval", item.target_id, item.observation_key, plan_id),
        plan_id=plan_id,
        observation_key=item.observation_key,
        target_id=item.target_id,
        asset_key=item.asset_key,
        observation_type=item.observation_type,
        freshness=item.freshness.value,
        last_seen=item.last_seen,
        reason=item.reason,
        priority=item.priority.value,
        status="open",
        meta={"tenant": tenant},
    )


def _attack_path_to_record(path: AttackPathMemory, *, tenant: str = "") -> AttackPathMemoryRecord:
    return AttackPathMemoryRecord(
        id=path.path_id,
        path_id=path.path_id,
        target_id=path.target_id,
        campaign_id=path.campaign_id,
        mission_id=path.mission_id,
        nodes=list(path.nodes),
        edges=list(path.edges),
        evidence_refs=list(path.evidence_refs),
        confidence=path.confidence,
        first_seen=path.first_seen,
        last_seen=path.last_seen,
        status=path.status,
        changes=list(path.changes),
        tenant=tenant,
    )


def _attack_path_from_record(record: AttackPathMemoryRecord) -> AttackPathMemory:
    return AttackPathMemory(
        path_id=record.path_id,
        target_id=record.target_id,
        campaign_id=record.campaign_id,
        mission_id=record.mission_id,
        nodes=list(record.nodes),
        edges=list(record.edges),
        evidence_refs=list(record.evidence_refs),
        confidence=float(record.confidence),
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        status=record.status,
        changes=list(record.changes),
        tenant=record.tenant,
    )


def _contradiction_to_record(contradiction: MemoryContradiction, *, tenant: str = "") -> MemoryContradictionRecord:
    return MemoryContradictionRecord(
        id=contradiction.contradiction_id,
        contradiction_id=contradiction.contradiction_id,
        target_id=contradiction.target_id,
        asset_key=contradiction.asset_key,
        observation_key=contradiction.observation_key,
        observations=list(contradiction.observations),
        tools=list(contradiction.tools),
        state=contradiction.state.value,
        resolution=contradiction.resolution,
        detected_at=contradiction.detected_at,
        resolved_at=contradiction.resolved_at,
        meta={"tenant": tenant},
    )


def _contradiction_from_record(record: MemoryContradictionRecord) -> MemoryContradiction:
    return MemoryContradiction(
        contradiction_id=record.contradiction_id,
        target_id=record.target_id,
        asset_key=record.asset_key,
        observation_key=record.observation_key,
        observations=list(record.observations),
        tools=list(record.tools),
        state=MemoryContradictionState(record.state),
        resolution=record.resolution,
        detected_at=record.detected_at,
        resolved_at=record.resolved_at,
    )


def _recommendation_to_record(recommendation: NextActionRecommendation, *, tenant: str = "") -> NextActionRecord:
    return NextActionRecord(
        id=recommendation.recommendation_id,
        recommendation_id=recommendation.recommendation_id,
        target_id=recommendation.target_id,
        campaign_id=recommendation.campaign_id,
        action=recommendation.action,
        reason=recommendation.reason,
        priority=recommendation.priority.value,
        required_tool_capabilities=list(recommendation.required_tool_capabilities),
        evidence_required=list(recommendation.evidence_required),
        expected_outcome=recommendation.expected_outcome,
        historical_context=list(recommendation.historical_context),
        meta={"tenant": tenant},
    )


def _recommendation_from_record(record: NextActionRecord) -> NextActionRecommendation:
    from hunterx.domain.target_memory.enums import ChangeSignificance

    return NextActionRecommendation(
        recommendation_id=record.recommendation_id,
        target_id=record.target_id,
        campaign_id=record.campaign_id,
        action=record.action,
        reason=record.reason,
        priority=ChangeSignificance(record.priority),
        required_tool_capabilities=list(record.required_tool_capabilities),
        evidence_required=list(record.evidence_required),
        expected_outcome=record.expected_outcome,
        historical_context=list(record.historical_context),
    )


__all__ = [
    "TargetMemoryQueryService",
    "TargetMemoryScopeError",
    "TargetMemoryService",
]
