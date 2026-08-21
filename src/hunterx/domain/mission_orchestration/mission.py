# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous mission orchestration aggregate.

``OrchestratedMission`` is the orchestration aggregate: it wraps the Sprint 027
planning aggregate (:class:`AdaptiveMission`) and adds the reasoning/evidence
state that drives the adaptive loop — context, observations, hypotheses,
decisions, branches, negative evidence, baselines, differential results, impact
analyses, novel-behavior records, reasoning trace, telemetry, runs, checkpoints
and the final outcome. It reuses the planning aggregate rather than
duplicating it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.adaptive_mission_planning.mission import AdaptiveMission
from hunterx.domain.mission_orchestration.enums import MissionPhase
from hunterx.domain.mission_orchestration.models import (
    BaselineObservation,
    DifferentialResult,
    ImpactAnalysis,
    MissionBranch,
    MissionBudget,
    MissionContext,
    MissionDecision,
    MissionHypothesis,
    MissionObservation,
    MissionOutcome,
    MissionPolicy,
    MissionRun,
    NegativeEvidenceRecord,
    NovelBehaviorRecord,
    ReasoningTraceEntry,
    TelemetrySnapshot,
)
from hunterx.domain.target_intelligence.enums import CoverageCapability, CoverageState
from hunterx.shared.time import utcnow_iso

#: Capability → assessment-phase grouping used by :meth:`OrchestratedMission.coverage_dimensions`.
_RECON_CAPABILITIES = frozenset(
    {
        "asset_discovery",
        "subdomain_enumeration",
        "dns_enumeration",
        "port_discovery",
        "service_detection",
        "technology_fingerprint",
        "certificate_enumeration",
        "endpoint_enumeration",
    }
)
_SURFACE_CAPABILITIES = frozenset(
    {
        "content_discovery",
        "javascript_analysis",
        "api_mapping",
        "parameter_discovery",
    }
)
_ACTIVE_TEST_CAPABILITIES = frozenset(
    {
        "sql_injection",
        "xss",
        "ssrf",
        "ssti",
        "xxe",
        "lfi",
        "rce",
        "idor",
        "api_security",
        "graphql_security",
        "authentication_analysis",
        "authorization_analysis",
        "secret_detection",
        "dependency_check",
        "csrf",
    }
)
_VALIDATION_CAPABILITIES = frozenset(
    {
        "vulnerability_scanning",
        "proof_validation",
        "replay",
    }
)


@dataclass(slots=True)
class OrchestratedMission:
    """The orchestration aggregate of an autonomous mission.

    Attributes:
        mission: the underlying Sprint 027 planning aggregate.
        context: persistent target-centric :class:`MissionContext`.
        policy: mission intent configuration (:class:`MissionPolicy`).
        budget: tracked resource consumption (:class:`MissionBudget`).
        observations / hypotheses / decisions / branches / runs / checkpoints:
            reasoning and evidence state.
        baselines / differential_results: baseline & differential-testing state.
        negative_evidence: bounded negative evidence records.
        impact_analyses: impact analysis for validated findings.
        novel_behaviors: novel-vulnerability pipeline records.
        trace: structured reasoning trace.
        telemetry_snapshots: mission telemetry history.
        current_phase: canonical :class:`MissionPhase`.
        outcome: final :class:`MissionOutcome`.

    """

    mission: AdaptiveMission
    context: MissionContext = field(default_factory=MissionContext)
    policy: MissionPolicy = field(default_factory=MissionPolicy)
    budget: MissionBudget = field(default_factory=MissionBudget)
    observations: list[MissionObservation] = field(default_factory=list)
    hypotheses: list[MissionHypothesis] = field(default_factory=list)
    decisions: list[MissionDecision] = field(default_factory=list)
    branches: list[MissionBranch] = field(default_factory=list)
    runs: list[MissionRun] = field(default_factory=list)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    baselines: list[BaselineObservation] = field(default_factory=list)
    differential_results: list[DifferentialResult] = field(default_factory=list)
    negative_evidence: list[NegativeEvidenceRecord] = field(default_factory=list)
    impact_analyses: list[ImpactAnalysis] = field(default_factory=list)
    novel_behaviors: list[NovelBehaviorRecord] = field(default_factory=list)
    trace: list[ReasoningTraceEntry] = field(default_factory=list)
    telemetry_snapshots: list[TelemetrySnapshot] = field(default_factory=list)
    coverage: dict[str, dict[str, CoverageCellState]] = field(default_factory=dict)
    current_phase: MissionPhase = MissionPhase.TARGET_MODELING
    outcome: MissionOutcome | None = None
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    @property
    def mission_id(self) -> str:
        """Return the mission identifier."""
        return self.mission.mission_id

    def touch(self) -> None:
        """Refresh the updated timestamp."""
        self.updated_at = utcnow_iso()

    # -- observation / hypothesis / decision indexes ------------------------

    def observation(self, observation_id: str) -> MissionObservation | None:
        """Return an observation by id or ``None``."""
        for observation in self.observations:
            if observation.observation_id == observation_id:
                return observation
        return None

    def add_observation(self, observation: MissionObservation) -> None:
        """Append a normalized observation and keep the context in sync."""
        self.observations.append(observation)
        self.context.add_observation(observation)
        self.touch()

    def hypothesis(self, hypothesis_id: str) -> MissionHypothesis | None:
        """Return a hypothesis by id or ``None``."""
        for hypothesis in self.hypotheses:
            if hypothesis.hypothesis_id == hypothesis_id:
                return hypothesis
        return None

    def upsert_hypothesis(self, hypothesis: MissionHypothesis) -> None:
        """Insert or replace a hypothesis."""
        for index, existing in enumerate(self.hypotheses):
            if existing.hypothesis_id == hypothesis.hypothesis_id:
                self.hypotheses[index] = hypothesis
                self.touch()
                return
        self.hypotheses.append(hypothesis)
        self.touch()

    def decision(self, decision_id: str) -> MissionDecision | None:
        """Return a decision by id or ``None``."""
        for decision in self.decisions:
            if decision.decision_id == decision_id:
                return decision
        return None

    def add_decision(self, decision: MissionDecision) -> None:
        """Append a decision and update the context."""
        self.decisions.append(decision)
        self.context.decisions.append(decision)
        self.touch()

    def open_hypotheses(self, *, limit: int = 20) -> list[MissionHypothesis]:
        """Return the highest-priority unresolved hypotheses."""
        open_states = ("proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior")
        candidates = [h for h in self.hypotheses if h.state.value in open_states]
        return sorted(candidates, key=lambda h: (-h.priority, -h.confidence))[:limit]

    def open_branches(self) -> list[MissionBranch]:
        """Return branches still open, ranked by priority."""
        return sorted((b for b in self.branches if b.state == "open"), key=lambda b: -b.priority)

    # -- coverage -----------------------------------------------------------

    def coverage_cell(
        self,
        asset_key: str,
        capability: CoverageCapability | str,
    ) -> CoverageCellState | None:
        """Return a coverage cell state or ``None``."""
        capability_key = capability.value if isinstance(capability, CoverageCapability) else str(capability)
        return self.coverage.get(asset_key, {}).get(capability_key)

    def record_coverage(
        self,
        *,
        asset_key: str,
        capability: CoverageCapability | str,
        state: CoverageState | str,
        tool_id: str = "",
        confidence: float = 0.0,
        evidence_refs: tuple[str, ...] = (),
        tested_at: str = "",
        notes: str = "",
    ) -> CoverageCellState:
        """Record (or replace) a coverage cell without lowering its rank."""
        capability_key = capability.value if isinstance(capability, CoverageCapability) else str(capability)
        state_enum = state if isinstance(state, CoverageState) else CoverageState(state)
        existing = self.coverage_cell(asset_key, capability_key)
        if existing is not None and existing.state.rank > state_enum.rank:
            return existing
        cell = CoverageCellState(
            cell_key=f"{asset_key}|{capability_key}",
            asset_key=asset_key,
            capability=capability_key,
            state=state_enum,
            tool_id=tool_id,
            confidence=confidence,
            evidence_refs=evidence_refs,
            tested_at=tested_at or utcnow_iso(),
            notes=notes,
        )
        self.coverage.setdefault(asset_key, {})[capability_key] = cell
        self.touch()
        return cell

    def coverage_ratio(self) -> float:
        """Return the fraction of coverage cells in a terminal state."""
        cells = [cell for asset in self.coverage.values() for cell in asset.values()]
        if not cells:
            return 0.0
        assessed = sum(1 for cell in cells if not cell.state.uncovered())
        return round(assessed / len(cells), 4)

    def coverage_cells(self) -> list[CoverageCellState]:
        """Return all coverage cells."""
        return [cell for asset in self.coverage.values() for cell in asset.values()]

    # -- coverage dimensions ------------------------------------------------

    def coverage_dimensions(self) -> dict[str, Any]:
        """Return per-dimension coverage of the full assessment lifecycle.

        A single ``coverage_ratio`` over all cells is misleading: it looks like
        full-assessment coverage when it mostly measures reconnaissance. This
        view tracks the phases separately (recon / attack surface / hypothesis
        / active test / validation / browser) plus an overall ratio. Untested
        areas remain ``NOT_ASSESSED``; absence of execution is never converted
        into negative security evidence.
        """

        def _dimension(names: frozenset[str]) -> dict[str, Any]:
            cells = [cell for cell in self.coverage_cells() if cell.capability in names]
            if not cells:
                return {"cells": 0, "assessed": 0, "coverage": 0.0}
            assessed = sum(1 for cell in cells if not cell.state.uncovered())
            return {"cells": len(cells), "assessed": assessed, "coverage": round(assessed / len(cells), 4)}

        open_states = ("proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior")
        total_hypotheses = max(1, len(self.hypotheses))
        settled_hypotheses = sum(1 for h in self.hypotheses if h.state.value not in open_states)
        recon = _dimension(_RECON_CAPABILITIES)
        surface = _dimension(_SURFACE_CAPABILITIES)
        active = _dimension(_ACTIVE_TEST_CAPABILITIES)
        validation = _dimension(_VALIDATION_CAPABILITIES)
        browser_cell = self.coverage_cell(
            self.context.target_id or "target", "browser_testing"
        )
        browser = {
            "cells": 1 if browser_cell is not None else 0,
            "assessed": 1
            if browser_cell is not None and not browser_cell.state.uncovered()
            else 0,
            "coverage": 1.0
            if browser_cell is not None and not browser_cell.state.uncovered()
            else 0.0,
            "state": browser_cell.state.value if browser_cell is not None else "not_assessed",
        }
        hypothesis = {
            "total": len(self.hypotheses),
            "settled": settled_hypotheses,
            "coverage": round(settled_hypotheses / total_hypotheses, 4),
        }
        return {
            "recon": recon,
            "attack_surface": surface,
            "hypothesis": hypothesis,
            "active_test": active,
            "validation": validation,
            "browser": browser,
            "overall": self.coverage_ratio(),
        }

    # -- telemetry ----------------------------------------------------------

    def last_telemetry(self) -> TelemetrySnapshot | None:
        """Return the most recent telemetry snapshot."""
        return self.telemetry_snapshots[-1] if self.telemetry_snapshots else None

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize the orchestration aggregate summary."""
        return {
            "mission_id": self.mission.mission_id,
            "planning": self.mission.to_dict(),
            "context": self.context.to_dict(),
            "policy": self.policy.to_dict(),
            "budget": self.budget.to_dict(),
            "current_phase": self.current_phase.value,
            "observation_count": len(self.observations),
            "hypothesis_count": len(self.hypotheses),
            "decision_count": len(self.decisions),
            "branch_count": len(self.branches),
            "open_branch_count": len(self.open_branches()),
            "run_count": len(self.runs),
            "checkpoint_count": len(self.checkpoints),
            "baseline_count": len(self.baselines),
            "differential_count": len(self.differential_results),
            "negative_evidence_count": len(self.negative_evidence),
            "impact_count": len(self.impact_analyses),
            "novel_behavior_count": len(self.novel_behaviors),
            "trace_count": len(self.trace),
            "telemetry_count": len(self.telemetry_snapshots),
            "coverage_ratio": self.coverage_ratio(),
            "outcome": self.outcome.to_dict() if self.outcome else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def coverage_dict(self) -> dict[str, Any]:
        """Serialize the mission coverage view."""
        cells = self.coverage_cells()
        by_capability: dict[str, int] = {}
        by_state: dict[str, int] = {}
        for cell in cells:
            by_capability[cell.capability] = by_capability.get(cell.capability, 0) + 1
            by_state[cell.state.value] = by_state.get(cell.state.value, 0) + 1
        return {
            "mission_id": self.mission.mission_id,
            "coverage_ratio": self.coverage_ratio(),
            "cell_count": len(cells),
            "by_capability": by_capability,
            "by_state": by_state,
            "cells": [cell.to_dict() for cell in cells],
        }


@dataclass(frozen=True, slots=True)
class CoverageCellState:
    """Coverage cell value stored inside :class:`OrchestratedMission`."""

    cell_key: str = ""
    asset_key: str = ""
    capability: str = ""
    state: CoverageState = CoverageState.NOT_ASSESSED
    tool_id: str = ""
    confidence: float = 0.0
    evidence_refs: tuple[str, ...] = ()
    tested_at: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "cell_key": self.cell_key,
            "asset_key": self.asset_key,
            "capability": self.capability,
            "state": self.state.value,
            "tool_id": self.tool_id,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "tested_at": self.tested_at,
            "notes": self.notes,
        }


def new_orchestrated_mission(
    *,
    mission: AdaptiveMission | None = None,
    scope: Any = None,
    policy: MissionPolicy | None = None,
    target_id: str = "",
) -> OrchestratedMission:
    """Create an orchestrated mission wrapping an adaptive mission."""
    if mission is None:
        mission = AdaptiveMission()
    context = MissionContext(mission_id=mission.mission_id, target_id=target_id)
    if scope is not None:
        context.scope = scope
    effective_policy = policy or MissionPolicy(
        objective_name=mission.objective.value,
    )
    return OrchestratedMission(
        mission=mission,
        context=context,
        policy=effective_policy,
        budget=MissionBudget(
            executions_budget=effective_policy.resource_budget,
            time_budget_seconds=effective_policy.time_budget_seconds,
            max_concurrency=effective_policy.max_concurrency,
        ),
    )


__all__ = [
    "CoverageCellState",
    "MissionBudget",
    "OrchestratedMission",
    "new_orchestrated_mission",
]
