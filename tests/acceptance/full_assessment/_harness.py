# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared harness for the Sprint 033 full-spectrum mission acceptance tests.

The harness drives a deterministic, synthetic target environment through the
autonomous mission orchestrator. Each full-spectrum mission (bug bounty, web
pentest, API security, attack surface, cloud/SaaS, vulnerability research, red
team recon) supplies its own scenario: objective, target, synthetic tool
responses, capability sequence and expected final state.

The harness deliberately reuses the orchestrator's reasoning loop
(ingest → hypothesize → test → validate → prove → impact → cascade → coverage)
rather than a hardcoded tool sequence. Tool failures, contradictory results and
false positives are injected per scenario to prove DETECTION != VALIDATION.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.mission_orchestration.enums import FindingStage, StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.target_intelligence.enums import CoverageState


@dataclass
class ToolScenario:
    """A synthetic tool execution contract used by a mission scenario.

    Attributes:
        capability: the capability the tool serves.
        tool_id: the canonical tool id (e.g. ``subfinder``).
        asset_key: the asset the tool targets.
        result: the raw result dict the synthetic environment returns.
        failure: when set, the tool returns an error payload instead.
        post: optional post-processing hook ``(runner, mission_id, scenario)``.
    """

    capability: str
    tool_id: str
    asset_key: str
    result: dict[str, Any] = field(default_factory=dict)
    failure: dict[str, Any] | None = None
    post: Any | None = None


@dataclass
class MissionScenario:
    """A complete full-spectrum mission scenario.

    Attributes:
        name: scenario name.
        objective: orchestration objective name.
        target: authorized target.
        description: human-readable mission description.
        scenarios: ordered list of synthetic tool executions.
        expected: expected final state assertions.
    """

    name: str
    objective: str
    target: str
    description: str = ""
    scenarios: list[ToolScenario] = field(default_factory=list)
    expected: dict[str, Any] = field(default_factory=dict)

    def add(self, scenario: ToolScenario) -> MissionScenario:
        """Append a tool scenario and return the scenario for chaining."""
        self.scenarios.append(scenario)
        return self


class FullSpectrumMissionRunner:
    """Drive a :class:`MissionScenario` through the orchestrator.

    The runner executes the scenario's synthetic tool executions in order,
    feeds observations/hypotheses/findings/coverage into the orchestrator,
    applies post-processing hooks and finalizes the mission.
    """

    def __init__(self, scenario: MissionScenario) -> None:
        self.scenario = scenario
        self.orchestrator = MissionOrchestrator()
        self.mission = None
        self._finding_seq = 0

    def run(self) -> dict[str, Any]:
        """Run the full scenario and return the mission summary."""
        import dataclasses


        self.mission = self.orchestrator.create_mission(
            objective=self.scenario.objective,
            target=self.scenario.target,
            strategy="adaptive",
        )
        # Raise the coverage target and only allow objective/budget stops so
        # every scenario step executes deterministically.
        self.mission.policy = dataclasses.replace(
            self.mission.policy,
            coverage_target=0.99,
            stop_conditions=(
                StopCondition.OBJECTIVES_COMPLETE,
                StopCondition.COVERAGE_TARGET_ACHIEVED,
                StopCondition.RESOURCE_BUDGET_EXHAUSTED,
                StopCondition.TIME_BUDGET_EXHAUSTED,
            ),
        )
        mission_id = self.mission.mission_id
        self.orchestrator.start(mission_id)
        self.orchestrator.record_coverage(
            mission_id,
            asset_key=self.scenario.target,
            capability="asset_discovery",
            state=CoverageState.CANDIDATE,
            tool_id="seed",
        )

        for step in self.scenario.scenarios:
            self._execute(mission_id, step)

        self.orchestrator.finalize(mission_id)
        return self.orchestrator.get(mission_id).to_dict()

    # -- helpers -------------------------------------------------------------

    def register_finding(
        self,
        mission_id: str,
        *,
        vulnerability_class: str,
        asset_key: str,
        severity: str = "high",
        tool: str = "",
        stage: FindingStage | str = FindingStage.PROVEN,
        confidence: float = 0.9,
        evidence_refs: tuple[str, ...] = (),
        title: str = "",
    ) -> None:
        """Register a finding and analyze its impact."""
        finding_id = f"F-{self.scenario.name.upper()}-{self._finding_seq}"
        self._finding_seq += 1
        self.orchestrator.register_finding(
            mission_id,
            finding_id=finding_id,
            vulnerability_class=vulnerability_class,
            asset_key=asset_key,
            severity=severity,
            tool=tool,
            stage=stage,
            confidence=confidence,
            evidence_refs=evidence_refs,
            title=title or f"{vulnerability_class} on {asset_key}",
        )
        self.orchestrator.analyze_impact(
            mission_id,
            finding={
                "finding_id": finding_id,
                "vulnerability_class": vulnerability_class,
                "asset_key": asset_key,
                "severity": severity,
            },
            confidence=confidence,
        )

    def support_hypothesis(
        self,
        mission_id: str,
        *,
        statement: str,
        supporting: tuple[str, ...],
        verify: bool = True,
    ) -> None:
        """Add a hypothesis and (optionally) verify it with supporting evidence."""
        hypothesis = self.orchestrator.add_hypothesis(
            mission_id,
            statement=statement,
            category="unknown_behavior",
            priority=0.8,
        )
        self.orchestrator.update_hypothesis(
            mission_id,
            hypothesis.hypothesis_id,
            supporting=supporting,
        )
        if verify:
            self.orchestrator.verify_hypothesis(
                mission_id, hypothesis.hypothesis_id, reproducible=True
            )

    def record_proof_coverage(
        self,
        mission_id: str,
        *,
        asset_key: str,
        capability: str,
        tool_id: str,
        evidence_refs: tuple[str, ...] = (),
        confidence: float = 0.95,
    ) -> None:
        """Record proof/validation coverage for a validated finding."""
        self.orchestrator.record_coverage(
            mission_id,
            asset_key=asset_key,
            capability=capability,
            state=CoverageState.PROVED,
            tool_id=tool_id,
            confidence=confidence,
            evidence_refs=evidence_refs,
        )

    def record_negative(
        self,
        mission_id: str,
        *,
        asset_key: str,
        capability: str,
        kind: str = "not_vulnerable",
        tool_id: str = "",
        outcome: str = "no exploitation observed",
    ) -> None:
        """Record bounded negative evidence (a false positive or non-exploit)."""
        self.orchestrator.record_negative(
            mission_id,
            asset_key=asset_key,
            capability=capability,
            kind=kind,
            tool_id=tool_id,
            outcome=outcome,
        )

    # -- internals -----------------------------------------------------------

    def _execute(self, mission_id: str, step: ToolScenario) -> None:
        if step.failure is not None:
            self.orchestrator.record_negative(
                mission_id,
                asset_key=step.asset_key,
                capability=step.capability,
                kind="blocked",
                tool_id=step.tool_id,
                outcome=str(step.failure.get("error", "tool failure")),
            )
            self.orchestrator.record_coverage(
                mission_id,
                asset_key=step.asset_key,
                capability=step.capability,
                state=CoverageState.TESTED,
                tool_id=step.tool_id,
                confidence=0.0,
            )
            return

        self.orchestrator.ingest_result(
            mission_id,
            tool_id=step.tool_id,
            asset_key=step.asset_key,
            raw=step.result,
        )
        if step.post is not None:
            step.post(self, mission_id, step)
        self.orchestrator.record_coverage(
            mission_id,
            asset_key=step.asset_key,
            capability=step.capability,
            state=CoverageState.VALIDATED,
            tool_id=step.tool_id,
            confidence=float(step.result.get("confidence", 0.7)),
        )


__all__ = [
    "FullSpectrumMissionRunner",
    "MissionScenario",
    "ToolScenario",
]
