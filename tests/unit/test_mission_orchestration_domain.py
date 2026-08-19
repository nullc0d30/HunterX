# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Autonomous Mission Orchestration domain.

Covers the pure domain models and engines: mission aggregate and coverage,
hypothesis loop, decision/information-gain engine, baseline & differential
testing, negative evidence, knowledge gaps, confidence, branches, telemetry,
reasoning trace, policy/stop conditions, impact analysis and finding cascades.
"""

from __future__ import annotations

from hunterx.domain.mission_orchestration.baseline import (
    BaselineEngine,
    DifferentialTestEngine,
    TestResponse,
)
from hunterx.domain.mission_orchestration.branch import BranchManager
from hunterx.domain.mission_orchestration.cascade import CascadeTrigger, FindingCascadeEngine
from hunterx.domain.mission_orchestration.confidence import ConfidenceEngine, ConfidenceInput
from hunterx.domain.mission_orchestration.decision import (
    CandidateAction,
    DecisionInput,
    MissionDecisionEngine,
)
from hunterx.domain.mission_orchestration.enums import (
    BehaviorClass,
    DifferentialSignal,
    HypothesisState,
    NegativeEvidenceKind,
    NovelPipelineStage,
    StopCondition,
    StrategyKind,
)
from hunterx.domain.mission_orchestration.gap import KnowledgeGapEngine
from hunterx.domain.mission_orchestration.hypothesis import HypothesisLoopEngine
from hunterx.domain.mission_orchestration.impact import ImpactAnalysisEngine
from hunterx.domain.mission_orchestration.mission import (
    CoverageCellState,
    new_orchestrated_mission,
)
from hunterx.domain.mission_orchestration.models import (
    MissionHypothesis,
    MissionPolicy,
    MissionScope,
)
from hunterx.domain.mission_orchestration.negative import NegativeEvidenceEngine
from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine
from hunterx.domain.mission_orchestration.telemetry import MissionTelemetry
from hunterx.domain.mission_orchestration.trace import ReasoningTrace
from hunterx.domain.target_intelligence.enums import CoverageState, HypothesisType


class TestHypothesisLoop:
    def test_proposed_to_weakly_supported(self) -> None:
        engine = HypothesisLoopEngine()
        hypothesis = engine.hypothesize(mission_id="m1", statement="SQLi on /search")
        updated = engine.update(hypothesis, supporting=("ev1",))
        assert updated.state is HypothesisState.WEAKLY_SUPPORTED

    def test_supported_threshold(self) -> None:
        engine = HypothesisLoopEngine()
        hypothesis = engine.hypothesize(mission_id="m1", statement="XSS reflected")
        updated = engine.update(hypothesis, supporting=("ev1", "ev2"))
        assert updated.state is HypothesisState.SUPPORTED

    def test_validated_requires_threshold_and_no_contradiction(self) -> None:
        engine = HypothesisLoopEngine()
        hypothesis = engine.hypothesize(mission_id="m1", statement="SQLi confirmed")
        updated = engine.update(hypothesis, supporting=("ev1", "ev2"))
        assert updated.state is HypothesisState.SUPPORTED
        verified = engine.verify(updated, reproducible=True)
        assert verified.state is HypothesisState.VALIDATED
        proved = engine.prove(verified, proof_ref="poc:1")
        assert proved.state is HypothesisState.VALIDATED
        assert proved.provenance.get("proof_ref") == "poc:1"

    def test_refuted_by_contradiction(self) -> None:
        engine = HypothesisLoopEngine()
        hypothesis = engine.hypothesize(mission_id="m1", statement="SQLi")
        updated = engine.update(hypothesis, contradicting=("ev1",))
        assert updated.state is HypothesisState.REFUTED

    def test_disproved_when_contradiction_outweighs(self) -> None:
        engine = HypothesisLoopEngine()
        hypothesis = engine.hypothesize(mission_id="m1", statement="SQLi")
        updated = engine.update(hypothesis, supporting=("ev1",), contradicting=("e2", "e3"))
        assert updated.state is HypothesisState.DISPROVED

    def test_verify_downgrades_unreproducible(self) -> None:
        engine = HypothesisLoopEngine()
        hypothesis = engine.hypothesize(mission_id="m1", statement="SQLi")
        updated = engine.update(hypothesis, supporting=("ev1", "ev2"))
        verified = engine.verify(updated, reproducible=False)
        assert verified.state is HypothesisState.SUPPORTED

    def test_novel_pipeline_advances(self) -> None:
        engine = HypothesisLoopEngine()
        record = engine.start_novel(mission_id="m1", asset_key="url:x", behavior_summary="weird")
        record = engine.advance_novel(record, experiments=("exp-1",))
        assert record.stage is NovelPipelineStage.BEHAVIORAL_MODEL
        for _ in range(10):
            record = engine.advance_novel(record, proof_ref="poc:1")
        assert record.stage is NovelPipelineStage.VALIDATED_BEHAVIOR
        assert record.classification is BehaviorClass.NOVEL_VALIDATED


class TestDecisionEngine:
    def _candidates(self) -> tuple[CandidateAction, ...]:
        return (
            CandidateAction(
                action_id="a1",
                capability="sql_injection",
                tool_ids=("sqlmap", "ghauri"),
                expected_information_gain=0.9,
                cost=0.2,
                hypothesis_discrimination=0.8,
            ),
            CandidateAction(
                action_id="a2",
                capability="xss",
                tool_ids=("dalfox",),
                expected_information_gain=0.4,
                cost=0.1,
                hypothesis_discrimination=0.2,
            ),
        )

    def test_ranks_by_information_gain(self) -> None:
        engine = MissionDecisionEngine()
        decision = engine.decide(DecisionInput(mission_id="m1", candidates=self._candidates()))
        assert decision is not None
        assert decision.next_action == "a1"
        assert decision.tool_id == "sqlmap"
        assert decision.information_gain > 0.5
        assert decision.alternatives  # contains a2 with why-not

    def test_negative_evidence_lowers_ranking(self) -> None:
        engine = MissionDecisionEngine()
        negative_engine = NegativeEvidenceEngine()
        negative = negative_engine.record(
            mission_id="m1",
            asset_key="url:x",
            capability="sql_injection",
            kind=NegativeEvidenceKind.NOT_REPRODUCIBLE,
            tool_id="sqlmap",
            outcome="no injection",
        )
        inp = DecisionInput(
            mission_id="m1",
            candidates=self._candidates(),
            negative_evidence=(negative, negative, negative),
        )
        decision = engine.decide(inp)
        assert decision is not None
        # repeated failures on the same capability reduce reliability
        assert decision.factors["information_gain"] < 0.9

    def test_empty_candidates_return_none(self) -> None:
        engine = MissionDecisionEngine()
        assert engine.decide(DecisionInput(mission_id="m1", candidates=())) is None

    def test_strategy_weights_are_deterministic(self) -> None:
        engine = MissionDecisionEngine()
        first = engine.rank(DecisionInput(mission_id="m1", candidates=self._candidates(), strategy=StrategyKind.RISK_FIRST))
        second = engine.rank(DecisionInput(mission_id="m1", candidates=self._candidates(), strategy=StrategyKind.RISK_FIRST))
        assert [item[0].action_id for item in first] == [item[0].action_id for item in second]


class TestBaselineDifferential:
    def test_baseline_capture_and_match(self) -> None:
        engine = BaselineEngine()
        baseline = engine.capture(
            mission_id="m1",
            asset_key="url:/search",
            request_fingerprint="GET /search?q=1",
            status_code=200,
            content_length=100,
        )
        assert engine.match(asset_key="url:/search", request_fingerprint="GET /search?q=1") is baseline

    def test_differential_detects_sqli_signals(self) -> None:
        engine = DifferentialTestEngine()
        baseline = BaselineEngine().capture(
            mission_id="m1",
            asset_key="url:/search",
            status_code=200,
            content_length=100,
        )
        result = engine.compare(
            mission_id="m1",
            asset_key="url:/search",
            baseline=baseline,
            test=TestResponse(status_code=500, content_length=300, body="SQL syntax error near hunterxprobe"),
            classification_hint="sql_injection",
        )
        assert DifferentialSignal.STATUS_CHANGE in result.signals
        assert DifferentialSignal.ERROR_BEHAVIOR in result.signals
        assert result.evidence_classification == "sql_injection_indicative"

    def test_differential_no_delta(self) -> None:
        engine = DifferentialTestEngine()
        baseline = BaselineEngine().capture(
            mission_id="m1", asset_key="url:x", status_code=200, content_length=50
        )
        result = engine.compare(
            mission_id="m1",
            asset_key="url:x",
            baseline=baseline,
            test=TestResponse(status_code=200, content_length=50, body="same"),
        )
        assert DifferentialSignal.NO_DELTA in result.signals


class TestNegativeEvidence:
    def test_deduplicates_by_input(self) -> None:
        engine = NegativeEvidenceEngine()
        first = engine.record(
            mission_id="m1", asset_key="url:x", capability="xss", tool_id="dalfox", input="<script>", outcome="none"
        )
        second = engine.record(
            mission_id="m1", asset_key="url:x", capability="xss", tool_id="dalfox", input="<script>", outcome="none"
        )
        assert first.record_id == second.record_id
        assert len(engine.all()) == 1

    def test_known_absent_does_not_claim_not_vulnerable(self) -> None:
        engine = NegativeEvidenceEngine()
        engine.record(mission_id="m1", asset_key="url:x", capability="xss", tool_id="dalfox", outcome="no reflection")
        assert engine.known_absent("url:x", "xss", tool_id="dalfox") is True
        # a different tool has not been tried
        assert engine.known_absent("url:x", "xss", tool_id="burp") is False


class TestConfidence:
    def test_confidence_requires_independent_evidence(self) -> None:
        engine = ConfidenceEngine()
        weak = engine.compute(ConfidenceInput(detection_evidence=0.9))
        strong = engine.compute(
            ConfidenceInput(
                detection_evidence=0.9,
                behavioral_evidence=0.8,
                independent_verification=1.0,
                reproducibility=1.0,
                tool_reliability=0.9,
                corroboration=3,
            )
        )
        assert strong.score > weak.score
        assert strong.verdict == "independently verified and reproduced"


class TestKnowledgeGaps:
    def test_analyze_returns_open_hypothesis_gap(self) -> None:
        engine = KnowledgeGapEngine()
        mission = new_orchestrated_mission()
        mission.upsert_hypothesis(
            MissionHypothesis(
                mission_id=mission.mission_id,
                statement="open hypothesis",
                category=HypothesisType.INJECTION,
                priority=0.9,
            )
        )
        gaps = engine.analyze(mission)
        assert any(gap.category == "hypothesis_evidence" for gap in gaps)


class TestBranches:
    def test_branch_lifecycle(self) -> None:
        manager = BranchManager()
        branch = manager.create(
            mission_id="m1", hypothesis_id="h1", rationale="two paths", priority=0.8
        )
        branch = manager.record_action(branch, "a1", cost=0.1)
        branch = manager.resolve(branch, outcome="validated")
        assert branch.state == "resolved"
        assert manager.rank([branch]) == []


class TestCoverage:
    def test_coverage_ratio_never_downgrades(self) -> None:
        mission = new_orchestrated_mission()
        mission.record_coverage(
            asset_key="url:x", capability="sql_injection", state=CoverageState.VALIDATED, tool_id="sqlmap"
        )
        mission.record_coverage(
            asset_key="url:x", capability="sql_injection", state=CoverageState.TESTED, tool_id="other"
        )
        assert mission.coverage_cell("url:x", "sql_injection").state is CoverageState.VALIDATED
        assert mission.coverage_ratio() == 1.0

    def test_coverage_state_object(self) -> None:
        cell = CoverageCellState(
            cell_key="a|b", asset_key="a", capability="b", state=CoverageState.PROVED
        )
        assert cell.to_dict()["state"] == "proved"


class TestPolicies:
    def test_stop_condition_budget_exhausted(self) -> None:
        mission = new_orchestrated_mission()
        mission.policy = MissionPolicy(stop_conditions=(StopCondition.RESOURCE_BUDGET_EXHAUSTED,))
        mission.budget.executions_budget = 1
        mission.budget.executions_used = 1
        engine = MissionPolicyEngine()
        assert engine.evaluate_stop(mission) is StopCondition.RESOURCE_BUDGET_EXHAUSTED

    def test_scope_gate(self) -> None:
        mission = new_orchestrated_mission()
        mission.context.scope = MissionScope(
            included_targets=("example.com",), excluded_assets=("admin.example.com",)
        )
        engine = MissionPolicyEngine()
        allowed = engine.check_action(mission, capability="scan", target="api.example.com")
        blocked = engine.check_action(mission, capability="scan", target="admin.example.com")
        assert allowed.allowed is True
        assert blocked.allowed is False

    def test_findings_validated_blocked_while_high_value_hypothesis_open(self) -> None:
        mission = new_orchestrated_mission()
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        mission.context.findings = [{"finding_id": "f1", "stage": "report_ready"}]
        mission.upsert_hypothesis(
            MissionHypothesis(
                mission_id=mission.mission_id,
                statement="The /api/search q parameter may be susceptible to SQL injection",
                category=HypothesisType.INJECTION,
                priority=0.8,
            )
        )
        engine = MissionPolicyEngine()
        stop = engine.evaluate_stop(mission)
        assert stop is None

    def test_findings_validated_fires_when_no_high_value_hypotheses_open(self) -> None:
        mission = new_orchestrated_mission()
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        mission.context.findings = [{"finding_id": "f1", "stage": "report_ready"}]
        engine = MissionPolicyEngine()
        assert engine.evaluate_stop(mission) is StopCondition.FINDINGS_VALIDATED

    def test_findings_validated_fires_once_high_value_hypotheses_resolved(self) -> None:
        mission = new_orchestrated_mission()
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        mission.context.findings = [{"finding_id": "f1", "stage": "report_ready"}]
        mission.upsert_hypothesis(
            MissionHypothesis(
                mission_id=mission.mission_id,
                statement="The /api/search q parameter may be susceptible to SQL injection",
                category=HypothesisType.INJECTION,
                priority=0.8,
                state=HypothesisState.REFUTED,
            )
        )
        engine = MissionPolicyEngine()
        assert engine.evaluate_stop(mission) is StopCondition.FINDINGS_VALIDATED

    def test_findings_validated_never_fires_without_findings(self) -> None:
        mission = new_orchestrated_mission()
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        engine = MissionPolicyEngine()
        assert engine.evaluate_stop(mission) is None

    def test_findings_validated_requires_terminal_findings(self) -> None:
        mission = new_orchestrated_mission()
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        mission.context.findings = [{"finding_id": "f1", "stage": "candidate"}]
        engine = MissionPolicyEngine()
        assert engine.evaluate_stop(mission) is None


class TestTelemetry:
    def test_snapshot_produces_metrics(self) -> None:
        mission = new_orchestrated_mission()
        mission.budget.executions_used = 10
        mission.context.findings = [
            {"finding_id": "f1", "stage": "report_ready"},
            {"finding_id": "f2", "stage": "candidate"},
        ]
        snapshot = MissionTelemetry().snapshot(mission)
        assert snapshot.finding_yield == 0.5
        assert snapshot.tool_executions == 10


class TestReasoningTrace:
    def test_trace_chain_reconstruction(self) -> None:
        trace = ReasoningTrace()
        obs = trace.record(mission_id="m1", kind="observation", node_id="o1", content={"type": "asset"})
        hyp = trace.record(
            mission_id="m1",
            kind="hypothesis",
            node_id="h1",
            content={"statement": "x"},
            parent_entry_id=obs.entry_id,
        )
        decision = trace.record(
            mission_id="m1",
            kind="decision",
            node_id="d1",
            content={"next": "a1"},
            parent_entry_id=hyp.entry_id,
        )
        chain = trace.chain_for(decision.entry_id)
        assert [entry.node_id for entry in chain] == ["o1", "h1", "d1"]


class TestImpactAndCascade:
    def test_impact_analysis_for_sqli(self) -> None:
        engine = ImpactAnalysisEngine()
        analysis = engine.analyze(
            finding={
                "finding_id": "f1",
                "vulnerability_class": "sql_injection",
                "asset_key": "url:/search",
                "severity": "critical",
            },
            mission_id="m1",
            confidence=0.9,
        )
        assert "database" in analysis.technical_impact
        assert analysis.confidence == 0.9
        assert analysis.reproducibility is True

    def test_cascade_ssrf_opens_follow_ons(self) -> None:
        engine = FindingCascadeEngine()
        hypotheses = engine.cascade(
            CascadeTrigger(finding_id="f1", vulnerability_class="ssrf", asset_key="url:/fetch")
        )
        assert len(hypotheses) == 2
        assert all(hypothesis.priority >= 0.7 for hypothesis in hypotheses)

    def test_cascade_sql_injection_opens_follow_ons(self) -> None:
        engine = FindingCascadeEngine()
        hypotheses = engine.cascade(
            CascadeTrigger(finding_id="f1", vulnerability_class="sql_injection", asset_key="url:/search")
        )
        assert len(hypotheses) == 2
