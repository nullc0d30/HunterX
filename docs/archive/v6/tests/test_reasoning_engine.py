from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from core.reasoning.goals import Goal, GoalType, GoalPriority, GoalStatus
from core.reasoning.prompts import ReasoningPromptManager, PromptTemplate
from core.reasoning.policies import ReasoningPolicy, ReasoningSafetyLevel, PolicyManager
from core.reasoning.validator import OutputValidator
from core.reasoning.formatter import ReasoningFormatter, ReasoningResult
from core.reasoning.confidence import ConfidenceScorer, ConfidenceLevel
from core.reasoning.consensus import ConsensusEngine, ConsensusMethod, IndividualResponse
from core.reasoning.memory import ReasoningMemory
from core.reasoning.planner import ReasoningPlanner
from core.reasoning.engine import ReasoningOrchestrator


class TestGoal:
    def test_create_default(self):
        g = Goal.create(GoalType.RECON, "test objective")
        assert g.id
        assert g.type == GoalType.RECON
        assert g.objective == "test objective"
        assert g.status == GoalStatus.PENDING

    def test_create_with_all_fields(self):
        g = Goal.create(
            GoalType.THREAT_MODELING,
            "threat model",
            context={"target": "example.com"},
            priority=GoalPriority.CRITICAL,
            source_agent="test_agent",
            confidence_requirement=0.9,
        )
        assert g.type == GoalType.THREAT_MODELING
        assert g.context == {"target": "example.com"}
        assert g.priority == GoalPriority.CRITICAL
        assert g.source_agent == "test_agent"
        assert g.confidence_requirement == 0.9

    def test_to_dict(self):
        g = Goal.create(GoalType.PAYLOAD_SELECTION, "pick payload")
        d = g.to_dict()
        assert d["type"] == "payload_selection"
        assert d["objective"] == "pick payload"
        assert d["priority"] == "medium"
        assert d["status"] == "pending"

    def test_goal_status_transition(self):
        g = Goal.create(GoalType.RECON, "test")
        assert g.status == GoalStatus.PENDING
        g.status = GoalStatus.PROCESSING
        assert g.status == GoalStatus.PROCESSING
        g.status = GoalStatus.COMPLETED
        assert g.status == GoalStatus.COMPLETED


class TestReasoningPromptManager:
    def test_default_templates_exist(self):
        templates = ReasoningPromptManager.list_templates()
        assert len(templates) >= 10

    def test_get_template(self):
        t = ReasoningPromptManager.get("threat_modeling")
        assert t is not None
        assert t.name == "threat_modeling"
        assert t.category == "threat_modeling"

    def test_format_template(self):
        result = ReasoningPromptManager.format(
            "payload_selection",
            vulnerability_type="SQLI",
            technology="MySQL",
            framework="Django",
            previous_attempts="none",
            waf_present="false",
        )
        assert "system" in result
        assert "user" in result
        assert "SQLI" in result["user"]

    def test_register_custom_template(self):
        t = PromptTemplate(
            name="custom_test",
            category="test",
            system_prompt="Test system",
            user_prompt_template="Test user: {var}",
            variables=["var"],
        )
        ReasoningPromptManager.register(t)
        assert ReasoningPromptManager.get("custom_test") is not None

    def test_list_by_category(self):
        reporting = ReasoningPromptManager.list_templates(category="reporting")
        assert len(reporting) >= 2

    def test_format_missing_template(self):
        with pytest.raises(ValueError):
            ReasoningPromptManager.format("nonexistent_template")


class TestReasoningPolicy:
    def test_default_policy(self):
        p = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        assert p.name == "balanced"
        assert p.min_confidence == 0.7
        assert p.allow_fallback is True
        assert p.validate_output is True

    def test_safest_policy(self):
        p = PolicyManager.from_safety_level(ReasoningSafetyLevel.SAFEST)
        assert p.min_confidence == 0.95
        assert p.allow_fallback is False
        assert p.min_consensus_providers == 3

    def test_research_policy(self):
        p = PolicyManager.from_safety_level(ReasoningSafetyLevel.RESEARCH)
        assert p.min_confidence == 0.3
        assert p.require_evidence is False

    def test_register_custom(self):
        p = ReasoningPolicy(name="custom", safety_level=ReasoningSafetyLevel.CONSERVATIVE, min_confidence=0.8)
        PolicyManager.register(p)
        retrieved = PolicyManager.get("custom")
        assert retrieved is not None
        assert retrieved.min_confidence == 0.8

    def test_list_policies(self):
        policies = PolicyManager.list_policies()
        assert len(policies) >= 5


class TestOutputValidator:
    def test_valid_output(self):
        policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        result = OutputValidator.validate("This is a valid security analysis finding.", policy)
        assert result.valid is True
        assert result.confidence > 0.5

    def test_hallucination_detection(self):
        policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        result = OutputValidator.validate("I cannot help with that as an AI assistant.", policy)
        assert len(result.warnings) > 0

    def test_short_output(self):
        policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        result = OutputValidator.validate("Hi", policy)
        assert result.valid is False

    def test_json_schema_validation(self):
        policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        result = OutputValidator.validate('{"finding": "SQLI", "severity": "high"}', policy)
        assert result.valid is True

    def test_json_schema_missing_field(self):
        policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        result = OutputValidator.validate('{"finding": "SQLI"}', policy)
        assert result.valid is True

    def test_normalize_response(self):
        result = OutputValidator.normalize_response('{"a": 1}')
        assert result == {"a": 1}

    def test_normalize_plain_text(self):
        result = OutputValidator.normalize_response("plain text")
        assert result["text"] == "plain text"


class TestConfidenceScorer:
    def test_from_score_certain(self):
        assert ConfidenceScorer.from_score(0.99) == ConfidenceLevel.CERTAIN

    def test_from_score_high(self):
        assert ConfidenceScorer.from_score(0.90) == ConfidenceLevel.HIGH

    def test_from_score_medium(self):
        assert ConfidenceScorer.from_score(0.75) == ConfidenceLevel.MEDIUM

    def test_from_score_low(self):
        assert ConfidenceScorer.from_score(0.55) == ConfidenceLevel.LOW

    def test_from_score_uncertain(self):
        assert ConfidenceScorer.from_score(0.40) == ConfidenceLevel.UNCERTAIN

    def test_from_score_conflicting(self):
        assert ConfidenceScorer.from_score(0.05) == ConfidenceLevel.CONFLICTING

    def test_aggregate_mean(self):
        assert ConfidenceScorer.aggregate([0.8, 0.9, 0.7]) == pytest.approx(0.8)

    def test_aggregate_max(self):
        assert ConfidenceScorer.aggregate([0.5, 0.9, 0.7], method="max") == 0.9

    def test_aggregate_min(self):
        assert ConfidenceScorer.aggregate([0.5, 0.9, 0.7], method="min") == 0.5

    def test_aggregate_median(self):
        assert ConfidenceScorer.aggregate([0.5, 0.9, 0.7], method="median") == 0.7

    def test_adjust_for_conflict(self):
        score = ConfidenceScorer.adjust_for_conflict(0.9, 2)
        assert score < 0.9
        assert score > 0.6

    def test_empty_list(self):
        assert ConfidenceScorer.aggregate([]) == 0.0


class TestConsensusEngine:
    def test_single_response(self):
        engine = ConsensusEngine()
        responses = [IndividualResponse(provider="p1", model="m1", content="result", confidence=0.9, latency_ms=100)]
        result = engine.reach_consensus(responses)
        assert result.agreement == 0.9
        assert result.final_response == "result"

    def test_majority_vote(self):
        engine = ConsensusEngine()
        responses = [
            IndividualResponse(provider="p1", model="m1", content="A", confidence=0.8, latency_ms=100),
            IndividualResponse(provider="p2", model="m2", content="A", confidence=0.7, latency_ms=200),
            IndividualResponse(provider="p3", model="m3", content="B", confidence=0.9, latency_ms=150),
        ]
        result = engine.reach_consensus(responses, ConsensusMethod.MAJORITY_VOTE)
        assert result.final_response == "A"
        assert result.agreement == pytest.approx(2/3)
        assert result.provider_count == 3

    def test_weighted_vote(self):
        engine = ConsensusEngine()
        responses = [
            IndividualResponse(provider="p1", model="m1", content="A", confidence=0.9, latency_ms=100),
            IndividualResponse(provider="p2", model="m2", content="B", confidence=0.5, latency_ms=200),
        ]
        result = engine.reach_consensus(responses, ConsensusMethod.WEIGHTED_VOTE)
        assert result.final_response == "A"

    def test_confidence_aggregation(self):
        engine = ConsensusEngine()
        responses = [
            IndividualResponse(provider="p1", model="m1", content="A", confidence=0.8, latency_ms=100),
            IndividualResponse(provider="p2", model="m2", content="B", confidence=0.6, latency_ms=200),
        ]
        result = engine.reach_consensus(responses, ConsensusMethod.CONFIDENCE_AGGREGATION)
        assert result.final_response == "A"
        assert result.agreement == pytest.approx(0.7)

    def test_empty_responses(self):
        engine = ConsensusEngine()
        result = engine.reach_consensus([])
        assert result.agreement == 0.0
        assert result.final_response == ""

    def test_detect_conflicts(self):
        engine = ConsensusEngine()
        responses = [
            IndividualResponse(provider="p1", model="m1", content="A", confidence=0.9, latency_ms=100),
            IndividualResponse(provider="p2", model="m2", content="B", confidence=0.4, latency_ms=200),
        ]
        conflicts = engine.detect_conflicts(responses)
        assert len(conflicts) > 0


class TestReasoningMemory:
    def test_store_and_retrieve(self):
        memory = ReasoningMemory()
        result = ReasoningResult(
            goal_id="g1", goal_type="recon", objective="test",
            response="result", confidence=0.9, confidence_level=ConfidenceLevel.HIGH,
            provider="p1", model="m1", latency_ms=100, cost=0.001,
        )
        memory.store(result)
        entry = memory.retrieve("g1")
        assert entry is not None
        assert entry.goal_id == "g1"
        assert entry.response == "result"

    def test_retrieve_missing(self):
        memory = ReasoningMemory()
        assert memory.retrieve("nonexistent") is None

    def test_search(self):
        memory = ReasoningMemory()
        r1 = ReasoningResult(goal_id="g1", goal_type="recon", objective="find SQL injection", response="SQLI found", confidence=0.9, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0)
        r2 = ReasoningResult(goal_id="g2", goal_type="recon", objective="find XSS", response="XSS found", confidence=0.8, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0)
        memory.store(r1)
        memory.store(r2)
        results = memory.search("SQL")
        assert len(results) >= 1
        assert any(r.goal_id == "g1" for r in results)

    def test_get_recent(self):
        memory = ReasoningMemory()
        r1 = ReasoningResult(goal_id="g1", goal_type="recon", objective="test1", response="r1", confidence=0.9, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0)
        r2 = ReasoningResult(goal_id="g2", goal_type="recon", objective="test2", response="r2", confidence=0.8, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0)
        memory.store(r1)
        memory.store(r2)
        recent = memory.get_recent(limit=1)
        assert len(recent) == 1

    def test_clear(self):
        memory = ReasoningMemory()
        r = ReasoningResult(goal_id="g1", goal_type="recon", objective="test", response="r", confidence=0.9, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0)
        memory.store(r)
        memory.clear()
        assert memory.retrieve("g1") is None

    def test_get_stats(self):
        memory = ReasoningMemory()
        r = ReasoningResult(goal_id="g1", goal_type="recon", objective="test", response="r", confidence=0.9, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0)
        memory.store(r)
        stats = memory.get_stats()
        assert stats["total_entries"] == 1
        assert stats["active_entries"] == 1

    def test_eviction(self):
        memory = ReasoningMemory(max_entries=2)
        for i in range(5):
            r = ReasoningResult(goal_id=f"g{i}", goal_type="recon", objective=f"test{i}", response=f"r{i}", confidence=0.1, confidence_level=ConfidenceLevel.LOW, provider="p1", model="m1", latency_ms=100, cost=0)
            memory.store(r)
        assert memory.get_stats()["total_entries"] <= 2


class TestReasoningPlanner:
    def test_create_plan(self):
        planner = ReasoningPlanner()
        goals = [
            Goal.create(GoalType.RECON, "recon", priority=GoalPriority.HIGH),
            Goal.create(GoalType.THREAT_MODELING, "threat model", priority=GoalPriority.CRITICAL),
        ]
        plan = planner.create_plan(goals)
        assert plan.total_goals == 2
        assert plan.goals[0].priority == GoalPriority.CRITICAL

    def test_prioritize_goals(self):
        planner = ReasoningPlanner()
        goals = [
            Goal.create(GoalType.RECON, "recon", priority=GoalPriority.LOW),
            Goal.create(GoalType.THREAT_MODELING, "tm", priority=GoalPriority.CRITICAL),
            Goal.create(GoalType.PLANNING, "plan", priority=GoalPriority.HIGH),
        ]
        ordered = planner.prioritize_goals(goals)
        assert ordered[0].priority == GoalPriority.CRITICAL
        assert ordered[1].priority == GoalPriority.HIGH
        assert ordered[2].priority == GoalPriority.LOW

    def test_get_plan(self):
        planner = ReasoningPlanner()
        plan = planner.create_plan([])
        retrieved = planner.get_plan(plan.id)
        assert retrieved is not None
        assert retrieved.id == plan.id

    def test_estimate_cost(self):
        planner = ReasoningPlanner()
        goal = Goal.create(GoalType.RECON, "test")
        cost = planner.estimate_cost(goal)
        assert cost > 0


class TestReasoningFormatter:
    def test_format_result_summary(self):
        results = [
            ReasoningResult(goal_id="g1", goal_type="recon", objective="test", response="r", confidence=0.9, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0),
        ]
        summary = ReasoningFormatter.format_result_summary(results)
        assert "Reasoning Summary" in summary

    def test_format_decision_trace(self):
        goal = Goal.create(GoalType.RECON, "test")
        result = ReasoningResult(goal_id=goal.id, goal_type="recon", objective="test", response="r", confidence=0.9, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0)
        trace = ReasoningFormatter.format_decision_trace(goal, result)
        assert "Decision Trace" in trace
        assert goal.id in trace

    def test_format_evidence_graph(self):
        results = [
            ReasoningResult(goal_id="g1", goal_type="recon", objective="test", response="r", confidence=0.9, confidence_level=ConfidenceLevel.HIGH, provider="p1", model="m1", latency_ms=100, cost=0, evidence_refs=["e1", "e2"]),
        ]
        graph = ReasoningFormatter.format_evidence_graph(results)
        assert "Evidence Graph" in graph

    def test_reasoning_result_to_dict(self):
        r = ReasoningResult(goal_id="g1", goal_type="recon", objective="test", response="result text", confidence=0.85, confidence_level=ConfidenceLevel.HIGH, provider="openai", model="gpt-4", latency_ms=1500, cost=0.002)
        d = r.to_dict()
        assert d["goal_id"] == "g1"
        assert d["confidence"] == 0.85
        assert d["provider"] == "openai"
        assert d["latency_ms"] == 1500


@pytest.mark.asyncio
class TestReasoningOrchestrator:
    @patch("core.reasoning.engine.AIManager")
    def test_reason(self, mock_ai_manager_class):
        mock_manager = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Analysis complete: SQL injection vulnerability confirmed."
        mock_response.provider = "test_provider"
        mock_response.model = "test_model"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 50
        mock_response.usage.completion_tokens = 100
        mock_response.usage.total_tokens = 150
        mock_manager.chat.return_value = mock_response
        mock_ai_manager_class.return_value = mock_manager

        engine = ReasoningOrchestrator(ai_manager=mock_manager)
        goal = Goal.create(GoalType.RECON, "Find vulnerabilities")
        result = engine.reason(goal)

        assert result.goal_id == goal.id
        assert result.objective == "Find vulnerabilities"
        assert result.confidence >= 0.1
        assert goal.status == GoalStatus.COMPLETED

    @patch("core.reasoning.engine.AIManager")
    def test_reason_failure(self, mock_ai_manager_class):
        mock_manager = MagicMock()
        mock_manager.chat.side_effect = Exception("API error")
        mock_ai_manager_class.return_value = mock_manager

        engine = ReasoningOrchestrator(ai_manager=mock_manager)
        goal = Goal.create(GoalType.RECON, "Test")
        result = engine.reason(goal)

        assert goal.status == GoalStatus.FAILED
        assert result.confidence == 0.0

    @patch("core.reasoning.engine.AIManager")
    def test_reason_with_consensus(self, mock_ai_manager_class):
        mock_manager = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Consensus result"
        mock_response.provider = "test_provider"
        mock_response.model = "test_model"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 50
        mock_response.usage.completion_tokens = 50
        mock_response.usage.total_tokens = 100
        mock_manager.chat.return_value = mock_response
        mock_ai_manager_class.return_value = mock_manager

        engine = ReasoningOrchestrator(ai_manager=mock_manager)
        goal = Goal.create(GoalType.RECON, "Consensus test")
        result = engine.reason_with_consensus(goal, providers=["p1", "p2"])

        assert result is not None
        assert goal.status in (GoalStatus.COMPLETED, GoalStatus.FAILED)

    @patch("core.reasoning.engine.AIManager")
    def test_reason_batch(self, mock_ai_manager_class):
        mock_manager = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Batch result"
        mock_response.provider = "test"
        mock_response.model = "test"
        mock_response.usage = MagicMock()
        mock_response.usage.total_tokens = 50
        mock_response.usage.prompt_tokens = 25
        mock_response.usage.completion_tokens = 25
        mock_manager.chat.return_value = mock_response
        mock_ai_manager_class.return_value = mock_manager

        engine = ReasoningOrchestrator(ai_manager=mock_manager)
        goals = [
            Goal.create(GoalType.RECON, "A", priority=GoalPriority.HIGH),
            Goal.create(GoalType.THREAT_MODELING, "B", priority=GoalPriority.CRITICAL),
        ]
        results = engine.reason_batch(goals)
        assert len(results) == 2

    def test_set_policy(self):
        engine = ReasoningOrchestrator()
        policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.CONSERVATIVE)
        engine.policy = policy
        assert engine.policy.min_confidence == 0.85

    def test_inspect_missing(self):
        engine = ReasoningOrchestrator()
        result = engine.inspect_reasoning("nonexistent")
        assert result is None
