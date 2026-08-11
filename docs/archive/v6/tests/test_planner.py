# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Planner
import json
from core.planner import (
    Planner,
    ScanPlan,
    PlanAction,
    ActionType,
    Priority,
)
from core.knowledge_graph import KnowledgeGraph, NodeType
from core.adaptive_memory import AdaptiveMemory
import tempfile


class TestPlanAction:
    def test_create(self):
        a = PlanAction(
            id="a1",
            action_type=ActionType.VERIFY,
            target="http://example.com",
            description="Test RCE",
            priority=Priority.CRITICAL,
            confidence=0.9,
            rationale="RCE is critical",
        )
        assert a.action_type == ActionType.VERIFY
        assert a.priority == Priority.CRITICAL

    def test_to_dict(self):
        a = PlanAction(id="a1", action_type=ActionType.PROBE,
                       target="http://test.com", description="Probe",
                       priority=Priority.HIGH, confidence=0.7)
        d = a.to_dict()
        assert d["action_type"] == "probe"


class TestScanPlan:
    def test_create(self):
        plan = ScanPlan(id="plan-1", target_url="http://example.com")
        assert len(plan.actions) == 0

    def test_add_action(self):
        plan = ScanPlan(id="plan-1", target_url="http://example.com")
        a = PlanAction(id="a1", action_type=ActionType.SCAN,
                       target="http://test.com", description="Scan",
                       priority=Priority.MEDIUM, confidence=0.5)
        plan.add_action(a)
        assert len(plan.actions) == 1
        assert plan.total_confidence == 0.5

    def test_to_dict(self):
        plan = ScanPlan(id="plan-1", target_url="http://example.com")
        a = PlanAction(id="a1", action_type=ActionType.ANALYZE,
                       target="http://test.com", description="Analyze",
                       priority=Priority.LOW, confidence=0.3)
        plan.add_action(a)
        d = plan.to_dict()
        assert d["target_url"] == "http://example.com"
        assert len(d["actions"]) == 1

    def test_to_json(self):
        plan = ScanPlan(id="p1", target_url="http://test.com")
        j = plan.to_json()
        parsed = json.loads(j)
        assert parsed["target_url"] == "http://test.com"


class TestPlanner:
    def test_plan_empty(self):
        planner = Planner()
        plan = planner.plan("http://example.com", [])
        assert plan.target_url == "http://example.com"
        assert len(plan.actions) > 0

    def test_plan_with_rce_finding(self):
        planner = Planner()
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.FINDING, "RCE detected", {"category": "RCE"})

        findings = [
            {"payload_category": "RCE", "payload": "id",
             "diff_score": 95, "findings": ["RCE confirmed"]},
        ]
        plan = planner.plan("http://example.com", findings, kg)
        assert len(plan.actions) > 0
        critical_actions = [a for a in plan.actions if a.priority == Priority.CRITICAL]
        assert len(critical_actions) > 0

    def test_plan_with_sqli_finding(self):
        planner = Planner()
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.FINDING, "SQLI detected")

        findings = [
            {"payload_category": "SQLI", "payload": "' OR 1=1",
             "diff_score": 90, "findings": []},
        ]
        plan = planner.plan("http://example.com", findings, kg)
        assert len(plan.actions) > 0

    def test_plan_with_ssti_finding(self):
        planner = Planner()
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.FINDING, "SSTI detected")

        findings = [
            {"payload_category": "SSTI", "payload": "{{7*7}}",
             "diff_score": 80, "findings": []},
        ]
        plan = planner.plan("http://example.com", findings, kg)
        assert len(plan.actions) > 0

    def test_plan_with_lfi_finding(self):
        planner = Planner()
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.FINDING, "LFI detected")

        findings = [
            {"payload_category": "LFI", "payload": "/etc/passwd",
             "diff_score": 75, "findings": []},
        ]
        plan = planner.plan("http://example.com", findings, kg)
        assert len(plan.actions) > 0

    def test_plan_with_memory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mem = AdaptiveMemory(storage_path=tmpdir, use_sqlite=False)
            mem.record_target_fingerprint("http://example.com",
                                           {"os": "Linux", "prev_findings": 5})
            planner = Planner(adaptive_memory=mem)
            plan = planner.plan("http://example.com", [], None, None)
            assert len(plan.actions) > 0

    def test_register_strategy_rule(self):
        planner = Planner()
        planner.register_strategy_rule({
            "priority": Priority.HIGH,
            "condition": lambda f, kg, ctx: True,
            "action": ActionType.SCAN,
            "description": "Always scan",
            "expected_impact": "Discovery",
        })
        assert len(planner._strategy_rules) > 1

    def test_explain_plan(self):
        planner = Planner()
        plan = planner.plan("http://example.com", [])
        explanation = planner.explain_plan(plan)
        assert "http://example.com" in explanation
        assert "Total Confidence" in explanation
