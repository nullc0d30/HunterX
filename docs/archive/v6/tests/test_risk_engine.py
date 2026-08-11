# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Risk Engine
import json
from core.risk_engine import (
    RiskEngine,
    RiskScore,
)
from core.knowledge_graph import KnowledgeGraph, NodeType, RelationshipType


class TestRiskScore:
    def test_create_default(self):
        rs = RiskScore()
        assert rs.normalized_score == 0.0
        assert rs.severity == "None"

    def test_compute_critical(self):
        rs = RiskScore(
            likelihood=1.0, exploitability=1.0, exposure=1.0,
            business_impact=1.0, reachability=1.0, confidence=1.0,
        )
        rs.compute()
        assert rs.normalized_score >= 0.9
        assert rs.severity == "Critical"

    def test_compute_high(self):
        rs = RiskScore(
            likelihood=0.8, exploitability=0.8, exposure=0.8,
            business_impact=0.8, reachability=0.8, confidence=0.8,
        )
        rs.compute()
        assert rs.severity in ("High", "Critical")

    def test_compute_medium(self):
        rs = RiskScore(
            likelihood=0.5, exploitability=0.5, exposure=0.5,
            business_impact=0.5, reachability=0.5, confidence=0.5,
        )
        rs.compute()
        assert rs.severity in ("Medium", "Low")

    def test_compute_low(self):
        rs = RiskScore(
            likelihood=0.1, exploitability=0.1, exposure=0.1,
            business_impact=0.1, reachability=0.1, confidence=0.1,
        )
        rs.compute()
        assert rs.severity in ("Low", "None")

    def test_to_dict(self):
        rs = RiskScore(likelihood=0.5, exploitability=0.5)
        rs.compute()
        d = rs.to_dict()
        assert "normalized_score" in d
        assert "severity" in d


class TestRiskEngine:
    def test_create_default(self):
        re = RiskEngine()
        assert re.weighting_profile == "default"

    def test_create_pentest(self):
        re = RiskEngine(weighting_profile="pentest")
        assert re.weighting_profile == "pentest"

    def test_set_weights(self):
        re = RiskEngine()
        re.set_weights({"likelihood": 0.5, "exploitability": 0.5})
        assert re.weights["likelihood"] == 0.5

    def test_evaluate_rce(self):
        re = RiskEngine()
        finding = {
            "payload_category": "RCE",
            "payload": "id",
            "diff_score": 95,
            "findings": ["uid=0(root)", "RCE confirmed"],
        }
        score = re.evaluate(finding)
        assert score.normalized_score > 0.5
        assert score.severity in ("Critical", "High")

    def test_evaluate_sqli(self):
        re = RiskEngine()
        finding = {
            "payload_category": "SQLI",
            "payload": "' OR 1=1",
            "diff_score": 85,
            "findings": ["SQL error"],
        }
        score = re.evaluate(finding)
        assert score.normalized_score > 0.5

    def test_evaluate_xss(self):
        re = RiskEngine()
        finding = {
            "payload_category": "XSS",
            "payload": "<script>",
            "diff_score": 60,
            "findings": ["Reflected"],
        }
        score = re.evaluate(finding)
        assert score.normalized_score > 0.1

    def test_evaluate_low_risk(self):
        re = RiskEngine()
        finding = {
            "payload_category": "OPEN_REDIRECT",
            "payload": "http://evil.com",
            "diff_score": 30,
            "findings": [],
        }
        score = re.evaluate(finding)
        assert score.normalized_score < 0.8

    def test_evaluate_with_knowledge_graph(self):
        re = RiskEngine()
        kg = KnowledgeGraph(target_url="http://example.com")
        f_node = kg.add_node(NodeType.FINDING, "RCE detected")
        kg.add_node(NodeType.EVIDENCE, "Confirmed execution", node_id="ev1")
        kg.add_edge(f_node.id, "ev1", RelationshipType.INDICATES)

        finding = {
            "payload_category": "RCE",
            "payload": "id",
            "diff_score": 90,
            "findings": ["RCE"],
        }
        score = re.evaluate(finding, kg)
        assert score.confidence > 0.3
        assert "High" in score.severity or "Critical" in score.severity

    def test_register_rule(self):
        re = RiskEngine()

        def custom_rule(finding, kg):
            if finding.get("payload_category") == "CUSTOM":
                return RiskScore(likelihood=1.0, business_impact=1.0)
            return None

        re.register_rule(custom_rule)
        finding = {
            "payload_category": "CUSTOM",
            "payload": "test",
            "diff_score": 50,
            "findings": [],
        }
        score = re.evaluate(finding)
        assert score.business_impact == 1.0

    def test_evaluate_multi(self):
        re = RiskEngine()
        findings = [
            {"payload_category": "XSS", "payload": "a", "diff_score": 60, "findings": []},
            {"payload_category": "LFI", "payload": "b", "diff_score": 80, "findings": []},
        ]
        scores = re.evaluate_multi(findings)
        assert len(scores) == 2

    def test_aggregate_risk(self):
        re = RiskEngine()
        scores = [
            RiskScore(likelihood=0.8, exploitability=0.8, exposure=0.8,
                       business_impact=0.8, reachability=0.8, confidence=0.8),
            RiskScore(likelihood=0.2, exploitability=0.2, exposure=0.2,
                       business_impact=0.2, reachability=0.2, confidence=0.2),
        ]
        aggregated = re.aggregate_risk(scores)
        assert aggregated.normalized_score > 0

    def test_get_risk_matrix(self):
        re = RiskEngine()
        findings = [
            {"payload_category": "RCE", "payload": "a", "diff_score": 90, "findings": []},
        ]
        scores = re.evaluate_multi(findings)
        matrix = re.get_risk_matrix(scores)
        assert len(matrix) == 1
        assert "risk" in matrix[0]

    def test_to_json(self):
        re = RiskEngine()
        scores = {}
        j = re.to_json(scores)
        parsed = json.loads(j)
        assert isinstance(parsed, list)
