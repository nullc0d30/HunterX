# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Explainability Engine
import json
from core.explainability import (
    ExplainabilityEngine,
    ExplainableEvidence,
    Explanation,
)
from core.knowledge_graph import KnowledgeGraph, NodeType
from core.attack_chain import AttackPath, ChainTransition


class TestExplainableEvidence:
    def test_create(self):
        e = ExplainableEvidence(
            source="test", detail="Something happened",
            confidence=0.8, category="observation",
        )
        assert e.source == "test"

    def test_to_dict(self):
        e = ExplainableEvidence(
            source="src", detail="detail", confidence=0.5,
        )
        d = e.to_dict()
        assert d["source"] == "src"


class TestExplanation:
    def test_create(self):
        exp = Explanation(
            finding_id="f1",
            finding_type="SQLI",
            conclusion="SQL injection detected",
            confidence=0.85,
        )
        assert exp.finding_type == "SQLI"

    def test_to_dict(self):
        exp = Explanation(
            finding_id="f1", finding_type="XSS",
            conclusion="XSS found", confidence=0.7,
            reasoning_steps=["Step 1", "Step 2"],
        )
        d = exp.to_dict()
        assert len(d["reasoning_steps"]) == 2


class TestExplainabilityEngine:
    def test_explain_sqli_finding(self):
        engine = ExplainabilityEngine()
        finding = {
            "payload_category": "SQLI",
            "payload": "' OR 1=1",
            "diff_score": 90,
            "findings": ["SQL syntax error detected"],
        }
        exp = engine.explain_finding(finding)
        assert exp.finding_type == "SQLI"
        assert exp.confidence > 0
        assert len(exp.reasoning_steps) > 0
        assert len(exp.alternative_explanations) > 0
        assert len(exp.missing_evidence) > 0

    def test_explain_lfi_finding(self):
        engine = ExplainabilityEngine()
        finding = {
            "payload_category": "LFI",
            "payload": "/etc/passwd",
            "diff_score": 80,
            "findings": ["root:x:0:0:"],
        }
        exp = engine.explain_finding(finding)
        assert exp.finding_type == "LFI"

    def test_explain_xss_finding(self):
        engine = ExplainabilityEngine()
        finding = {
            "payload_category": "XSS",
            "payload": "<script>alert(1)</script>",
            "diff_score": 70,
            "findings": ["Payload reflected"],
        }
        exp = engine.explain_finding(finding)
        assert exp.finding_type == "XSS"

    def test_explain_rce_finding(self):
        engine = ExplainabilityEngine()
        finding = {
            "payload_category": "RCE",
            "payload": "id",
            "diff_score": 95,
            "findings": ["uid=0(root)"],
        }
        exp = engine.explain_finding(finding)
        assert exp.finding_type == "RCE"

    def test_explain_ssti_finding(self):
        engine = ExplainabilityEngine()
        finding = {
            "payload_category": "SSTI",
            "payload": "{{7*7}}",
            "diff_score": 85,
            "findings": ["49"],
        }
        exp = engine.explain_finding(finding)
        assert exp.finding_type == "SSTI"

    def test_explain_ssrf_finding(self):
        engine = ExplainabilityEngine()
        finding = {
            "payload_category": "SSRF",
            "payload": "http://169.254.169.254",
            "diff_score": 75,
            "findings": ["Metadata endpoint hit"],
        }
        exp = engine.explain_finding(finding)
        assert exp.finding_type == "SSRF"

    def test_explain_generic_finding(self):
        engine = ExplainabilityEngine()
        finding = {
            "payload_category": "UNKNOWN",
            "payload": "test",
            "diff_score": 40,
            "findings": [],
        }
        exp = engine.explain_finding(finding)
        assert exp.finding_type == "UNKNOWN"

    def test_explain_with_knowledge_graph(self):
        engine = ExplainabilityEngine()
        kg = KnowledgeGraph(target_url="http://example.com")
        kg.add_node(NodeType.FINDING, "XSS test", node_id="f1")

        finding = {
            "payload_category": "XSS",
            "payload": "<script>",
            "diff_score": 70,
            "findings": ["Reflected"],
        }
        exp = engine.explain_finding(finding, kg)
        assert exp.confidence > 0

    def test_explain_attack_path(self):
        engine = ExplainabilityEngine()
        t = ChainTransition(
            source_finding="LFI", target_finding="RCE",
            technique="Log poisoning", confidence=0.7,
        )
        path = AttackPath(
            id="p1", name="LFI->RCE", steps=[t],
            overall_confidence=0.7, prerequisites=["File write access"],
        )
        exp = engine.explain_attack_path(path)
        assert exp.finding_type == "attack_path"

    def test_get_explanation(self):
        engine = ExplainabilityEngine()
        finding = {"payload_category": "SQLI", "payload": "test",
                   "diff_score": 50, "findings": []}
        exp = engine.explain_finding(finding)
        retrieved = engine.get_explanation(exp.finding_id)
        assert retrieved is not None
        assert retrieved.finding_id == exp.finding_id

    def test_get_all_explanations(self):
        engine = ExplainabilityEngine()
        engine.explain_finding({"payload_category": "A", "payload": "a",
                                 "diff_score": 50, "findings": []})
        engine.explain_finding({"payload_category": "B", "payload": "b",
                                 "diff_score": 60, "findings": []})
        assert len(engine.get_all_explanations()) == 2

    def test_to_dict(self):
        engine = ExplainabilityEngine()
        engine.explain_finding({"payload_category": "XSS", "payload": "x",
                                 "diff_score": 50, "findings": []})
        d = engine.to_dict()
        assert "explanations" in d

    def test_to_json(self):
        engine = ExplainabilityEngine()
        engine.explain_finding({"payload_category": "XSS", "payload": "x",
                                 "diff_score": 50, "findings": []})
        j = engine.to_json()
        parsed = json.loads(j)
        assert "explanations" in parsed
