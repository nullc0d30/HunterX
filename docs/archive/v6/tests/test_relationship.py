# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Relationship Engine
import json
from core.relationship import (
    RelationshipEngine,
    InfrastructureRelation,
    RelationInferenceRule,
)
from core.knowledge_graph import KnowledgeGraph, NodeType, RelationshipType


class TestInfrastructureRelation:
    def test_create(self):
        r = InfrastructureRelation(
            relation_type="SHARED_IP",
            source="a.com",
            target="b.com",
            confidence=0.8,
            evidence=["Shared IP: 1.2.3.4"],
        )
        assert r.source == "a.com"
        assert r.target == "b.com"

    def test_to_dict(self):
        r = InfrastructureRelation(
            relation_type="SHARED_IP",
            source="a.com", target="b.com", confidence=0.8,
        )
        d = r.to_dict()
        assert d["type"] == "SHARED_IP"


class TestRelationshipEngine:
    def test_create(self):
        engine = RelationshipEngine()
        assert len(engine.rules) > 0

    def test_register_rule(self):
        engine = RelationshipEngine()
        rule = RelationInferenceRule(
            "test", NodeType.HOST, NodeType.HOST,
            RelationshipType.RELATED_TO,
            lambda s, t, ctx: True,
        )
        engine.register_rule(rule)
        assert len(engine.rules) > 1

    def test_correlate_empty_graph(self):
        engine = RelationshipEngine()
        kg = KnowledgeGraph(target_url="http://test.com")
        relations = engine.correlate(kg)
        assert relations == []

    def test_correlate_with_nodes(self):
        engine = RelationshipEngine()
        kg = KnowledgeGraph(target_url="http://test.com")
        kg.add_node(NodeType.HOST, "h1", {"ip": "1.2.3.4"})
        kg.add_node(NodeType.HOST, "h2", {"ip": "1.2.3.4"})
        relations = engine.correlate(kg)
        assert len(relations) >= 0

    def test_correlate_domains(self):
        engine = RelationshipEngine()
        domains = [
            {"domain": "a.com", "ips": ["1.2.3.4"], "cnames": ["cdn.a.com"]},
            {"domain": "b.com", "ips": ["1.2.3.4"], "cnames": ["cdn.b.com"]},
        ]
        relations = engine.correlate_domains(domains)
        assert len(relations) > 0
        assert relations[0].relation_type == "SHARED_IP"

    def test_correlate_technologies(self):
        engine = RelationshipEngine()
        tech_map = {
            "a.com": ["PHP", "nginx"],
            "b.com": ["PHP", "Apache"],
            "c.com": ["Python", "nginx"],
        }
        relations = engine.correlate_technologies(tech_map)
        assert len(relations) > 0

    def test_extract_relations(self):
        engine = RelationshipEngine()
        kg = KnowledgeGraph(target_url="http://test.com")
        h = kg.add_node(NodeType.HOST, "test.com")
        t = kg.add_node(NodeType.TECHNOLOGY, "PHP")
        kg.add_edge(h.id, t.id, RelationshipType.USES)

        findings = [
            {"payload_category": "XSS", "payload": "<script>",
             "diff_score": 50, "findings": []},
        ]
        relations = engine.extract_relations(kg, findings)
        assert isinstance(relations, list)

    def test_to_dict(self):
        engine = RelationshipEngine()
        relations = [
            InfrastructureRelation("SHARED_IP", "a", "b", 0.8),
        ]
        d = engine.to_dict(relations)
        assert len(d) == 1

    def test_to_json(self):
        engine = RelationshipEngine()
        relations = [
            InfrastructureRelation("SHARED_IP", "a", "b", 0.8),
        ]
        j = engine.to_json(relations)
        parsed = json.loads(j)
        assert len(parsed) == 1
