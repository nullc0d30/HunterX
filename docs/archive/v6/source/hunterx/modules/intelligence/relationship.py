# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .knowledge_graph import (
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)
from ...utils.utils import logger


@dataclass
class InfrastructureRelation:
    relation_type: str
    source: str
    target: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.relation_type,
            "source": self.source,
            "target": self.target,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "properties": self.properties,
        }


class RelationInferenceRule:
    def __init__(
        self,
        name: str,
        source_type: NodeType,
        target_type: NodeType,
        relationship: RelationshipType,
        matcher: callable,
        weight: float = 1.0,
    ):
        self.name = name
        self.source_type = source_type
        self.target_type = target_type
        self.relationship = relationship
        self.matcher = matcher
        self.weight = weight


class RelationshipEngine:
    def __init__(self):
        self.rules: List[RelationInferenceRule] = []
        self._register_default_rules()

    def _register_default_rules(self):
        self.rules.extend([
            RelationInferenceRule(
                "same_ip_different_subdomain",
                NodeType.HOST, NodeType.HOST,
                RelationshipType.RELATED_TO,
                lambda s, t, ctx: (
                    ctx.get("source_ip") == ctx.get("target_ip")
                    and ctx.get("source_domain") != ctx.get("target_domain")
                ),
            ),
            RelationInferenceRule(
                "same_certificate_issuer",
                NodeType.CERTIFICATE, NodeType.CERTIFICATE,
                RelationshipType.RELATED_TO,
                lambda s, t, ctx: (
                    ctx.get("issuer") == ctx.get("target_issuer")
                ),
            ),
            RelationInferenceRule(
                "technology_matches_framework",
                NodeType.TECHNOLOGY, NodeType.FRAMEWORK,
                RelationshipType.DEPENDS_ON,
                lambda s, t, ctx: True,
            ),
            RelationInferenceRule(
                "cookie_domain_match",
                NodeType.COOKIE, NodeType.HOST,
                RelationshipType.RELATED_TO,
                lambda s, t, ctx: True,
            ),
        ])

    def register_rule(self, rule: RelationInferenceRule) -> None:
        self.rules.append(rule)
        logger.info(f"RelationshipEngine: registered rule '{rule.name}'")

    def correlate(
        self,
        knowledge_graph: KnowledgeGraph,
        context: Any = None,
    ) -> List[InfrastructureRelation]:
        relations: List[InfrastructureRelation] = []
        nodes = list(knowledge_graph.nodes.values())

        for rule in self.rules:
            for source_node in nodes:
                if source_node.node_type != rule.source_type:
                    continue
                for target_node in nodes:
                    if target_node.node_type != rule.target_type:
                        continue
                    if source_node.id == target_node.id:
                        continue

                    ctx = {
                        **source_node.properties,
                        **{f"target_{k}": v for k, v in target_node.properties.items()},
                        "source_ip": source_node.properties.get("ip", ""),
                        "target_ip": target_node.properties.get("ip", ""),
                        "source_domain": source_node.label,
                        "target_domain": target_node.label,
                        "issuer": source_node.properties.get("issuer", ""),
                        "target_issuer": target_node.properties.get("issuer", ""),
                    }

                    try:
                        if rule.matcher(source_node, target_node, ctx):
                            relation = InfrastructureRelation(
                                relation_type=rule.relationship.value,
                                source=source_node.label,
                                target=target_node.label,
                                confidence=rule.weight,
                                evidence=[f"Inferred by rule: {rule.name}"],
                                properties={
                                    "source_type": source_node.node_type.value,
                                    "target_type": target_node.node_type.value,
                                    "rule": rule.name,
                                },
                            )
                            relations.append(relation)

                            if source_node.id in knowledge_graph.nodes and target_node.id in knowledge_graph.nodes:
                                knowledge_graph.add_edge(
                                    source_node.id,
                                    target_node.id,
                                    rule.relationship,
                                    {"inferred_by": rule.name},
                                    weight=rule.weight,
                                )
                    except Exception as e:
                        logger.debug(f"Rule '{rule.name}' failed: {e}")

        logger.info(f"RelationshipEngine: inferred {len(relations)} infrastructure relationships")
        return relations

    def correlate_domains(
        self, domains: List[Dict[str, Any]]
    ) -> List[InfrastructureRelation]:
        relations: List[InfrastructureRelation] = []
        for i, d1 in enumerate(domains):
            for d2 in domains[i + 1:]:
                shared_ips = set(d1.get("ips", [])) & set(d2.get("ips", []))
                if shared_ips:
                    relations.append(InfrastructureRelation(
                        relation_type="SHARED_IP",
                        source=d1.get("domain", ""),
                        target=d2.get("domain", ""),
                        confidence=0.8,
                        evidence=[f"Shared IP: {ip}" for ip in shared_ips],
                    ))

                shared_cnames = set(d1.get("cnames", [])) & set(d2.get("cnames", []))
                if shared_cnames:
                    relations.append(InfrastructureRelation(
                        relation_type="SHARED_CNAME",
                        source=d1.get("domain", ""),
                        target=d2.get("domain", ""),
                        confidence=0.6,
                        evidence=[f"Shared CNAME: {cname}" for cname in shared_cnames],
                    ))

        return relations

    def correlate_technologies(
        self, tech_map: Dict[str, List[str]]
    ) -> List[InfrastructureRelation]:
        relations: List[InfrastructureRelation] = []
        tech_sets: Dict[str, List[str]] = {}
        for domain, techs in tech_map.items():
            for tech in techs:
                if tech not in tech_sets:
                    tech_sets[tech] = []
                tech_sets[tech].append(domain)

        for tech, domains in tech_sets.items():
            if len(domains) > 1:
                for i, d1 in enumerate(domains):
                    for d2 in domains[i + 1:]:
                        relations.append(InfrastructureRelation(
                            relation_type="SHARED_TECHNOLOGY",
                            source=d1,
                            target=d2,
                            confidence=0.5,
                            evidence=[f"Both use: {tech}"],
                        ))

        return relations

    def extract_relations(
        self,
        knowledge_graph: KnowledgeGraph,
        findings: List[Dict],
        context: Any = None,
    ) -> List[InfrastructureRelation]:
        relations = self.correlate(knowledge_graph, context)

        tech_map: Dict[str, List[str]] = {}
        for node in knowledge_graph.nodes.values():
            if node.node_type == NodeType.TECHNOLOGY:
                for host_node in knowledge_graph.get_nodes_by_type(NodeType.HOST):
                    edges = knowledge_graph.get_edges_for_node(host_node.id)
                    if any(e.source_id == node.id or e.target_id == node.id for e in edges):
                        if host_node.label not in tech_map:
                            tech_map[host_node.label] = []
                        tech_map[host_node.label].append(node.label)

        if tech_map:
            relations.extend(self.correlate_technologies(tech_map))

        return relations

    def to_dict(self, relations: List[InfrastructureRelation]) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in relations]

    def to_json(self, relations: List[InfrastructureRelation], indent: int = 2) -> str:
        return json.dumps(self.to_dict(relations), indent=indent)
