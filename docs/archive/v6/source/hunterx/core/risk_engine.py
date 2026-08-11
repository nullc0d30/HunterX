# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ..modules.intelligence.knowledge_graph import KnowledgeGraph, NodeType
from ..utils.utils import logger


@dataclass
class RiskScore:
    likelihood: float = 0.0
    exploitability: float = 0.0
    exposure: float = 0.0
    business_impact: float = 0.0
    reachability: float = 0.0
    confidence: float = 0.0
    normalized_score: float = 0.0
    severity: str = "None"

    def compute(self) -> float:
        self.normalized_score = (
            self.likelihood * 0.20
            + self.exploitability * 0.20
            + self.exposure * 0.15
            + self.business_impact * 0.20
            + self.reachability * 0.15
            + self.confidence * 0.10
        )
        self.normalized_score = min(1.0, max(0.0, self.normalized_score))
        if self.normalized_score >= 0.9:
            self.severity = "Critical"
        elif self.normalized_score >= 0.7:
            self.severity = "High"
        elif self.normalized_score >= 0.4:
            self.severity = "Medium"
        elif self.normalized_score >= 0.1:
            self.severity = "Low"
        else:
            self.severity = "None"
        return self.normalized_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "likelihood": round(self.likelihood, 3),
            "exploitability": round(self.exploitability, 3),
            "exposure": round(self.exposure, 3),
            "business_impact": round(self.business_impact, 3),
            "reachability": round(self.reachability, 3),
            "confidence": round(self.confidence, 3),
            "normalized_score": round(self.normalized_score, 3),
            "severity": self.severity,
        }


SEVERITY_WEIGHTS: Dict[str, Dict[str, float]] = {
    "default": {
        "likelihood": 0.20,
        "exploitability": 0.20,
        "exposure": 0.15,
        "business_impact": 0.20,
        "reachability": 0.15,
        "confidence": 0.10,
    },
    "pentest": {
        "likelihood": 0.15,
        "exploitability": 0.30,
        "exposure": 0.10,
        "business_impact": 0.15,
        "reachability": 0.20,
        "confidence": 0.10,
    },
    "bug_bounty": {
        "likelihood": 0.10,
        "exploitability": 0.25,
        "exposure": 0.10,
        "business_impact": 0.30,
        "reachability": 0.15,
        "confidence": 0.10,
    },
    "compliance": {
        "likelihood": 0.15,
        "exploitability": 0.10,
        "exposure": 0.20,
        "business_impact": 0.35,
        "reachability": 0.10,
        "confidence": 0.10,
    },
}

CATEGORY_RISK_PROFILES: Dict[str, Dict[str, float]] = {
    "RCE": {"likelihood": 0.8, "exploitability": 0.9, "exposure": 0.9, "business_impact": 1.0, "reachability": 0.7, "confidence": 0.8},
    "SQLI": {"likelihood": 0.8, "exploitability": 0.85, "exposure": 0.8, "business_impact": 0.9, "reachability": 0.7, "confidence": 0.8},
    "SSTI": {"likelihood": 0.75, "exploitability": 0.8, "exposure": 0.7, "business_impact": 0.9, "reachability": 0.6, "confidence": 0.7},
    "LFI": {"likelihood": 0.7, "exploitability": 0.75, "exposure": 0.6, "business_impact": 0.7, "reachability": 0.7, "confidence": 0.7},
    "XSS": {"likelihood": 0.6, "exploitability": 0.5, "exposure": 0.5, "business_impact": 0.5, "reachability": 0.6, "confidence": 0.5},
    "SSRF": {"likelihood": 0.6, "exploitability": 0.6, "exposure": 0.6, "business_impact": 0.7, "reachability": 0.5, "confidence": 0.5},
    "OPEN_REDIRECT": {"likelihood": 0.4, "exploitability": 0.3, "exposure": 0.3, "business_impact": 0.3, "reachability": 0.4, "confidence": 0.3},
    "CRLF": {"likelihood": 0.4, "exploitability": 0.4, "exposure": 0.3, "business_impact": 0.3, "reachability": 0.3, "confidence": 0.3},
    "INFO_LEAK": {"likelihood": 0.5, "exploitability": 0.3, "exposure": 0.4, "business_impact": 0.3, "reachability": 0.5, "confidence": 0.4},
    "FILE_DISCLOSURE": {"likelihood": 0.6, "exploitability": 0.5, "exposure": 0.5, "business_impact": 0.5, "reachability": 0.6, "confidence": 0.5},
    "WAF_BYPASS": {"likelihood": 0.3, "exploitability": 0.5, "exposure": 0.2, "business_impact": 0.2, "reachability": 0.3, "confidence": 0.3},
}


class RiskEngine:
    def __init__(self, weighting_profile: str = "default"):
        self.weighting_profile = weighting_profile
        self.weights = SEVERITY_WEIGHTS.get(weighting_profile, SEVERITY_WEIGHTS["default"])
        self._custom_rules: List[Callable] = []

    def set_weights(self, weights: Dict[str, float]) -> None:
        for key in ["likelihood", "exploitability", "exposure", "business_impact", "reachability", "confidence"]:
            if key in weights:
                self.weights[key] = weights[key]

    def register_rule(self, rule: Callable[[Dict[str, Any], Optional[KnowledgeGraph]], Optional[RiskScore]]) -> None:
        self._custom_rules.append(rule)

    def evaluate(
        self,
        finding: Dict[str, Any],
        knowledge_graph: Optional[KnowledgeGraph] = None,
        context: Any = None,
    ) -> RiskScore:
        category = finding.get("payload_category", "GENERIC")
        diff_score = finding.get("diff_score", 0)
        raw_findings = finding.get("findings", [])

        profile = CATEGORY_RISK_PROFILES.get(category, {
            "likelihood": 0.3, "exploitability": 0.3, "exposure": 0.3,
            "business_impact": 0.3, "reachability": 0.3, "confidence": 0.3,
        })

        diff_factor = min(1.0, diff_score / 100.0)
        evidence_factor = min(1.0, len(raw_findings) * 0.1)

        risk = RiskScore(
            likelihood=min(1.0, profile["likelihood"] * (0.5 + 0.5 * diff_factor)),
            exploitability=min(1.0, profile["exploitability"] * (0.5 + 0.5 * diff_factor)),
            exposure=min(1.0, profile["exposure"] * (0.5 + 0.5 * evidence_factor)),
            business_impact=profile["business_impact"],
            reachability=min(1.0, profile["reachability"] * (0.5 + 0.5 * diff_factor)),
            confidence=min(1.0, profile["confidence"] * (0.3 + 0.7 * evidence_factor)),
        )

        if knowledge_graph:
            finding_nodes = knowledge_graph.get_nodes_by_type(NodeType.FINDING)
            for f_node in finding_nodes:
                if category in f_node.label:
                    related_evidence = [
                        n for n in knowledge_graph.get_neighbors(f_node.id)
                        if n.node_type == NodeType.EVIDENCE
                    ]
                    if related_evidence:
                        risk.confidence = min(1.0, risk.confidence + 0.1)
                    for edge in knowledge_graph.get_edges_for_node(f_node.id):
                        if edge.relationship.value == "EXPLOITS":
                            risk.exploitability = min(1.0, risk.exploitability + 0.1)

        for rule in self._custom_rules:
            try:
                custom_score = rule(finding, knowledge_graph)
                if custom_score:
                    risk.likelihood = max(risk.likelihood, custom_score.likelihood)
                    risk.business_impact = max(risk.business_impact, custom_score.business_impact)
            except Exception as e:
                logger.debug(f"RiskEngine custom rule failed: {e}")

        risk.compute()
        return risk

    def evaluate_multi(
        self,
        findings: List[Dict[str, Any]],
        knowledge_graph: Optional[KnowledgeGraph] = None,
    ) -> Dict[str, RiskScore]:
        return {f.get("payload", "")[:40]: self.evaluate(f, knowledge_graph) for f in findings}

    def aggregate_risk(self, scores: List[RiskScore]) -> RiskScore:
        if not scores:
            return RiskScore()
        aggregated = RiskScore(
            likelihood=sum(s.likelihood for s in scores) / len(scores),
            exploitability=sum(s.exploitability for s in scores) / len(scores),
            exposure=sum(s.exposure for s in scores) / len(scores),
            business_impact=max(s.business_impact for s in scores),
            reachability=sum(s.reachability for s in scores) / len(scores),
            confidence=sum(s.confidence for s in scores) / len(scores),
        )
        aggregated.compute()
        return aggregated

    def get_risk_matrix(self, scores: Dict[str, RiskScore]) -> List[Dict[str, Any]]:
        return [
            {
                "finding": finding_key,
                "risk": score.to_dict(),
            }
            for finding_key, score in sorted(
                scores.items(), key=lambda x: x[1].normalized_score, reverse=True
            )
        ]

    def to_json(self, scores: Dict[str, RiskScore], indent: int = 2) -> str:
        return json.dumps(self.get_risk_matrix(scores), indent=indent)
