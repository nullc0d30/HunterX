# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from ..modules.intelligence.knowledge_graph import KnowledgeGraph, NodeType
from ..modules.intelligence.adaptive_memory import AdaptiveMemory
from ..utils.utils import logger


class ActionType(str, Enum):
    PROBE = "probe"
    SCAN = "scan"
    VERIFY = "verify"
    ENUMERATE = "enumerate"
    EXTRACT = "extract"
    ANALYZE = "analyze"
    MONITOR = "monitor"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PlanAction:
    id: str
    action_type: ActionType
    target: str
    description: str
    priority: Priority
    confidence: float
    required_evidence: List[str] = field(default_factory=list)
    expected_impact: str = ""
    depends_on: List[str] = field(default_factory=list)
    rationale: str = ""
    estimated_risk: float = 0.0
    expected_duration_seconds: int = 30
    plugin: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action_type": self.action_type.value,
            "target": self.target,
            "description": self.description,
            "priority": self.priority.value,
            "confidence": self.confidence,
            "required_evidence": self.required_evidence,
            "expected_impact": self.expected_impact,
            "depends_on": self.depends_on,
            "rationale": self.rationale,
            "estimated_risk": self.estimated_risk,
            "expected_duration_seconds": self.expected_duration_seconds,
        }


@dataclass
class ScanPlan:
    id: str
    target_url: str
    actions: List[PlanAction] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    total_confidence: float = 0.0
    estimated_duration: int = 0
    risk_score: float = 0.0

    def add_action(self, action: PlanAction) -> None:
        self.actions.append(action)
        self.total_confidence = sum(a.confidence for a in self.actions) / max(1, len(self.actions))
        self.estimated_duration = sum(a.expected_duration_seconds for a in self.actions)
        self.risk_score = sum(a.estimated_risk for a in self.actions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "actions": [a.to_dict() for a in self.actions],
            "created_at": self.created_at.isoformat(),
            "total_confidence": self.total_confidence,
            "estimated_duration_seconds": self.estimated_duration,
            "risk_score": self.risk_score,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class Planner:
    def __init__(self, adaptive_memory: Optional[AdaptiveMemory] = None):
        self.memory = adaptive_memory
        self._strategy_rules: List[Dict[str, Any]] = [
            {
                "priority": Priority.CRITICAL,
                "condition": lambda f, kg, ctx: any(
                    n.node_type == NodeType.FINDING and "RCE" in n.label
                    for n in (kg.nodes.values() if kg else [])
                ),
                "action": ActionType.VERIFY,
                "description": "Immediate RCE verification required",
                "expected_impact": "Remote Code Execution poses critical risk",
            },
            {
                "priority": Priority.CRITICAL,
                "condition": lambda f, kg, ctx: any(
                    n.node_type == NodeType.FINDING and "SQLI" in n.label
                    for n in (kg.nodes.values() if kg else [])
                ),
                "action": ActionType.VERIFY,
                "description": "SQL injection confirmation required",
                "expected_impact": "SQL injection can lead to data breach",
            },
            {
                "priority": Priority.HIGH,
                "condition": lambda f, kg, ctx: any(
                    n.node_type == NodeType.FINDING and "SSTI" in n.label
                    for n in (kg.nodes.values() if kg else [])
                ),
                "action": ActionType.VERIFY,
                "description": "SSTI verification and sandbox escape assessment",
                "expected_impact": "SSTI frequently leads to RCE",
            },
            {
                "priority": Priority.HIGH,
                "condition": lambda f, kg, ctx: any(
                    n.node_type == NodeType.FINDING and "LFI" in n.label
                    for n in (kg.nodes.values() if kg else [])
                ),
                "action": ActionType.EXTRACT,
                "description": "LFI exploitation for credential extraction",
                "expected_impact": "LFI can leak sensitive configuration files",
            },
            {
                "priority": Priority.MEDIUM,
                "condition": lambda f, kg, ctx: any(
                    n.node_type == NodeType.FINDING and "XSS" in n.label
                    for n in (kg.nodes.values() if kg else [])
                ),
                "action": ActionType.ANALYZE,
                "description": "XSS context analysis and impact assessment",
                "expected_impact": "XSS can lead to session theft and phishing",
            },
            {
                "priority": Priority.MEDIUM,
                "condition": lambda f, kg, ctx: any(
                    n.node_type == NodeType.FINDING and "SSRF" in n.label
                    for n in (kg.nodes.values() if kg else [])
                ),
                "action": ActionType.ENUMERATE,
                "description": "SSRF attack surface enumeration",
                "expected_impact": "SSRF can access internal cloud metadata",
            },
            {
                "priority": Priority.LOW,
                "condition": lambda f, kg, ctx: any(
                    n.node_type == NodeType.FINDING and "OPEN_REDIRECT" in n.label
                    for n in (kg.nodes.values() if kg else [])
                ),
                "action": ActionType.ANALYZE,
                "description": "Open redirect usage analysis",
                "expected_impact": "Open redirect enables phishing attacks",
            },
        ]

    def register_strategy_rule(self, rule: Dict[str, Any]) -> None:
        self._strategy_rules.append(rule)
        logger.info(f"Planner: registered strategy rule for {rule.get('priority', 'unknown')}")

    def plan(
        self,
        target_url: str,
        findings: List[Dict],
        knowledge_graph: Optional[KnowledgeGraph] = None,
        context: Any = None,
    ) -> ScanPlan:
        plan = ScanPlan(
            id=str(uuid.uuid4()),
            target_url=target_url,
        )

        priority_map: Dict[Priority, int] = {
            Priority.CRITICAL: 0,
            Priority.HIGH: 1,
            Priority.MEDIUM: 2,
            Priority.LOW: 3,
            Priority.INFO: 4,
        }

        matching_rules = []
        for rule in self._strategy_rules:
            try:
                if rule["condition"](findings, knowledge_graph, context):
                    matching_rules.append(rule)
            except Exception as e:
                logger.debug(f"Planner strategy rule condition failed: {e}")

        matching_rules.sort(key=lambda r: priority_map.get(r["priority"], 99))

        for rule in matching_rules:
            evidence = []
            if knowledge_graph:
                finding_nodes = knowledge_graph.get_nodes_by_type(NodeType.FINDING)
                for f_node in finding_nodes:
                    if any(rule["action"].value.upper() in f_node.label.upper() for tag in ["RCE", "SQLI", "SSTI", "LFI", "XSS", "SSRF"]):
                        evidence.extend(
                            n.label for n in knowledge_graph.get_neighbors(f_node.id)
                            if n.node_type == NodeType.EVIDENCE
                        )

            action = PlanAction(
                id=str(uuid.uuid4()),
                action_type=rule["action"],
                target=target_url,
                description=rule["description"],
                priority=rule["priority"],
                confidence=0.8 if rule["priority"] == Priority.CRITICAL else 0.6,
                required_evidence=evidence[:5],
                expected_impact=rule["expected_impact"],
                rationale=f"Triggered by rule: {rule['description']}. "
                          f"Priority set to {rule['priority'].value} based on finding severity.",
                estimated_risk=0.9 if rule["priority"] == Priority.CRITICAL else 0.5,
                expected_duration_seconds=60 if rule["priority"] == Priority.CRITICAL else 30,
            )
            plan.add_action(action)

        if not plan.actions and findings:
            plan.add_action(PlanAction(
                id=str(uuid.uuid4()),
                action_type=ActionType.ANALYZE,
                target=target_url,
                description="Analyze existing findings for correlations",
                priority=Priority.MEDIUM,
                confidence=0.5,
                rationale=f"Generated {len(findings)} findings. Further analysis may reveal attack chains.",
                expected_impact="Correlation analysis may identify compound vulnerabilities",
                estimated_risk=0.3,
            ))

        if not plan.actions:
            plan.add_action(PlanAction(
                id=str(uuid.uuid4()),
                action_type=ActionType.PROBE,
                target=target_url,
                description="Initial reconnaissance and discovery",
                priority=Priority.INFO,
                confidence=0.3,
                rationale="No vulnerabilities detected. Exploring target surface.",
                expected_impact="Discovery of new attack surface",
                estimated_risk=0.1,
            ))

        if self.memory:
            fp = self.memory.get_target_fingerprint(target_url)
            if fp:
                plan.add_action(PlanAction(
                    id=str(uuid.uuid4()),
                    action_type=ActionType.ANALYZE,
                    target=target_url,
                    description="Cross-reference with historical target fingerprint",
                    priority=Priority.INFO,
                    confidence=0.4,
                    rationale="Target previously scanned. Historical data available for comparison.",
                    expected_impact="Identify changes in attack surface",
                    estimated_risk=0.0,
                ))

        logger.info(f"Planner: generated plan with {len(plan.actions)} actions "
                     f"(confidence={plan.total_confidence:.2f}, risk={plan.risk_score:.2f})")
        return plan

    def explain_plan(self, plan: ScanPlan) -> str:
        lines = [f"Scan Plan for {plan.target_url}", f"Total Confidence: {plan.total_confidence:.2f}", ""]
        for i, action in enumerate(plan.actions, 1):
            lines.append(f"{i}. [{action.priority.value.upper()}] {action.description}")
            lines.append(f"   Type: {action.action_type.value}")
            lines.append(f"   Confidence: {action.confidence:.2f}")
            lines.append(f"   Rationale: {action.rationale}")
            if action.required_evidence:
                lines.append(f"   Evidence: {', '.join(action.required_evidence[:3])}")
            lines.append("")
        return "\n".join(lines)
