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
from typing import Any, Dict, List, Optional, Set

from .knowledge_graph import KnowledgeGraph, NodeType
from ...utils.utils import logger


class ChainStatus(str, Enum):
    HYPOTHETICAL = "hypothetical"
    CONFIRMED = "confirmed"
    BLOCKED = "blocked"
    PARTIAL = "partial"


@dataclass
class ChainTransition:
    source_finding: str
    target_finding: str
    technique: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    estimated_likelihood: float = 0.5
    risk_increase: float = 0.1
    prerequisites: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_finding,
            "target": self.target_finding,
            "technique": self.technique,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "requirements": self.requirements,
            "estimated_likelihood": self.estimated_likelihood,
            "risk_increase": self.risk_increase,
            "prerequisites": self.prerequisites,
        }


@dataclass
class AttackPath:
    id: str
    name: str
    steps: List[ChainTransition]
    status: ChainStatus = ChainStatus.HYPOTHETICAL
    overall_confidence: float = 0.0
    total_risk: float = 0.0
    prerequisites: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "status": self.status.value,
            "overall_confidence": self.overall_confidence,
            "total_risk": self.total_risk,
            "prerequisites": self.prerequisites,
            "mitigations": self.mitigations,
            "created_at": self.created_at.isoformat(),
        }

    def summary(self) -> str:
        steps_str = " -> ".join(s.target_finding for s in self.steps)
        return f"[{self.status.value.upper()}] {self.name}: {steps_str} (confidence={self.overall_confidence:.2f}, risk={self.total_risk:.2f})"


class ChainPluginInterface:
    def can_handle(self, source_finding: str, target_finding: str) -> bool:
        raise NotImplementedError

    def build_transition(
        self, source_finding: str, target_finding: str, context: Any = None
    ) -> Optional[ChainTransition]:
        raise NotImplementedError


DEFAULT_CHAINS: Dict[str, List[Dict[str, Any]]] = {
    "LFI": [
        {
            "target": "CONFIGURATION_DISCLOSURE",
            "technique": "Configuration file extraction via path traversal",
            "confidence": 0.75,
            "evidence_template": "LFI confirmed. Attacker can read configuration files such as /etc/passwd, wp-config.php.",
            "requirements": ["Unrestricted file read via path traversal"],
            "likelihood": 0.7,
            "risk_increase": 0.2,
        },
        {
            "target": "CREDENTIAL_LEAKAGE",
            "technique": "Credential extraction from leaked config files",
            "confidence": 0.6,
            "evidence_template": "Configuration disclosure provides credentials for database, API, or application access.",
            "requirements": ["Configuration disclosure achieved"],
            "likelihood": 0.6,
            "risk_increase": 0.3,
        },
    ],
    "CREDENTIAL_LEAKAGE": [
        {
            "target": "SSH_ACCESS",
            "technique": "Credential reuse for SSH authentication",
            "confidence": 0.5,
            "evidence_template": "Leaked credentials may grant SSH access to the target server.",
            "requirements": ["SSH service exposed", "Valid credentials leaked"],
            "likelihood": 0.5,
            "risk_increase": 0.3,
        },
        {
            "target": "DATABASE_ACCESS",
            "technique": "Database connection using leaked credentials",
            "confidence": 0.6,
            "evidence_template": "Database credentials found. Remote database access may be possible.",
            "requirements": ["Database port exposed", "Valid credentials leaked"],
            "likelihood": 0.5,
            "risk_increase": 0.3,
        },
    ],
    "XSS": [
        {
            "target": "SESSION_HIJACKING",
            "technique": "Cookie theft via XSS payload",
            "confidence": 0.7,
            "evidence_template": "XSS confirmed. Cookie theft can lead to session hijacking.",
            "requirements": ["HttpOnly flag not set", "Session cookies in use"],
            "likelihood": 0.65,
            "risk_increase": 0.25,
        },
        {
            "target": "CSRF_BYPASS",
            "technique": "Anti-CSRF token extraction via XSS",
            "confidence": 0.5,
            "evidence_template": "XSS can be used to read Anti-CSRF tokens from DOM.",
            "requirements": ["CSRF tokens embedded in DOM"],
            "likelihood": 0.5,
            "risk_increase": 0.15,
        },
    ],
    "SSTI": [
        {
            "target": "RCE",
            "technique": "Template sandbox escape to RCE",
            "confidence": 0.85,
            "evidence_template": "SSTI confirmed. Template engines often allow sandbox escape to RCE.",
            "requirements": ["Template engine with known sandbox bypass"],
            "likelihood": 0.8,
            "risk_increase": 0.5,
        },
    ],
    "SQLI": [
        {
            "target": "DATABASE_EXFILTRATION",
            "technique": "Data extraction via UNION-based SQL injection",
            "confidence": 0.8,
            "evidence_template": "SQL injection confirmed. Database contents can be extracted.",
            "requirements": ["Determined column count", "Database user has read permissions"],
            "likelihood": 0.75,
            "risk_increase": 0.4,
        },
        {
            "target": "OS_COMMAND_EXECUTION",
            "technique": "xp_cmdshell or MySQL INTO OUTFILE for RCE",
            "confidence": 0.4,
            "evidence_template": "SQL injection may lead to OS command execution via database features.",
            "requirements": ["Database user has file write privileges", "MSSQL xp_cmdshell enabled"],
            "likelihood": 0.3,
            "risk_increase": 0.5,
        },
    ],
    "SSRF": [
        {
            "target": "CLOUD_METADATA_ACCESS",
            "technique": "Cloud metadata service enumeration",
            "confidence": 0.75,
            "evidence_template": "SSRF confirmed. Cloud metadata endpoints may be reachable.",
            "requirements": ["Target hosted on cloud provider"],
            "likelihood": 0.7,
            "risk_increase": 0.4,
        },
        {
            "target": "INTERNAL_PORT_SCAN",
            "technique": "Internal network scanning via SSRF",
            "confidence": 0.6,
            "evidence_template": "SSRF enables internal network reconnaissance.",
            "requirements": ["Internal services behind NAT/firewall"],
            "likelihood": 0.6,
            "risk_increase": 0.2,
        },
    ],
    "OPEN_REDIRECT": [
        {
            "target": "OAUTH_TOKEN_THEFT",
            "technique": "OAuth token interception via open redirect",
            "confidence": 0.4,
            "evidence_template": "Open redirect can be used in OAuth flows to steal authorization codes.",
            "requirements": ["OAuth flow in use", "Redirect URI validation bypass"],
            "likelihood": 0.35,
            "risk_increase": 0.2,
        },
    ],
    "RCE": [
        {
            "target": "PRIVILEGE_ESCALATION",
            "technique": "Post-exploitation privilege escalation",
            "confidence": 0.5,
            "evidence_template": "RCE confirmed. Privilege escalation may be possible based on OS and configuration.",
            "requirements": ["Vulnerable SUID binaries", "Kernel exploit available"],
            "likelihood": 0.5,
            "risk_increase": 0.3,
        },
        {
            "target": "PERSISTENCE",
            "technique": "Backdoor installation for persistent access",
            "confidence": 0.6,
            "evidence_template": "RCE allows persistence mechanisms (cron, services, startup scripts).",
            "requirements": ["Write access to persistence points"],
            "likelihood": 0.6,
            "risk_increase": 0.2,
        },
        {
            "target": "LATERAL_MOVEMENT",
            "technique": "Network pivoting for lateral movement",
            "confidence": 0.4,
            "evidence_template": "RCE on this host can be used to pivot to internal network segments.",
            "requirements": ["Multiple network interfaces", "Internal network connectivity"],
            "likelihood": 0.4,
            "risk_increase": 0.3,
        },
    ],
    "WAF_BYPASS": [
        {
            "target": "LFI",
            "technique": "WAF bypass leading to LFI exploitation",
            "confidence": 0.5,
            "evidence_template": "WAF bypass techniques identified. Original vulnerability may be exploitable.",
            "requirements": ["Original vulnerability exists behind WAF"],
            "likelihood": 0.4,
            "risk_increase": 0.2,
        },
    ],
}


class AttackChainEngine:
    def __init__(self):
        self.plugins: List[ChainPluginInterface] = []
        self._chains: Dict[str, List[Dict[str, Any]]] = {
            k: list(v) for k, v in DEFAULT_CHAINS.items()
        }

    def register_plugin(self, plugin: ChainPluginInterface) -> None:
        self.plugins.append(plugin)
        logger.info(f"AttackChain: registered plugin {plugin.__class__.__name__}")

    def register_chain(self, source: str, transitions: List[Dict[str, Any]]) -> None:
        if source not in self._chains:
            self._chains[source] = []
        self._chains[source].extend(transitions)
        logger.info(f"AttackChain: registered {len(transitions)} transitions for {source}")

    def build_attack_paths(
        self,
        findings: List[Dict],
        knowledge_graph: Optional[KnowledgeGraph] = None,
    ) -> List[AttackPath]:
        paths: List[AttackPath] = []
        vuln_categories: Set[str] = set()
        category_map: Dict[str, List[Dict]] = {}

        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            vuln_categories.add(cat)
            if cat not in category_map:
                category_map[cat] = []
            category_map[cat].append(finding)

        for source_cat in vuln_categories:
            if source_cat not in self._chains:
                continue

            if source_cat not in category_map:
                continue

            for transition_def in self._chains[source_cat]:
                source_findings = category_map[source_cat]
                for sf in source_findings:
                    transition = ChainTransition(
                        source_finding=sf.get("payload_category", source_cat),
                        target_finding=transition_def["target"],
                        technique=transition_def["technique"],
                        confidence=transition_def["confidence"],
                        evidence=[transition_def["evidence_template"]],
                        requirements=transition_def.get("requirements", []),
                        estimated_likelihood=transition_def.get("likelihood", 0.5),
                        risk_increase=transition_def.get("risk_increase", 0.1),
                    )

                    base_confidence = transition_def["confidence"]
                    diff_score = sf.get("diff_score", 0)
                    evidence_boost = min(0.2, len(sf.get("findings", [])) * 0.05)
                    adjusted_confidence = min(1.0, base_confidence * (diff_score / 50.0) + evidence_boost)

                    transition.confidence = adjusted_confidence
                    transition.evidence = sf.get("findings", []) + [transition_def["evidence_template"]]

                    if knowledge_graph:
                        finding_nodes = knowledge_graph.get_nodes_by_type(NodeType.FINDING)
                        matching = [
                            n for n in finding_nodes
                            if source_cat in n.label
                        ]
                        if matching:
                            related = knowledge_graph.get_neighbors(matching[0].id)
                            related_evidence = [
                                n.label for n in related
                                if n.node_type == NodeType.EVIDENCE
                            ]
                            if related_evidence:
                                transition.evidence.extend(related_evidence)

                    path = AttackPath(
                        id=str(uuid.uuid4()),
                        name=f"{source_cat} -> {transition_def['target']}",
                        steps=[transition],
                        overall_confidence=adjusted_confidence,
                        total_risk=transition_def.get("risk_increase", 0.1),
                        prerequisites=transition_def.get("requirements", []),
                    )

                    paths.append(path)

        for plugin in self.plugins:
            try:
                for source_cat in vuln_categories:
                    for target_cat in vuln_categories:
                        if plugin.can_handle(source_cat, target_cat):
                            transition = plugin.build_transition(source_cat, target_cat)
                            if transition:
                                path = AttackPath(
                                    id=str(uuid.uuid4()),
                                    name=f"{source_cat} -> {target_cat} (plugin)",
                                    steps=[transition],
                                    overall_confidence=transition.confidence,
                                    total_risk=transition.risk_increase,
                                )
                                paths.append(path)
            except Exception as e:
                logger.debug(f"Chain plugin error: {e}")

        paths.sort(key=lambda p: p.overall_confidence, reverse=True)
        logger.info(f"AttackChainEngine: generated {len(paths)} attack paths")
        return paths

    def to_dict(self, paths: List[AttackPath]) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in paths]

    def to_json(self, paths: List[AttackPath], indent: int = 2) -> str:
        return json.dumps([p.to_dict() for p in paths], indent=indent)
