# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .knowledge_graph import KnowledgeGraph, NodeType
from .attack_chain import AttackPath


@dataclass
class ExplainableEvidence:
    source: str
    detail: str
    confidence: float
    category: str = "observation"

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "detail": self.detail, "confidence": self.confidence, "category": self.category}


@dataclass
class Explanation:
    finding_id: str
    finding_type: str
    conclusion: str
    evidence: List[ExplainableEvidence] = field(default_factory=list)
    reasoning_steps: List[str] = field(default_factory=list)
    confidence: float = 0.0
    alternative_explanations: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "conclusion": self.conclusion,
            "evidence": [e.to_dict() for e in self.evidence],
            "reasoning_steps": self.reasoning_steps,
            "confidence": self.confidence,
            "alternative_explanations": self.alternative_explanations,
            "missing_evidence": self.missing_evidence,
            "assumptions": self.assumptions,
            "limitations": self.limitations,
            "created_at": self.created_at.isoformat(),
        }


class ExplainabilityEngine:
    def __init__(self):
        self._explanations: Dict[str, Explanation] = {}

    def explain_finding(
        self,
        finding: Dict[str, Any],
        knowledge_graph: Optional[KnowledgeGraph] = None,
        context: Any = None,
    ) -> Explanation:
        finding_id = str(uuid.uuid4())
        cat = finding.get("payload_category", "GENERIC")
        payload = finding.get("payload", "")
        diff_score = finding.get("diff_score", 0)
        raw_findings = finding.get("findings", [])

        evidence_list: List[ExplainableEvidence] = []
        reasoning_steps: List[str] = []
        alternative: List[str] = []
        missing: List[str] = []

        confidence_base = min(1.0, diff_score / 100.0)

        evidence_list.append(ExplainableEvidence(
            source="diff_analysis",
            detail=f"Anomaly score of {diff_score}/100 indicates significant response difference",
            confidence=min(1.0, diff_score / 80.0),
            category="quantitative",
        ))

        if raw_findings:
            for rf in raw_findings[:5]:
                evidence_list.append(ExplainableEvidence(
                    source="signature_match",
                    detail=str(rf),
                    confidence=0.8,
                    category="signature",
                ))
            reasoning_steps.append(f"Signature-based detection matched {len(raw_findings)} known patterns")

        if payload:
            evidence_list.append(ExplainableEvidence(
                source="payload_analysis",
                detail=f"Payload '{payload[:80]}' was injected",
                confidence=0.9,
                category="input",
            ))
            reasoning_steps.append(f"Payload of category '{cat}' was injected into the target")

        if cat == "SQLI":
            reasoning_steps.append("Database error messages or syntax anomalies detected in response")
            reasoning_steps.append("SQL control characters in payload produced unexpected database output")
            alternative.append("False positive: Database error may be generic, not injection-based")
            alternative.append("Error might originate from application logic, not SQL injection")
            missing.append("Blind SQL injection confirmation via time-based or boolean techniques")
            missing.append("Database fingerprinting to confirm injection context")

        elif cat == "LFI":
            reasoning_steps.append("File path traversal attempt yielded contents of a server-side file")
            reasoning_steps.append("Response contains recognizable file content patterns")
            alternative.append("File content may be cached or reflected from earlier legitimate requests")
            alternative.append("WAF may have returned a sample file instead of the real target")
            missing.append("Multiple file read attempts to confirm arbitrary read capability")

        elif cat == "XSS":
            reasoning_steps.append("JavaScript payload was reflected in the response without sanitization")
            reasoning_steps.append("Context analysis confirms payload lands in executable context")
            alternative.append("Payload may be HTML-encoded and not executable")
            alternative.append("CSP headers may prevent actual script execution")
            missing.append("CSP policy analysis to determine exploitability")
            missing.append("Confirmation that no output encoding is applied")

        elif cat == "RCE":
            reasoning_steps.append("Command output or execution artifacts detected in response")
            reasoning_steps.append("System command injection point confirmed")
            alternative.append("Output may be from a different input source")
            missing.append("Out-of-band confirmation via DNS/HTTP callback")

        elif cat == "SSTI":
            reasoning_steps.append("Template expression evaluated by the server-side engine")
            reasoning_steps.append("Mathematical or variable output confirms template context")
            alternative.append("Output may be coincidental and not template evaluation")
            missing.append("Determine template engine type for sandbox escape assessment")

        elif cat == "SSRF":
            reasoning_steps.append("Server attempted to fetch an external resource based on payload")
            reasoning_steps.append("Cloud metadata or internal service responses detected")
            alternative.append("Response may be from a local cache, not a live fetch")
            missing.append("OOB callback confirmation of SSRF")

        else:
            reasoning_steps.append(f"Anomaly detected in category '{cat}' with score {diff_score}")
            alternative.append("Response difference may be due to network or server conditions")
            missing.append("Additional confirmation payloads needed to reduce false positive rate")

        if knowledge_graph:
            finding_nodes = knowledge_graph.get_nodes_by_type(NodeType.FINDING)
            for f_node in finding_nodes:
                if cat in f_node.label:
                    for neighbor in knowledge_graph.get_neighbors(f_node.id):
                        evidence_list.append(ExplainableEvidence(
                            source="knowledge_graph",
                            detail=f"Related {neighbor.node_type.value}: {neighbor.label[:60]}",
                            confidence=neighbor.confidence,
                            category="graph",
                        ))

        confidence = min(1.0, confidence_base + len(evidence_list) * 0.05)
        confidence = max(0.1, confidence - len(missing) * 0.1)

        explanation = Explanation(
            finding_id=finding_id,
            finding_type=cat,
            conclusion=f"{cat} vulnerability detected with {confidence:.0%} confidence based on "
                       f"{len(evidence_list)} evidence points and {len(reasoning_steps)} reasoning steps",
            evidence=evidence_list,
            reasoning_steps=reasoning_steps,
            confidence=round(confidence, 3),
            alternative_explanations=alternative,
            missing_evidence=missing,
            assumptions=[
                "Target response is truthful and not manipulated by middleware",
                "Network conditions are normal and not causing artificial differences",
            ],
            limitations=[
                "Static analysis cannot confirm runtime exploitability",
                "WAF or IPS may interfere with detection accuracy",
                "Evidence is based on observed responses, not code-level verification",
            ],
        )

        self._explanations[finding_id] = explanation
        return explanation

    def explain_attack_path(
        self,
        path: AttackPath,
        knowledge_graph: Optional[KnowledgeGraph] = None,
    ) -> Explanation:
        evidence_list = []
        reasoning_steps = []

        for i, step in enumerate(path.steps):
            evidence_list.append(ExplainableEvidence(
                source="attack_chain",
                detail=f"Step {i + 1}: {step.source_finding} -> {step.target_finding} via {step.technique}",
                confidence=step.confidence,
                category="transition",
            ))
            reasoning_steps.append(f"Transition {i + 1}: {step.technique} (confidence={step.confidence:.2f})")

        return Explanation(
            finding_id=str(uuid.uuid4()),
            finding_type="attack_path",
            conclusion=f"Attack path '{path.name}' has {path.overall_confidence:.0%} overall confidence",
            evidence=evidence_list,
            reasoning_steps=reasoning_steps,
            confidence=path.overall_confidence,
            alternative_explanations=[
                "Some transitions may require preconditions not currently met",
                "Alternative attack paths may exist with different tooling",
            ],
            missing_evidence=[
                s for s in path.prerequisites if s not in [e.detail for e in evidence_list]
            ],
        )

    def get_explanation(self, finding_id: str) -> Optional[Explanation]:
        return self._explanations.get(finding_id)

    def get_all_explanations(self) -> List[Explanation]:
        return list(self._explanations.values())

    def to_dict(self) -> Dict[str, Any]:
        return {"explanations": [e.to_dict() for e in self._explanations.values()]}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
