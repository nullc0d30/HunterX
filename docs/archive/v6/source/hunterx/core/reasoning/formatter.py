from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .goals import Goal
from .consensus import ConsensusResult
from .confidence import ConfidenceLevel


@dataclass
class ReasoningResult:
    goal_id: str
    goal_type: str
    objective: str
    response: str
    confidence: float
    confidence_level: ConfidenceLevel
    provider: str
    model: str
    latency_ms: float
    cost: float
    normalized_output: Optional[Dict[str, Any]] = None
    consensus: Optional[ConsensusResult] = None
    validation_errors: List[str] = field(default_factory=list)
    validation_warnings: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "goal_type": self.goal_type,
            "objective": self.objective,
            "response": self.response,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "provider": self.provider,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "cost": self.cost,
            "normalized_output": self.normalized_output,
            "consensus": self.consensus.to_dict() if self.consensus else None,
            "validation_errors": self.validation_errors,
            "validation_warnings": self.validation_warnings,
            "evidence_refs": self.evidence_refs,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ReasoningFormatter:
    @staticmethod
    def format_goal_for_prompt(goal: Goal) -> Dict[str, str]:
        context_str = json.dumps(goal.context, indent=2) if goal.context else "{}"
        return {
            "objective": goal.objective,
            "context": context_str,
            "expected_output": goal.expected_output,
            "priority": goal.priority.value,
        }

    @staticmethod
    def format_result_summary(results: List[ReasoningResult]) -> str:
        lines = ["Reasoning Summary", "=" * 40]
        for r in results:
            lines.append(f"Goal: {r.objective[:60]}")
            lines.append(f"  Confidence: {r.confidence:.2f} ({r.confidence_level.value})")
            lines.append(f"  Provider: {r.provider}/{r.model}")
            lines.append(f"  Latency: {r.latency_ms:.0f}ms")
            lines.append(f"  Valid: {len(r.validation_errors) == 0}")
            if r.consensus:
                lines.append(f"  Consensus: {r.consensus.agreement:.2f} ({r.consensus.method})")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def format_decision_trace(goal: Goal, result: ReasoningResult) -> str:
        lines = [
            f"Decision Trace for Goal: {goal.id}",
            f"Objective: {goal.objective}",
            f"Source Agent: {goal.source_agent}",
            f"Priority: {goal.priority.value}",
            "",
            "Context:",
            json.dumps(goal.context, indent=2),
            "",
            "Reasoning Result:",
            f"Provider: {result.provider}",
            f"Confidence: {result.confidence:.2f}",
            f"Response: {result.response[:500]}",
            "",
            "Validation:",
            f"Errors: {result.validation_errors or 'None'}",
            f"Warnings: {result.validation_warnings or 'None'}",
        ]
        return "\n".join(lines)

    @staticmethod
    def format_evidence_graph(results: List[ReasoningResult]) -> str:
        lines = ["Evidence Graph", "=" * 40]
        for r in results:
            if r.evidence_refs:
                lines.append(f"  {r.goal_id[:8]} -> {', '.join(r.evidence_refs)}")
        return "\n".join(lines)
