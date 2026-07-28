from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SkillStatus(str, Enum):
    PENDING = "pending"
    PREPARING = "preparing"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class SkillResult:
    skill_id: str
    status: SkillStatus
    confidence: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    telemetry: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    purple_team_rules: List[Dict[str, Any]] = field(default_factory=list)
    mitre_mapping: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    noise_score: float = 0.0
    execution_time_ms: float = 0.0
    retries: int = 0
    error_message: str = ""
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "status": self.status.value,
            "confidence": self.confidence,
            "findings_count": len(self.findings),
            "evidence_count": len(self.evidence),
            "artifacts_keys": list(self.artifacts.keys()),
            "logs_count": len(self.logs),
            "telemetry": self.telemetry,
            "recommendations": self.recommendations,
            "purple_team_rules_count": len(self.purple_team_rules),
            "mitre_mapping": self.mitre_mapping,
            "risk_score": self.risk_score,
            "noise_score": self.noise_score,
            "execution_time_ms": self.execution_time_ms,
            "retries": self.retries,
            "error_message": self.error_message,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def success(
        cls,
        skill_id: str,
        confidence: float = 1.0,
        findings: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> SkillResult:
        return cls(
            skill_id=skill_id,
            status=SkillStatus.COMPLETED,
            confidence=confidence,
            findings=findings or [],
            evidence=evidence or [],
            **kwargs,
        )

    @classmethod
    def failure(
        cls,
        skill_id: str,
        error_message: str = "",
        **kwargs: Any,
    ) -> SkillResult:
        return cls(
            skill_id=skill_id,
            status=SkillStatus.FAILED,
            error_message=error_message,
            **kwargs,
        )
