from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class GoalType(str, Enum):
    RECON = "recon"
    THREAT_MODELING = "threat_modeling"
    PAYLOAD_SELECTION = "payload_selection"
    VERIFICATION = "verification"
    PLANNING = "planning"
    RISK_ANALYSIS = "risk_analysis"
    REPORTING = "reporting"
    MITIGATION = "mitigation"
    CLASSIFICATION = "classification"
    SUMMARIZATION = "summarization"
    EXPLOITABILITY_ESTIMATION = "exploitability_estimation"
    ATTACK_PATH_PRIORITIZATION = "attack_path_prioritization"
    EVIDENCE_VERIFICATION = "evidence_verification"
    EXECUTIVE_SUMMARY = "executive_summary"
    PURPLE_TEAM = "purple_team"
    LEARNING = "learning"
    CODE_REVIEW = "code_review"
    CUSTOM = "custom"


class GoalPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GoalStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass
class Goal:
    id: str
    type: GoalType
    objective: str
    context: Dict[str, Any] = field(default_factory=dict)
    expected_output: str = ""
    priority: GoalPriority = GoalPriority.MEDIUM
    status: GoalStatus = GoalStatus.PENDING
    confidence_requirement: float = 0.7
    max_cost: float = 0.0
    max_latency_ms: float = 30000.0
    safety_policy: str = "balanced"
    source_agent: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    parent_goal_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "objective": self.objective,
            "context": self.context,
            "expected_output": self.expected_output,
            "priority": self.priority.value,
            "status": self.status.value,
            "confidence_requirement": self.confidence_requirement,
            "max_cost": self.max_cost,
            "max_latency_ms": self.max_latency_ms,
            "safety_policy": self.safety_policy,
            "source_agent": self.source_agent,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "parent_goal_id": self.parent_goal_id,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def create(
        cls,
        goal_type: GoalType,
        objective: str,
        context: Optional[Dict[str, Any]] = None,
        priority: GoalPriority = GoalPriority.MEDIUM,
        source_agent: str = "",
        **kwargs: Any,
    ) -> Goal:
        return cls(
            id=str(uuid.uuid4()),
            type=goal_type,
            objective=objective,
            context=context or {},
            priority=priority,
            source_agent=source_agent,
            **kwargs,
        )
