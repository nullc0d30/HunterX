from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ReasoningSafetyLevel(str, Enum):
    SAFEST = "safest"
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"
    RESEARCH = "research"


@dataclass
class ReasoningPolicy:
    name: str
    safety_level: ReasoningSafetyLevel = ReasoningSafetyLevel.BALANCED
    min_confidence: float = 0.7
    require_evidence: bool = True
    max_retries: int = 3
    allow_fallback: bool = True
    allow_consensus: bool = False
    min_consensus_providers: int = 1
    max_cost_per_goal: float = 0.0
    max_latency_ms: float = 60000.0
    validate_output: bool = True
    require_json_schema: bool = False
    log_reasoning: bool = True
    cache_results: bool = True
    cache_ttl_seconds: int = 3600
    metadata: Dict[str, Any] = field(default_factory=dict)


SAFETY_PRESETS: Dict[ReasoningSafetyLevel, Dict[str, Any]] = {
    ReasoningSafetyLevel.SAFEST: {
        "min_confidence": 0.95,
        "require_evidence": True,
        "allow_fallback": False,
        "allow_consensus": True,
        "min_consensus_providers": 3,
        "validate_output": True,
        "require_json_schema": True,
        "max_cost_per_goal": 0.0,
    },
    ReasoningSafetyLevel.CONSERVATIVE: {
        "min_confidence": 0.85,
        "require_evidence": True,
        "allow_fallback": True,
        "allow_consensus": False,
        "validate_output": True,
        "require_json_schema": True,
        "max_cost_per_goal": 0.01,
    },
    ReasoningSafetyLevel.BALANCED: {
        "min_confidence": 0.7,
        "require_evidence": True,
        "allow_fallback": True,
        "allow_consensus": False,
        "validate_output": True,
        "require_json_schema": False,
        "max_cost_per_goal": 0.05,
    },
    ReasoningSafetyLevel.PERMISSIVE: {
        "min_confidence": 0.5,
        "require_evidence": False,
        "allow_fallback": True,
        "allow_consensus": False,
        "validate_output": True,
        "require_json_schema": False,
        "max_cost_per_goal": 0.1,
    },
    ReasoningSafetyLevel.RESEARCH: {
        "min_confidence": 0.3,
        "require_evidence": False,
        "allow_fallback": True,
        "allow_consensus": True,
        "min_consensus_providers": 1,
        "validate_output": False,
        "require_json_schema": False,
        "max_cost_per_goal": 1.0,
    },
}


class PolicyManager:
    _policies: Dict[str, ReasoningPolicy] = {}

    @classmethod
    def register(cls, policy: ReasoningPolicy) -> None:
        cls._policies[policy.name] = policy

    @classmethod
    def get(cls, name: str) -> Optional[ReasoningPolicy]:
        return cls._policies.get(name)

    @classmethod
    def from_safety_level(cls, level: ReasoningSafetyLevel) -> ReasoningPolicy:
        name = level.value
        preset = SAFETY_PRESETS.get(level, {})
        return ReasoningPolicy(name=name, safety_level=level, **preset)

    @classmethod
    def list_policies(cls) -> List[ReasoningPolicy]:
        return list(cls._policies.values())


for level in ReasoningSafetyLevel:
    PolicyManager.register(PolicyManager.from_safety_level(level))
