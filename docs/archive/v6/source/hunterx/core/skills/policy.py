from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict


class SkillSafetyLevel(str, Enum):
    SAFE = "safe"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    RESEARCH = "research"
    PARANOID = "paranoid"


@dataclass
class SkillPolicy:
    safety_level: SkillSafetyLevel = SkillSafetyLevel.BALANCED
    allow_destructive: bool = False
    allow_intrusive: bool = False
    allow_network_scan: bool = True
    max_execution_time: int = 60
    max_retries: int = 3
    require_confirmation: bool = False
    log_full_output: bool = True
    validate_output: bool = True
    require_evidence: bool = True
    min_confidence: float = 0.5
    rate_limit_per_minute: int = 30
    max_concurrent_executions: int = 5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safety_level": self.safety_level.value,
            "allow_destructive": self.allow_destructive,
            "allow_intrusive": self.allow_intrusive,
            "allow_network_scan": self.allow_network_scan,
            "max_execution_time": self.max_execution_time,
            "max_retries": self.max_retries,
            "require_confirmation": self.require_confirmation,
            "log_full_output": self.log_full_output,
            "validate_output": self.validate_output,
            "require_evidence": self.require_evidence,
            "min_confidence": self.min_confidence,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "max_concurrent_executions": self.max_concurrent_executions,
        }


SAFETY_PRESETS: Dict[SkillSafetyLevel, Dict[str, Any]] = {
    SkillSafetyLevel.SAFE: {
        "allow_destructive": False,
        "allow_intrusive": False,
        "allow_network_scan": False,
        "require_confirmation": True,
        "validate_output": True,
        "min_confidence": 0.9,
        "max_retries": 1,
    },
    SkillSafetyLevel.BALANCED: {
        "allow_destructive": False,
        "allow_intrusive": False,
        "allow_network_scan": True,
        "require_confirmation": False,
        "validate_output": True,
        "min_confidence": 0.7,
        "max_retries": 3,
    },
    SkillSafetyLevel.AGGRESSIVE: {
        "allow_destructive": False,
        "allow_intrusive": True,
        "allow_network_scan": True,
        "require_confirmation": False,
        "validate_output": True,
        "min_confidence": 0.5,
        "max_retries": 5,
    },
    SkillSafetyLevel.RESEARCH: {
        "allow_destructive": True,
        "allow_intrusive": True,
        "allow_network_scan": True,
        "require_confirmation": False,
        "validate_output": False,
        "min_confidence": 0.3,
        "max_retries": 10,
    },
    SkillSafetyLevel.PARANOID: {
        "allow_destructive": False,
        "allow_intrusive": False,
        "allow_network_scan": True,
        "require_confirmation": True,
        "validate_output": True,
        "min_confidence": 0.95,
        "log_full_output": True,
        "max_retries": 1,
    },
}
