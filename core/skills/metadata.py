from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NoiseLevel(str, Enum):
    SILENT = "silent"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    AGGRESSIVE = "aggressive"


@dataclass
class SkillMetadata:
    skill_id: str
    name: str
    description: str
    version: str = "1.0.0"
    author: str = "HunterX"
    license: str = "Apache-2.0"
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    supported_protocols: List[str] = field(default_factory=list)
    supported_technologies: List[str] = field(default_factory=list)
    supported_languages: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    noise_level: NoiseLevel = NoiseLevel.LOW
    safety_policy: str = "balanced"
    dependencies: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    cvss_reference: str = ""
    required_permissions: List[str] = field(default_factory=list)
    expected_artifacts: List[str] = field(default_factory=list)
    timeout_seconds: int = 60
    retry_allowed: bool = True
    max_retries: int = 3
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "license": self.license,
            "tags": self.tags,
            "categories": self.categories,
            "required_capabilities": self.required_capabilities,
            "supported_protocols": self.supported_protocols,
            "supported_technologies": self.supported_technologies,
            "supported_languages": self.supported_languages,
            "risk_level": self.risk_level.value,
            "noise_level": self.noise_level.value,
            "safety_policy": self.safety_policy,
            "dependencies": self.dependencies,
            "mitre_techniques": self.mitre_techniques,
            "owasp_categories": self.owasp_categories,
            "cwe_ids": self.cwe_ids,
            "capec_ids": self.capec_ids,
            "cvss_reference": self.cvss_reference,
            "required_permissions": self.required_permissions,
            "expected_artifacts": self.expected_artifacts,
            "timeout_seconds": self.timeout_seconds,
            "retry_allowed": self.retry_allowed,
            "max_retries": self.max_retries,
        }

    @classmethod
    def create(
        cls,
        skill_id: str,
        name: str,
        description: str,
        version: str = "1.0.0",
        **kwargs: Any,
    ) -> SkillMetadata:
        return cls(
            skill_id=skill_id,
            name=name,
            description=description,
            version=version,
            **kwargs,
        )
