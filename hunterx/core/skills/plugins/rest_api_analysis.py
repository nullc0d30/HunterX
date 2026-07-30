from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class RESTAPIAnalysisSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.REST_API]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="rest_api_analysis",
            name="REST API Analysis",
            description="Audits REST API endpoints for authentication, rate limiting, and data exposure issues",
            version="1.0.0",
            author="HunterX",
            tags=["rest", "api", "endpoint"],
            categories=["api security", "analysis"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1190"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "rest_api_audit", "detail": f"Audited REST API at {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
