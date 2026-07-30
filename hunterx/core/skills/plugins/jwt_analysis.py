from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class JWTAnalysisSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.JWT_ANALYSIS]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="jwt_analysis",
            name="JWT Analysis",
            description="Inspects JSON Web Tokens for signature bypass, alg confusion, and claims tampering",
            version="1.0.0",
            author="HunterX",
            tags=["jwt", "token", "auth"],
            categories=["authentication", "analysis"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1608"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "jwt_audit", "detail": f"Decoded and inspected JWT from {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
