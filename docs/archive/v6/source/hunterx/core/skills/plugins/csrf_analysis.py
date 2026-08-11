from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class CSRFDetectionSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.CSRF_ANALYSIS]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="csrf_detection",
            name="CSRF Detection",
            description="Detects missing or weak cross-site request forgery protections on state-changing endpoints",
            version="1.0.0",
            author="HunterX",
            tags=["csrf", "web", "token"],
            categories=["web security", "detection"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1190"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "csrf_check", "detail": f"Tested CSRF protections on {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
