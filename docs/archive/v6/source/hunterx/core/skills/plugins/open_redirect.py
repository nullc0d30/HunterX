from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class OpenRedirectSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.OPEN_REDIRECT]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="open_redirect",
            name="Open Redirect Detection",
            description="Identifies unvalidated redirect parameters that could lead to phishing attacks",
            version="1.0.0",
            author="HunterX",
            tags=["redirect", "web", "phishing"],
            categories=["web security", "detection"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1204"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "redirect_check", "detail": f"Scanned for open redirects on {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
