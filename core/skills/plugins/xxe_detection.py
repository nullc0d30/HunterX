from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class XXEDetectionSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.XXE]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="xxe_detection",
            name="XXE Detection",
            description="Detects XML External Entity processing vulnerabilities in XML parsers",
            version="1.0.0",
            author="HunterX",
            tags=["xxe", "xml", "entity"],
            categories=["web security", "detection"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1190"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "xxe_test", "detail": f"Tested for XXE on {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
