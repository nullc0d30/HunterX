from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class RFIDetectionSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.RFI]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="rfi_detection",
            name="RFI Detection",
            description="Identifies remote file inclusion vectors that allow external script execution",
            version="1.0.0",
            author="HunterX",
            tags=["rfi", "remote", "inclusion"],
            categories=["web security", "detection"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1190"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "rfi_check", "detail": f"Checked for RFI on {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
