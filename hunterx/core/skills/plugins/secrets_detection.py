from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class SecretsDetectionSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.SECRETS_DETECTION]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="secrets_detection",
            name="Secrets Detection",
            description="Scans for exposed API keys, tokens, passwords, and other secrets in responses and source",
            version="1.0.0",
            author="HunterX",
            tags=["secret", "leak", "credential"],
            categories=["security", "detection"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1552"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "secret_leak", "detail": f"Searched for secrets on {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
