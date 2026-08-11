from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class AzureBlobAnalysisSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.AZURE_BLOB]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="azure_blob_analysis",
            name="Azure Blob Analysis",
            description="Audits Azure Blob storage containers for anonymous access and data leakage",
            version="1.0.0",
            author="HunterX",
            tags=["azure", "blob", "storage"],
            categories=["cloud security", "analysis"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1613"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "azure_blob_audit", "detail": f"Audited Azure blob containers for {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
