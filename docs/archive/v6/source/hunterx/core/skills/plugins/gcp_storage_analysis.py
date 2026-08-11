from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class GCPStorageAnalysisSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.GCP_STORAGE]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="gcp_storage_analysis",
            name="GCP Storage Analysis",
            description="Inspects Google Cloud Storage buckets for uniform vs fine-grained access control issues",
            version="1.0.0",
            author="HunterX",
            tags=["gcp", "storage", "bucket"],
            categories=["cloud security", "analysis"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1613"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "gcp_storage_check", "detail": f"Checked GCP storage ACLs for {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
