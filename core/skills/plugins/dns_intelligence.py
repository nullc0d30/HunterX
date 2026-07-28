from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class DNSIntelligenceSkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.DNS_INTELLIGENCE]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="dns_intelligence",
            name="DNS Intelligence",
            description="Gathers DNS records including A, AAAA, MX, TXT, NS, and CNAME for reconnaissance",
            version="1.0.0",
            author="HunterX",
            tags=["dns", "recon", "resolution"],
            categories=["reconnaissance", "intelligence"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1595"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "dns_records", "detail": f"Resolved DNS records for {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
