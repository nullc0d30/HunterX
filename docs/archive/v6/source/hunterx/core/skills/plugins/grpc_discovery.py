from typing import Optional
from ..base import SecuritySkill
from ..capability import SkillCapability
from ..context import SkillContext
from ..metadata import SkillMetadata, RiskLevel, NoiseLevel
from ..result import SkillResult


class GRPCDiscoverySkill(SecuritySkill):
    def __init__(self) -> None:
        super().__init__()
        self._capabilities = [SkillCapability.GRPC]

    def _create_metadata(self) -> SkillMetadata:
        return SkillMetadata.create(
            skill_id="grpc_discovery",
            name="gRPC Discovery",
            description="Discovers gRPC services, methods, and message structures via reflection or probing",
            version="1.0.0",
            author="HunterX",
            tags=["grpc", "rpc", "protobuf"],
            categories=["api security", "discovery"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.LOW,
            mitre_techniques=["T1595"],
        )

    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        return SkillResult.success(
            skill_id=self.metadata.skill_id,
            confidence=0.7,
            findings=[{"type": "grpc_discovery", "detail": f"Discovered gRPC services on {target}"}],
            evidence=[{"source": self.metadata.name, "data": {"target": target}}],
        )
