from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ...modules.intelligence.knowledge_graph import KnowledgeGraph
from ...modules.intelligence.threat_model import ThreatModel
from ...modules.payloads.payload_graph import PayloadKnowledgeGraph
from ...modules.intelligence.adaptive_memory import AdaptiveMemory
from ..risk_engine import RiskEngine
from ...modules.intelligence.browser_intelligence import BrowserIntelligenceEngine
from ..session import StealthSession
from .policy import SkillPolicy


@dataclass
class SkillContext:
    target: str = ""
    knowledge_graph: Optional[KnowledgeGraph] = None
    threat_model: Optional[ThreatModel] = None
    payload_graph: Optional[PayloadKnowledgeGraph] = None
    adaptive_memory: Optional[AdaptiveMemory] = None
    risk_engine: Optional[RiskEngine] = None
    browser_intelligence: Optional[BrowserIntelligenceEngine] = None
    session: Optional[StealthSession] = None
    policy: Optional[SkillPolicy] = None
    technologies: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "technologies": self.technologies,
            "findings_count": len(self.findings),
            "evidence_keys": list(self.evidence.keys()),
            "metadata": self.metadata,
        }
