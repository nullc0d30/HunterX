from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..knowledge_graph import KnowledgeGraph
from ..threat_model import ThreatModel
from ..payload_graph import PayloadKnowledgeGraph
from ..adaptive_memory import AdaptiveMemory
from ..planner import Planner
from ..risk_engine import RiskEngine
from ..browser_intelligence import BrowserIntelligenceEngine as BrowserIntelligence
from ..session import StealthSession as Session


@dataclass
class AgentContext:
    target_url: str = ""
    knowledge_graph: Optional[KnowledgeGraph] = None
    threat_model: Optional[ThreatModel] = None
    payload_graph: Optional[PayloadKnowledgeGraph] = None
    adaptive_memory: Optional[AdaptiveMemory] = None
    planner: Optional[Planner] = None
    risk_engine: Optional[RiskEngine] = None
    browser_intelligence: Optional[BrowserIntelligence] = None
    session: Optional[Session] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    conversation_history: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "technologies": self.technologies,
            "findings_count": len(self.findings),
            "evidence_keys": list(self.evidence.keys()),
            "conversation_length": len(self.conversation_history),
            "metadata": self.metadata,
        }
