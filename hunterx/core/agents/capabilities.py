from __future__ import annotations

from enum import Enum
from typing import Dict, List, Set


class AgentCapability(str, Enum):
    RECON = "recon"
    THREAT_MODELING = "threat_modeling"
    PAYLOAD_SELECTION = "payload_selection"
    VERIFICATION = "verification"
    PLANNING = "planning"
    RISK_ANALYSIS = "risk_analysis"
    REPORTING = "reporting"
    PURPLE_TEAM = "purple_team"
    BROWSER_INTELLIGENCE = "browser_intelligence"
    LEARNING = "learning"
    COORDINATION = "coordination"
    CODE_REVIEW = "code_review"
    EXPLOITABILITY_ESTIMATION = "exploitability_estimation"
    SUMMARIZATION = "summarization"
    CLASSIFICATION = "classification"
    MITIGATION = "mitigation"
    CUSTOM = "custom"


class CapabilityRegistry:
    _capabilities: Dict[str, Set[AgentCapability]] = {}

    @classmethod
    def register(cls, agent_id: str, capabilities: List[AgentCapability]) -> None:
        cls._capabilities[agent_id] = set(capabilities)

    @classmethod
    def unregister(cls, agent_id: str) -> None:
        cls._capabilities.pop(agent_id, None)

    @classmethod
    def get_capabilities(cls, agent_id: str) -> Set[AgentCapability]:
        return cls._capabilities.get(agent_id, set())

    @classmethod
    def find_agents_by_capability(cls, capability: AgentCapability) -> List[str]:
        return [aid for aid, caps in cls._capabilities.items() if capability in caps]

    @classmethod
    def find_agents_by_capabilities(cls, capabilities: List[AgentCapability]) -> List[str]:
        required = set(capabilities)
        return [aid for aid, caps in cls._capabilities.items() if required.issubset(caps)]

    @classmethod
    def all_capabilities(cls) -> Dict[str, List[str]]:
        return {aid: [c.value for c in caps] for aid, caps in cls._capabilities.items()}

    @classmethod
    def clear(cls) -> None:
        cls._capabilities.clear()
