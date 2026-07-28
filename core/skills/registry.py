from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Set

from ..utils import logger
from .base import SecuritySkill
from .capability import SkillCapability, SkillCapabilityRegistry
from .metadata import SkillMetadata


class SkillRegistry:
    _instance: Optional[SkillRegistry] = None
    _lock: threading.RLock = threading.RLock()

    def __new__(cls) -> SkillRegistry:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._skills: Dict[str, SecuritySkill] = {}
                    cls._instance._enabled: Set[str] = set()
        return cls._instance

    def register(self, skill: SecuritySkill) -> None:
        skill_id = skill.metadata.skill_id
        self._skills[skill_id] = skill
        SkillCapabilityRegistry.register(skill_id, skill.capabilities)
        self._enabled.add(skill_id)
        logger.info(f"SkillRegistry: registered {skill.metadata.name} ({skill_id})")

    def unregister(self, skill_id: str) -> None:
        self._skills.pop(skill_id, None)
        SkillCapabilityRegistry.unregister(skill_id)
        self._enabled.discard(skill_id)

    def get(self, skill_id: str) -> Optional[SecuritySkill]:
        return self._skills.get(skill_id)

    def get_enabled(self, skill_id: str) -> Optional[SecuritySkill]:
        if skill_id in self._enabled:
            return self._skills.get(skill_id)
        return None

    def list(self) -> List[Dict[str, Any]]:
        return [s.metadata.to_dict() for s in self._skills.values()]

    def list_enabled(self) -> List[Dict[str, Any]]:
        return [self._skills[sid].metadata.to_dict() for sid in self._enabled if sid in self._skills]

    def search(self, query: str) -> List[SkillMetadata]:
        results: List[SkillMetadata] = []
        q = query.lower()
        for skill in self._skills.values():
            m = skill.metadata
            if q in m.name.lower() or q in m.description.lower() or q in m.skill_id.lower():
                results.append(m)
            elif any(q in t.lower() for t in m.tags):
                results.append(m)
            elif any(q in c.lower() for c in m.categories):
                results.append(m)
        return results

    def filter(
        self,
        category: str = "",
        capability: Optional[SkillCapability] = None,
        risk_level: str = "",
        min_confidence: float = 0.0,
    ) -> List[SkillMetadata]:
        results: List[SkillMetadata] = []
        for skill in self._skills.values():
            m = skill.metadata
            if category and category not in m.categories:
                continue
            if capability and capability not in skill.capabilities:
                continue
            if risk_level and m.risk_level.value != risk_level:
                continue
            results.append(m)
        return results

    def dependencies(self, skill_id: str) -> List[str]:
        skill = self._skills.get(skill_id)
        if skill:
            return skill.metadata.dependencies
        return []

    def health(self) -> Dict[str, Any]:
        healthy = 0
        for skill in self._skills.values():
            try:
                if skill._initialized:
                    healthy += 1
            except Exception:
                pass
        return {
            "total": len(self._skills),
            "enabled": len(self._enabled),
            "healthy": healthy,
            "skill_ids": list(self._skills.keys()),
        }

    def enable(self, skill_id: str) -> bool:
        if skill_id in self._skills:
            self._enabled.add(skill_id)
            return True
        return False

    def disable(self, skill_id: str) -> bool:
        self._enabled.discard(skill_id)
        return True

    def count(self) -> int:
        return len(self._skills)

    def clear(self) -> None:
        self._skills.clear()
        self._enabled.clear()
        SkillCapabilityRegistry.clear()
