from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ...utils.utils import logger
from .capability import SkillCapability
from .context import SkillContext
from .metadata import SkillMetadata
from .policy import SkillPolicy
from .result import SkillResult, SkillStatus


class SecuritySkill(ABC):
    def __init__(self) -> None:
        self._metadata: Optional[SkillMetadata] = None
        self._capabilities: List[SkillCapability] = []
        self._policy: SkillPolicy = SkillPolicy()
        self._initialized: bool = False

    @property
    def metadata(self) -> SkillMetadata:
        if self._metadata is None:
            self._metadata = self._create_metadata()
        return self._metadata

    @property
    def capabilities(self) -> List[SkillCapability]:
        return self._capabilities

    @property
    def policy(self) -> SkillPolicy:
        return self._policy

    @policy.setter
    def policy(self, policy: SkillPolicy) -> None:
        self._policy = policy

    def initialize(self) -> None:
        if self._initialized:
            return
        self._on_initialize()
        self._initialized = True
        logger.info(f"Skill {self.metadata.name} v{self.metadata.version} initialized")

    def shutdown(self) -> None:
        self._on_shutdown()
        self._initialized = False
        logger.info(f"Skill {self.metadata.name} shutdown")

    def supports(self, target: str, context: Optional[SkillContext] = None) -> bool:
        return self._on_supports(target, context)

    def validate(self, target: str, context: Optional[SkillContext] = None) -> Optional[str]:
        return self._on_validate(target, context)

    def prepare(self, target: str, context: Optional[SkillContext] = None) -> bool:
        return self._on_prepare(target, context)

    def execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult:
        if not self._initialized:
            self.initialize()
        validation_error = self.validate(target, context)
        if validation_error:
            return SkillResult.failure(self.metadata.skill_id, error_message=validation_error)
        self.prepare(target, context)
        return self._on_execute(target, context)

    def verify(self, result: SkillResult) -> bool:
        return self._on_verify(result)

    def cleanup(self, result: SkillResult) -> None:
        self._on_cleanup(result)

    def explain(self, result: SkillResult) -> str:
        return self._on_explain(result)

    def estimate_cost(self, target: str) -> float:
        return self._on_estimate_cost(target)

    def estimate_duration(self, target: str) -> float:
        return self._on_estimate_duration(target)

    def risk_level(self) -> str:
        return self.metadata.risk_level.value

    def requirements(self) -> List[str]:
        return self._on_requirements()

    def _on_initialize(self) -> None: ...

    def _on_shutdown(self) -> None: ...

    def _on_supports(self, target: str, context: Optional[SkillContext] = None) -> bool:
        return len(target) > 0

    def _on_validate(self, target: str, context: Optional[SkillContext] = None) -> Optional[str]:
        if not target:
            return "Target is required"
        return None

    def _on_prepare(self, target: str, context: Optional[SkillContext] = None) -> bool:
        return True

    @abstractmethod
    def _on_execute(self, target: str, context: Optional[SkillContext] = None) -> SkillResult: ...

    def _on_verify(self, result: SkillResult) -> bool:
        return result.status == SkillStatus.COMPLETED and result.confidence >= 0.5

    def _on_cleanup(self, result: SkillResult) -> None: ...

    def _on_explain(self, result: SkillResult) -> str:
        return f"Skill {self.metadata.name} completed with confidence {result.confidence:.2f}"

    def _on_estimate_cost(self, target: str) -> float:
        return 0.001

    def _on_estimate_duration(self, target: str) -> float:
        return 1000.0

    def _on_requirements(self) -> List[str]:
        return self.metadata.dependencies

    @abstractmethod
    def _create_metadata(self) -> SkillMetadata: ...

    def to_dict(self) -> Dict[str, Any]:
        return self.metadata.to_dict()
