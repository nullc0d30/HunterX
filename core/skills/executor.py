from __future__ import annotations

import time
import threading
from typing import Dict, List, Optional

from ..utils import logger
from .cache import SkillCache
from .context import SkillContext
from .policy import SkillPolicy
from .registry import SkillRegistry
from .result import SkillResult, SkillStatus
from .telemetry import SkillTelemetry
from .validator import SkillValidator


class SkillExecutor:
    def __init__(
        self,
        registry: Optional[SkillRegistry] = None,
        cache: Optional[SkillCache] = None,
        telemetry: Optional[SkillTelemetry] = None,
        validator: Optional[SkillValidator] = None,
    ):
        self._registry = registry or SkillRegistry()
        self._cache = cache or SkillCache()
        self._telemetry = telemetry or SkillTelemetry()
        self._validator = validator or SkillValidator()
        self._lock = threading.RLock()
        self._active_executions: Dict[str, int] = {}

    def execute(
        self,
        skill_id: str,
        target: str,
        context: Optional[SkillContext] = None,
        use_cache: bool = True,
    ) -> SkillResult:
        skill = self._registry.get_enabled(skill_id)
        if not skill:
            return SkillResult.failure(skill_id, error_message=f"Skill not found or disabled: {skill_id}")

        policy = context.policy if context and context.policy else SkillPolicy()
        policy_warnings = SkillValidator.validate_policy(skill.metadata, policy)
        if policy_warnings:
            logger.warning(f"Skill {skill_id} policy warnings: {policy_warnings}")

        if use_cache:
            cached = self._cache.get(skill_id, target)
            if cached:
                logger.info(f"SkillExecutor: cache hit for {skill_id} on {target}")
                return cached

        if not skill.supports(target, context):
            return SkillResult.failure(skill_id, error_message=f"Skill does not support target: {target}")

        with self._lock:
            current = self._active_executions.get(skill_id, 0)
            if current >= policy.max_concurrent_executions:
                return SkillResult.failure(skill_id, error_message="Max concurrent executions reached")
            self._active_executions[skill_id] = current + 1

        try:
            start = time.monotonic()
            result = skill.execute(target, context)
            elapsed = (time.monotonic() - start) * 1000
            result.execution_time_ms = elapsed

            if result.status == SkillStatus.COMPLETED and use_cache:
                self._cache.set(skill_id, target, result)

            self._telemetry.record(
                skill_id=skill_id,
                execution_time_ms=elapsed,
                success=result.status == SkillStatus.COMPLETED,
                confidence=result.confidence,
                risk_score=result.risk_score,
                noise_score=result.noise_score,
                retries=result.retries,
            )

            return result

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.error(f"SkillExecutor: {skill_id} failed: {e}")
            result = SkillResult.failure(skill_id, error_message=str(e))
            result.execution_time_ms = elapsed

            self._telemetry.record(
                skill_id=skill_id,
                execution_time_ms=elapsed,
                success=False,
                retries=result.retries,
            )
            return result

        finally:
            with self._lock:
                self._active_executions[skill_id] = max(0, self._active_executions.get(skill_id, 1) - 1)

    def execute_batch(
        self,
        skills: List[str],
        target: str,
        context: Optional[SkillContext] = None,
    ) -> Dict[str, SkillResult]:
        results: Dict[str, SkillResult] = {}
        for skill_id in skills:
            results[skill_id] = self.execute(skill_id, target, context)
        return results

    def get_cache(self) -> SkillCache:
        return self._cache

    def get_telemetry(self) -> SkillTelemetry:
        return self._telemetry
