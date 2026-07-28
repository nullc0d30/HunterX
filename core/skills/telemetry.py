from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class TelemetryRecord:
    skill_id: str
    execution_time_ms: float
    success: bool
    confidence: float
    risk_score: float
    noise_score: float
    cost: float
    retries: int
    timestamp: float = field(default_factory=time.time)


class SkillTelemetry:
    def __init__(self, max_records: int = 10000):
        self._lock = threading.RLock()
        self._records: List[TelemetryRecord] = []
        self._max_records = max_records

    def record(
        self,
        skill_id: str,
        execution_time_ms: float,
        success: bool,
        confidence: float = 0.0,
        risk_score: float = 0.0,
        noise_score: float = 0.0,
        cost: float = 0.0,
        retries: int = 0,
    ) -> None:
        with self._lock:
            self._records.append(TelemetryRecord(
                skill_id=skill_id,
                execution_time_ms=execution_time_ms,
                success=success,
                confidence=confidence,
                risk_score=risk_score,
                noise_score=noise_score,
                cost=cost,
                retries=retries,
            ))
            if len(self._records) > self._max_records:
                self._records = self._records[-self._max_records:]

    def get_stats(self, skill_id: str = "") -> Dict[str, Any]:
        with self._lock:
            records = [r for r in self._records if not skill_id or r.skill_id == skill_id]
            if not records:
                return {"total_executions": 0}

            total = len(records)
            successes = sum(1 for r in records if r.success)
            return {
                "total_executions": total,
                "success_count": successes,
                "failure_count": total - successes,
                "success_rate": successes / total if total > 0 else 0.0,
                "avg_execution_time_ms": sum(r.execution_time_ms for r in records) / total,
                "avg_confidence": sum(r.confidence for r in records) / total,
                "avg_risk_score": sum(r.risk_score for r in records) / total,
                "avg_noise_score": sum(r.noise_score for r in records) / total,
                "avg_cost": sum(r.cost for r in records) / total,
                "avg_retries": sum(r.retries for r in records) / total,
                "min_execution_time_ms": min(r.execution_time_ms for r in records),
                "max_execution_time_ms": max(r.execution_time_ms for r in records),
            }

    def get_summary(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            skill_ids = set(r.skill_id for r in self._records)
            return {sid: self.get_stats(sid) for sid in skill_ids}

    def clear(self, skill_id: str = "") -> None:
        with self._lock:
            if skill_id:
                self._records = [r for r in self._records if r.skill_id != skill_id]
            else:
                self._records.clear()
