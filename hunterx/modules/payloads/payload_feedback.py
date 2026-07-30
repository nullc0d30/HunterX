# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..intelligence.adaptive_memory import AdaptiveMemory
from ...utils.utils import logger


@dataclass
class FeedbackRecord:
    id: str = ""
    payload_hash: str = ""
    payload: str = ""
    category: str = ""
    technique: str = "original"
    success: bool = False
    detected: bool = False
    blocked: bool = False
    waf_blocked: bool = False
    latency_ms: float = 0.0
    status_code: int = 0
    response_size: int = 0
    error_message: str = ""
    target: str = ""
    target_fingerprint: str = ""
    confidence: float = 0.0
    score_delta: float = 0.0
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "payload_hash": self.payload_hash,
            "payload": self.payload[:200],
            "category": self.category,
            "technique": self.technique,
            "success": self.success,
            "detected": self.detected,
            "blocked": self.blocked,
            "waf_blocked": self.waf_blocked,
            "latency_ms": self.latency_ms,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "error_message": self.error_message,
            "target": self.target,
            "target_fingerprint": self.target_fingerprint,
            "confidence": round(self.confidence, 3),
            "score_delta": round(self.score_delta, 3),
            "timestamp": self.timestamp,
        }


class PayloadFeedbackLoop:
    def __init__(
        self,
        adaptive_memory: Optional[AdaptiveMemory] = None,
        storage_path: Optional[str] = None,
    ):
        self._memory = adaptive_memory or AdaptiveMemory()
        self._lock = threading.RLock()
        self._storage_path = storage_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "payload_feedback"
        )
        self._db_path = os.path.join(self._storage_path, "feedback.json")
        os.makedirs(self._storage_path, exist_ok=True)
        self._feedback_log: List[FeedbackRecord] = []
        self._load_feedback()

    def _load_feedback(self) -> None:
        if os.path.exists(self._db_path):
            try:
                with open(self._db_path) as f:
                    data = json.load(f)
                    self._feedback_log = [FeedbackRecord(**item) for item in data]
                logger.info(f"FeedbackLoop: loaded {len(self._feedback_log)} records")
            except Exception as e:
                logger.debug(f"FeedbackLoop: load failed: {e}")

    def _save_feedback(self) -> None:
        try:
            data = [r.to_dict() for r in self._feedback_log[-10000:]]
            with open(self._db_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"FeedbackLoop: save failed: {e}")

    def record_result(
        self,
        payload: str,
        category: str,
        success: bool,
        detected: bool = False,
        blocked: bool = False,
        waf_blocked: bool = False,
        latency_ms: float = 0.0,
        status_code: int = 0,
        response_size: int = 0,
        error_message: str = "",
        target: str = "",
        target_fingerprint: str = "",
        confidence: float = 0.5,
        technique: str = "original",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FeedbackRecord:
        payload_hash = self._hash(payload)
        score_delta = self._compute_score_delta(success, detected, blocked, waf_blocked)

        record = FeedbackRecord(
            id=str(uuid.uuid4()),
            payload_hash=payload_hash,
            payload=payload,
            category=category,
            technique=technique,
            success=success,
            detected=detected,
            blocked=blocked,
            waf_blocked=waf_blocked,
            latency_ms=latency_ms,
            status_code=status_code,
            response_size=response_size,
            error_message=error_message,
            target=target,
            target_fingerprint=target_fingerprint,
            confidence=confidence,
            score_delta=score_delta,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )

        with self._lock:
            self._feedback_log.append(record)
            self._update_adaptive_memory(record)
            self._save_feedback()

        log_level = "success" if success else ("blocked" if blocked else "failure")
        logger.debug(f"FeedbackLoop: {log_level} | {category} | delta={score_delta:+.3f}")

        return record

    def _compute_score_delta(
        self,
        success: bool,
        detected: bool,
        blocked: bool,
        waf_blocked: bool,
    ) -> float:
        if success and not detected:
            return 0.15
        if success and detected:
            return 0.05
        if blocked:
            return -0.1
        if waf_blocked:
            return -0.2
        return -0.05

    def _update_adaptive_memory(self, record: FeedbackRecord) -> None:
        if record.success:
            self._memory.record_successful_payload(
                payload=record.payload,
                category=record.category,
                target_fingerprint=record.target_fingerprint or record.target,
                confidence=record.confidence,
            )
        if record.blocked or record.waf_blocked:
            reason = "waf" if record.waf_blocked else "unknown"
            self._memory.record_blocked_payload(
                payload=record.payload,
                category=record.category,
                block_reason=reason,
            )

    def get_success_rate(
        self,
        category: Optional[str] = None,
        technique: Optional[str] = None,
        window: Optional[int] = None,
    ) -> float:
        filtered = self._filter_feedback(category, technique, window)
        if not filtered:
            return 0.0
        successes = sum(1 for r in filtered if r.success)
        return successes / len(filtered)

    def get_detection_rate(
        self,
        category: Optional[str] = None,
        technique: Optional[str] = None,
        window: Optional[int] = None,
    ) -> float:
        filtered = self._filter_feedback(category, technique, window)
        if not filtered:
            return 0.0
        detected = sum(1 for r in filtered if r.detected)
        return detected / len(filtered)

    def get_block_rate(
        self,
        category: Optional[str] = None,
        technique: Optional[str] = None,
        window: Optional[int] = None,
    ) -> float:
        filtered = self._filter_feedback(category, technique, window)
        if not filtered:
            return 0.0
        blocked = sum(1 for r in filtered if r.blocked or r.waf_blocked)
        return blocked / len(filtered)

    def get_top_performing(
        self,
        category: Optional[str] = None,
        top_n: int = 10,
        min_attempts: int = 3,
    ) -> List[Dict[str, Any]]:
        agg: Dict[str, Dict[str, Any]] = {}
        for record in self._feedback_log:
            if category and record.category != category:
                continue
            key = f"{record.category}:{record.payload_hash}"
            if key not in agg:
                agg[key] = {
                    "payload_hash": record.payload_hash,
                    "payload": record.payload,
                    "category": record.category,
                    "attempts": 0,
                    "successes": 0,
                    "blocks": 0,
                    "detections": 0,
                    "total_latency": 0.0,
                    "total_score_delta": 0.0,
                }
            a = agg[key]
            a["attempts"] += 1
            a["successes"] += 1 if record.success else 0
            a["blocks"] += 1 if record.blocked or record.waf_blocked else 0
            a["detections"] += 1 if record.detected else 0
            a["total_latency"] += record.latency_ms
            a["total_score_delta"] += record.score_delta

        scored = []
        for key, a in agg.items():
            if a["attempts"] < min_attempts:
                continue
            success_rate = a["successes"] / a["attempts"]
            block_rate = a["blocks"] / a["attempts"]
            avg_latency = a["total_latency"] / a["attempts"]
            performance = success_rate * 0.5 + (1.0 - block_rate) * 0.3 + (1.0 - min(1.0, avg_latency / 5000)) * 0.2
            scored.append((performance, a))

        scored.sort(key=lambda x: x[0], reverse=True)
        result = []
        for perf, a in scored[:top_n]:
            result.append({
                "payload_hash": a["payload_hash"],
                "payload": a["payload"][:200],
                "category": a["category"],
                "success_rate": round(a["successes"] / a["attempts"], 3),
                "block_rate": round(a["blocks"] / a["attempts"], 3),
                "detection_rate": round(a["detections"] / a["attempts"], 3),
                "avg_latency_ms": round(a["total_latency"] / a["attempts"], 1),
                "attempts": a["attempts"],
                "performance_score": round(perf, 3),
            })
        return result

    def get_recent_feedback(
        self,
        limit: int = 50,
        category: Optional[str] = None,
    ) -> List[FeedbackRecord]:
        filtered = self._feedback_log
        if category:
            filtered = [r for r in filtered if r.category == category]
        return filtered[-limit:]

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._feedback_log)
        if total == 0:
            return {"total": 0, "success_rate": 0.0, "detection_rate": 0.0, "block_rate": 0.0}

        successes = sum(1 for r in self._feedback_log if r.success)
        detections = sum(1 for r in self._feedback_log if r.detected)
        blocks = sum(1 for r in self._feedback_log if r.blocked or r.waf_blocked)

        categories: Dict[str, int] = {}
        for r in self._feedback_log:
            cat = r.category or "UNKNOWN"
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total": total,
            "success_rate": round(successes / total, 3),
            "detection_rate": round(detections / total, 3),
            "block_rate": round(blocks / total, 3),
            "categories": categories,
            "unique_payloads": len(set(r.payload_hash for r in self._feedback_log)),
        }

    def _filter_feedback(
        self,
        category: Optional[str] = None,
        technique: Optional[str] = None,
        window: Optional[int] = None,
    ) -> List[FeedbackRecord]:
        filtered = self._feedback_log
        if category:
            filtered = [r for r in filtered if r.category == category]
        if technique:
            filtered = [r for r in filtered if r.technique == technique]
        if window:
            filtered = filtered[-window:]
        return filtered

    @staticmethod
    def _hash(payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]
