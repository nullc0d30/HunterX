from __future__ import annotations

from enum import Enum
from typing import Dict, List


class ConfidenceLevel(str, Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"
    INSUFFICIENT_DATA = "insufficient_data"
    CONFLICTING = "conflicting"


CONFIDENCE_THRESHOLDS: Dict[ConfidenceLevel, float] = {
    ConfidenceLevel.CERTAIN: 0.95,
    ConfidenceLevel.HIGH: 0.85,
    ConfidenceLevel.MEDIUM: 0.70,
    ConfidenceLevel.LOW: 0.50,
    ConfidenceLevel.UNCERTAIN: 0.30,
    ConfidenceLevel.INSUFFICIENT_DATA: 0.10,
    ConfidenceLevel.CONFLICTING: 0.0,
}


class ConfidenceScorer:
    @staticmethod
    def from_score(score: float) -> ConfidenceLevel:
        for level, threshold in sorted(CONFIDENCE_THRESHOLDS.items(), key=lambda x: -x[1]):
            if score >= threshold:
                return level
        return ConfidenceLevel.INSUFFICIENT_DATA

    @staticmethod
    def aggregate(scores: List[float], method: str = "mean") -> float:
        if not scores:
            return 0.0
        if method == "mean":
            return sum(scores) / len(scores)
        elif method == "median":
            sorted_scores = sorted(scores)
            mid = len(sorted_scores) // 2
            if len(sorted_scores) % 2 == 0:
                return (sorted_scores[mid - 1] + sorted_scores[mid]) / 2
            return sorted_scores[mid]
        elif method == "max":
            return max(scores)
        elif method == "min":
            return min(scores)
        elif method == "weighted":
            weights = [1.0 / (i + 1) for i in range(len(scores))]
            total_weight = sum(weights)
            return sum(s * w for s, w in zip(scores, weights)) / total_weight
        return sum(scores) / len(scores)

    @staticmethod
    def adjust_for_conflict(score: float, conflicting_count: int) -> float:
        if conflicting_count == 0:
            return score
        penalty = min(0.3, conflicting_count * 0.1)
        return max(0.0, score - penalty)

    @staticmethod
    def score_to_level(score: float) -> ConfidenceLevel:
        return ConfidenceScorer.from_score(score)

    @staticmethod
    def level_to_score(level: ConfidenceLevel) -> float:
        return CONFIDENCE_THRESHOLDS.get(level, 0.0)
