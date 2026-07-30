from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .confidence import ConfidenceLevel, ConfidenceScorer


class ConsensusMethod(str, Enum):
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_VOTE = "weighted_vote"
    CONFIDENCE_AGGREGATION = "confidence_aggregation"
    DELPHI = "delphi"


@dataclass
class IndividualResponse:
    provider: str
    model: str
    content: str
    confidence: float
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "content": self.content[:500],
            "confidence": self.confidence,
            "latency_ms": self.latency_ms,
        }


@dataclass
class ConsensusResult:
    method: ConsensusMethod
    final_response: str
    agreement: float
    agreement_level: ConfidenceLevel
    responses: List[IndividualResponse] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    alternative_hypotheses: List[str] = field(default_factory=list)
    provider_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method.value,
            "final_response": self.final_response,
            "agreement": self.agreement,
            "agreement_level": self.agreement_level.value,
            "responses": [r.to_dict() for r in self.responses],
            "conflicts": self.conflicts,
            "alternative_hypotheses": self.alternative_hypotheses,
            "provider_count": self.provider_count,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ConsensusEngine:
    def __init__(self, confidence_scorer: Optional[ConfidenceScorer] = None):
        self._confidence = confidence_scorer or ConfidenceScorer()

    def reach_consensus(
        self,
        responses: List[IndividualResponse],
        method: ConsensusMethod = ConsensusMethod.CONFIDENCE_AGGREGATION,
    ) -> ConsensusResult:
        if not responses:
            return ConsensusResult(
                method=method,
                final_response="",
                agreement=0.0,
                agreement_level=ConfidenceLevel.INSUFFICIENT_DATA,
                responses=[],
                provider_count=0,
            )

        if len(responses) == 1:
            return ConsensusResult(
                method=method,
                final_response=responses[0].content,
                agreement=responses[0].confidence,
                agreement_level=self._confidence.score_to_level(responses[0].confidence),
                responses=responses,
                provider_count=1,
            )

        if method == ConsensusMethod.MAJORITY_VOTE:
            return self._majority_vote(responses)
        elif method == ConsensusMethod.WEIGHTED_VOTE:
            return self._weighted_vote(responses)
        else:
            return self._confidence_aggregation(responses)

    def _majority_vote(self, responses: List[IndividualResponse]) -> ConsensusResult:
        contents: Dict[str, List[IndividualResponse]] = {}
        for r in responses:
            key = r.content[:200]
            if key not in contents:
                contents[key] = []
            contents[key].append(r)

        max_count = max(len(v) for v in contents.values())
        winners = [k for k, v in contents.items() if len(v) == max_count]
        final = winners[0] if winners else responses[0].content

        conflicts = []
        if len(winners) > 1:
            conflicts.append(f"Tie between {len(winners)} options")

        for key, group in contents.items():
            if key != final:
                conflicts.append(f"Alternative: {key[:100]}... ({len(group)} votes)")

        return ConsensusResult(
            method=ConsensusMethod.MAJORITY_VOTE,
            final_response=final,
            agreement=max_count / len(responses) if responses else 0,
            agreement_level=self._confidence.score_to_level(max_count / len(responses)),
            responses=responses,
            conflicts=conflicts,
            alternative_hypotheses=[k[:200] for k in contents.keys() if k != final],
            provider_count=len(responses),
        )

    def _weighted_vote(self, responses: List[IndividualResponse]) -> ConsensusResult:
        if not responses:
            return ConsensusResult(
                method=ConsensusMethod.WEIGHTED_VOTE,
                final_response="", agreement=0.0,
                agreement_level=ConfidenceLevel.INSUFFICIENT_DATA,
                provider_count=0,
            )

        weighted = sorted(responses, key=lambda r: r.confidence, reverse=True)
        best = weighted[0]

        total_weight = sum(r.confidence for r in responses)
        agreement = best.confidence / total_weight if total_weight > 0 else 0

        return ConsensusResult(
            method=ConsensusMethod.WEIGHTED_VOTE,
            final_response=best.content,
            agreement=agreement,
            agreement_level=self._confidence.score_to_level(agreement),
            responses=responses,
            provider_count=len(responses),
        )

    def _confidence_aggregation(self, responses: List[IndividualResponse]) -> ConsensusResult:
        if not responses:
            return ConsensusResult(
                method=ConsensusMethod.CONFIDENCE_AGGREGATION,
                final_response="", agreement=0.0,
                agreement_level=ConfidenceLevel.INSUFFICIENT_DATA,
                provider_count=0,
            )

        scores = [r.confidence for r in responses]
        avg_confidence = ConfidenceScorer.aggregate(scores, method="mean")
        weighted = sorted(responses, key=lambda r: r.confidence, reverse=True)
        best = weighted[0]

        conflicts = []
        alternatives = []

        if len(weighted) > 1:
            for r in weighted[1:]:
                if abs(r.confidence - best.confidence) < 0.1:
                    conflicts.append(f"Similar confidence: {r.provider} ({r.confidence:.2f})")
                    alternatives.append(r.content[:200])

        return ConsensusResult(
            method=ConsensusMethod.CONFIDENCE_AGGREGATION,
            final_response=best.content,
            agreement=avg_confidence,
            agreement_level=self._confidence.score_to_level(avg_confidence),
            responses=responses,
            conflicts=conflicts,
            alternative_hypotheses=alternatives,
            provider_count=len(responses),
        )

    def detect_conflicts(self, responses: List[IndividualResponse]) -> List[str]:
        conflicts: List[str] = []
        if len(responses) < 2:
            return conflicts
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                r1, r2 = responses[i], responses[j]
                if abs(r1.confidence - r2.confidence) > 0.3:
                    conflicts.append(f"Confidence mismatch: {r1.provider} ({r1.confidence:.2f}) vs {r2.provider} ({r2.confidence:.2f})")
        return conflicts
