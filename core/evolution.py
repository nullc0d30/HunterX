# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .utils import logger


@dataclass
class PayloadScore:
    payload_hash: str
    payload: str
    category: str
    success_rate: float = 0.0
    detection_rate: float = 0.0
    latency: float = 0.0
    noise: float = 0.0
    waf_reaction: float = 0.0
    confidence: float = 0.0
    overall_score: float = 0.0
    attempts: int = 0
    successes: int = 0
    last_used: Optional[datetime] = None
    mutations: List[Dict[str, Any]] = field(default_factory=list)

    def update(
        self,
        success: bool,
        detected: bool = False,
        latency_ms: float = 0.0,
        blocked: bool = False,
    ):
        self.attempts += 1
        if success:
            self.successes += 1
        self.success_rate = self.successes / max(1, self.attempts)
        self.detection_rate = (self.detection_rate * (self.attempts - 1) + (1.0 if detected else 0.0)) / max(1, self.attempts)
        self.latency = (self.latency * (self.attempts - 1) + latency_ms) / max(1, self.attempts)
        if blocked:
            self.waf_reaction = min(1.0, self.waf_reaction + 0.1)
        self.last_used = datetime.now(timezone.utc)
        self._compute_overall()

    def _compute_overall(self):
        self.overall_score = (
            self.success_rate * 0.35
            + (1.0 - self.detection_rate) * 0.25
            + (1.0 - min(1.0, self.latency / 10000.0)) * 0.10
            + (1.0 - self.noise) * 0.10
            + (1.0 - self.waf_reaction) * 0.10
            + self.confidence * 0.10
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_hash": self.payload_hash,
            "payload": self.payload[:100] if len(self.payload) > 100 else self.payload,
            "category": self.category,
            "success_rate": round(self.success_rate, 3),
            "detection_rate": round(self.detection_rate, 3),
            "latency": round(self.latency, 1),
            "noise": round(self.noise, 3),
            "waf_reaction": round(self.waf_reaction, 3),
            "confidence": round(self.confidence, 3),
            "overall_score": round(self.overall_score, 3),
            "attempts": self.attempts,
            "successes": self.successes,
            "last_used": self.last_used.isoformat() if self.last_used else None,
        }


MutationFunction = Callable[[str], List[str]]
MUTATION_REGISTRY: Dict[str, List[MutationFunction]] = {}


def register_mutation(technique: str):
    def decorator(func: MutationFunction):
        if technique not in MUTATION_REGISTRY:
            MUTATION_REGISTRY[technique] = []
        MUTATION_REGISTRY[technique].append(func)
        return func
    return decorator


@register_mutation("case")
def mutate_case(payload: str) -> List[str]:
    variants = []
    if len(payload) > 3:
        variants.append(payload.swapcase())
        variants.append(payload.capitalize())
        variants.append(payload.upper() if payload.islower() else payload.lower())
    return variants


@register_mutation("encoding")
def mutate_encoding(payload: str) -> List[str]:
    variants = []
    url_enc_map = {"<": "%3C", ">": "%3E", "'": "%27", '"': "%22", "(": "%28", ")": "%29", " ": "%20"}
    encoded = ""
    for ch in payload:
        encoded += url_enc_map.get(ch, ch)
    if encoded != payload:
        variants.append(encoded)

    double_encoded = ""
    for ch in payload:
        double_encoded += url_enc_map.get(ch, "%25" + hex(ord(ch))[2:].upper().zfill(2))
    if double_encoded != payload:
        variants.append(double_encoded)

    return variants


@register_mutation("whitespace")
def mutate_whitespace(payload: str) -> List[str]:
    variants = []
    if " " in payload:
        variants.append(payload.replace(" ", "\t"))
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "%09"))
    return variants


@register_mutation("comment")
def mutate_comment_injection(payload: str) -> List[str]:
    variants = []
    if len(payload) > 5:
        variants.append(f"/**/{payload}")
        variants.append(f"{payload}/*!*/")
        for i in range(min(3, len(payload) // 2)):
            pos = i * 2
            variants.append(payload[:pos] + "/**/" + payload[pos:])
    return variants


@register_mutation("null_byte")
def mutate_null_byte(payload: str) -> List[str]:
    variants = []
    variants.append(payload + "%00")
    if "." in payload:
        variants.append(payload.replace(".", "%00."))
    return variants


@register_mutation("unicode")
def mutate_unicode(payload: str) -> List[str]:
    variants = []
    if "<" in payload:
        variants.append(payload.replace("<", "%u003C"))
    if ">" in payload:
        variants.append(payload.replace(">", "%u003E"))
    if "'" in payload:
        variants.append(payload.replace("'", "%u0027"))
    return variants


class PayloadEvolutionEngine:
    def __init__(self, max_mutations_per_payload: int = 10):
        self.max_mutations = max_mutations_per_payload
        self.history: Dict[str, PayloadScore] = {}
        self.mutation_registry = MUTATION_REGISTRY

    def register_mutation_technique(self, technique: str, func: MutationFunction) -> None:
        if technique not in self.mutation_registry:
            self.mutation_registry[technique] = []
        self.mutation_registry[technique].append(func)

    def evolve(
        self,
        payload: str,
        category: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        seen = set()

        for technique, funcs in self.mutation_registry.items():
            for func in funcs:
                try:
                    variants = func(payload)
                    for variant in variants:
                        if variant and variant not in seen and variant != payload:
                            seen.add(variant)
                            candidates.append({
                                "payload": variant,
                                "technique": technique,
                                "parent": payload,
                                "category": category,
                            })
                except Exception as e:
                    logger.debug(f"Mutation '{technique}' failed: {e}")

        if context:
            if context.get("waf_detected"):
                waf_evasions = self._generate_waf_evasion(payload)
                for variant in waf_evasions:
                    if variant not in seen:
                        seen.add(variant)
                        candidates.append({
                            "payload": variant,
                            "technique": "waf_evasion",
                            "parent": payload,
                            "category": category,
                        })

        random.shuffle(candidates)
        candidates = candidates[:self.max_mutations]

        payload_hash = self._hash(payload)
        if payload_hash in self.history:
            score = self.history[payload_hash]
            score.mutations = [c["technique"] for c in candidates]

        logger.info(f"EvolutionEngine: generated {len(candidates)} mutations for {category} payload")
        return candidates

    def record_result(
        self,
        original_payload: str,
        mutated_payload: str,
        category: str,
        success: bool,
        detected: bool = False,
        latency_ms: float = 0.0,
        blocked: bool = False,
        confidence: float = 0.0,
    ) -> None:
        payload_hash = self._hash(original_payload)

        if payload_hash not in self.history:
            self.history[payload_hash] = PayloadScore(
                payload_hash=payload_hash,
                payload=original_payload,
                category=category,
                confidence=confidence,
            )

        self.history[payload_hash].update(success, detected, latency_ms, blocked)

        mutated_hash = self._hash(mutated_payload)
        if mutated_hash not in self.history:
            self.history[mutated_hash] = PayloadScore(
                payload_hash=mutated_hash,
                payload=mutated_payload,
                category=category,
                confidence=confidence * 0.8,
            )
        self.history[mutated_hash].update(success, detected, latency_ms, blocked)

    def rank_payloads(
        self,
        payloads: List[Dict[str, Any]],
        top_n: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        scored: List[Tuple[float, Dict[str, Any]]] = []
        for p in payloads:
            ph = self._hash(p.get("payload", ""))
            if ph in self.history:
                score = self.history[ph]
                overall = score.overall_score
            else:
                overall = 0.5

            scored.append((overall, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        result = [p for _, p in scored]
        if top_n:
            result = result[:top_n]

        return result

    def get_best_payload(
        self, category: str, min_attempts: int = 1
    ) -> Optional[PayloadScore]:
        best = None
        best_score = -1.0
        for score in self.history.values():
            if score.category == category and score.attempts >= min_attempts:
                if score.overall_score > best_score:
                    best_score = score.overall_score
                    best = score
        return best

    def get_evolution_summary(self) -> Dict[str, Any]:
        categories: Dict[str, int] = {}
        total = len(self.history)
        for score in self.history.values():
            cat = score.category
            if cat not in categories:
                categories[cat] = 0
            categories[cat] += 1

        avg_scores = {
            "avg_success_rate": 0.0,
            "avg_detection_rate": 0.0,
            "avg_overall_score": 0.0,
        }
        if total > 0:
            avg_scores["avg_success_rate"] = sum(s.success_rate for s in self.history.values()) / total
            avg_scores["avg_detection_rate"] = sum(s.detection_rate for s in self.history.values()) / total
            avg_scores["avg_overall_score"] = sum(s.overall_score for s in self.history.values()) / total

        return {
            "total_payloads_tracked": total,
            "categories": categories,
            "averages": avg_scores,
            "mutations_generated": sum(len(s.mutations) for s in self.history.values()),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "history": [s.to_dict() for s in sorted(
                self.history.values(),
                key=lambda x: x.overall_score,
                reverse=True,
            )[:1000]],
            "summary": self.get_evolution_summary(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def _generate_waf_evasion(self, payload: str) -> List[str]:
        variants = []
        if len(payload) > 10:
            mid = len(payload) // 2
            variants.append(payload[:mid] + "\n" + payload[mid:])
            variants.append(payload[:mid] + "\r\n" + payload[mid:])
            variants.append("=".join(payload.split("=", 1)) if "=" in payload else payload)
        return variants

    @staticmethod
    def _hash(payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]
