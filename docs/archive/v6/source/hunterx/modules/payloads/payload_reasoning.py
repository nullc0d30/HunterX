# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .payload_context import PayloadContextEngine
from .payload_index import IndexedPayload, PayloadIndexer
from .payload_policy import PayloadExecutionPolicy, PolicyLevel
from .payload_ranking import PayloadRankingEngine


@dataclass
class ReasoningExplanation:
    reason: str
    confidence: float = 1.0
    contributing_factors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reason": self.reason,
            "confidence": round(self.confidence, 3),
            "contributing_factors": self.contributing_factors,
            "warnings": self.warnings,
            "alternatives": self.alternatives,
        }


@dataclass
class ReasoningResult:
    payload: IndexedPayload
    score: float = 0.0
    explanation: Optional[ReasoningExplanation] = None
    category: str = ""
    technique: str = "original"
    mutation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload.row_id,
            "payload": self.payload.payload_text[:200],
            "category": self.category or self.payload.category,
            "score": round(self.score, 3),
            "explanation": self.explanation.to_dict() if self.explanation else None,
            "technique": self.technique,
        }


class PayloadReasoning:
    def __init__(
        self,
        indexer: Optional[PayloadIndexer] = None,
        context_engine: Optional[PayloadContextEngine] = None,
        ranking_engine: Optional[PayloadRankingEngine] = None,
        policy: Optional[PayloadExecutionPolicy] = None,
    ):
        self.indexer = indexer or PayloadIndexer()
        self.context_engine = context_engine or PayloadContextEngine()
        self.ranking_engine = ranking_engine or PayloadRankingEngine()
        self.policy = policy or PayloadExecutionPolicy(PolicyLevel.BALANCED)

    def reason(
        self,
        target_info: Dict[str, Any],
        category: Optional[str] = None,
        top_n: int = 5,
    ) -> List[ReasoningResult]:
        context = self.context_engine.recommend(target_info)
        candidates: List[IndexedPayload] = []

        if category:
            candidates = self._get_candidates_by_category(category, context)
        else:
            candidates = self._get_candidates_from_context(context)

        if not candidates:
            return []

        ranked = self.ranking_engine.rank(candidates, target_info)
        scored: List[Tuple[float, IndexedPayload, ReasoningExplanation]] = []

        for payload in ranked[:top_n * 3]:
            explanation = self._explain_selection(payload, target_info, context)
            final_score = payload.row_id * 0  # placeholder
            scored.append((final_score, payload, explanation))

        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[ReasoningResult] = []
        for score, payload, exp in scored[:top_n]:
            results.append(ReasoningResult(
                payload=payload,
                score=score,
                explanation=exp,
                category=payload.category,
            ))

        return results

    def explain(
        self,
        payload: IndexedPayload,
        target_info: Dict[str, Any],
    ) -> ReasoningExplanation:
        context = self.context_engine.recommend(target_info)
        return self._explain_selection(payload, target_info, context)

    def _get_candidates_by_category(
        self,
        category: str,
        context: Dict[str, Any],
    ) -> List[IndexedPayload]:
        candidates: List[IndexedPayload] = []
        for alias in self._get_category_aliases(category):
            results = self.indexer.search(
                query=alias,
                limit=50,
                category_filter=alias,
            )
            candidates.extend(results)
        if not candidates:
            results = self.indexer.search(query=category, limit=50)
            candidates.extend(results)
        seen = set()
        unique = []
        for c in candidates:
            if c.payload_hash not in seen:
                seen.add(c.payload_hash)
                unique.append(c)
        return unique

    def _get_candidates_from_context(
        self,
        context: Dict[str, Any],
    ) -> List[IndexedPayload]:
        candidates: List[IndexedPayload] = []
        search_terms: List[str] = []

        techs = context.get("technologies", [])
        if isinstance(techs, list):
            search_terms.extend(techs[:3])

        frameworks = context.get("frameworks", [])
        if isinstance(frameworks, list):
            search_terms.extend(frameworks[:3])

        languages = context.get("languages", [])
        if isinstance(languages, list):
            search_terms.extend(languages[:2])

        threat_model = context.get("threat_model", {})
        if isinstance(threat_model, dict):
            techniques = threat_model.get("techniques", [])
            if isinstance(techniques, list):
                search_terms.extend(techniques[:3])

        for term in search_terms:
            results = self.indexer.search(query=term, limit=20)
            candidates.extend(results)

        seen = set()
        unique = []
        for c in candidates:
            if c.payload_hash not in seen:
                seen.add(c.payload_hash)
                unique.append(c)
        return unique

    def _explain_selection(
        self,
        payload: IndexedPayload,
        target_info: Dict[str, Any],
        context: Dict[str, Any],
    ) -> ReasoningExplanation:
        factors: List[str] = []
        warnings: List[str] = []
        alternatives: List[str] = []

        matches = self._match_context(payload, context)
        factors.extend(matches)

        tech = payload.technology or []
        fw = payload.framework or []
        lang = payload.language or []

        target_techs = context.get("technologies", [])
        if isinstance(target_techs, list):
            matched_tech = [t for t in tech if any(t.lower() in str(tt).lower() for tt in target_techs)]
            if matched_tech:
                factors.append(f"Technology match: {', '.join(matched_tech)}")

        matched_fw = [f for f in fw if any(f.lower() in str(ctx).lower() for ctx in context.get("frameworks", []))]
        if matched_fw:
            factors.append(f"Framework match: {', '.join(matched_fw)}")

        matched_lang = [lg for lg in lang if any(lg.lower() in str(ctx).lower() for ctx in context.get("languages", []))]
        if matched_lang:
            factors.append(f"Language match: {', '.join(matched_lang)}")

        cat = payload.category.upper()
        if cat in ("RCE", "COMMAND_INJECTION"):
            warnings.append("RCE payloads are high risk — ensure proper authorization")
        elif cat in ("SQLI", "SQL_INJECTION"):
            warnings.append("SQL injection may modify or destroy data")
        elif cat in ("XSS", "CROSS_SITE_SCRIPTING"):
            warnings.append("XSS payloads may trigger WAF alerts")

        if self._is_noisy(payload):
            warnings.append("This payload may generate excessive noise")

        confidence = self._estimate_confidence(payload, context)
        reason = self._build_reason(cat, tech, fw, lang, confidence)

        return ReasoningExplanation(
            reason=reason,
            confidence=confidence,
            contributing_factors=factors,
            warnings=warnings,
            alternatives=alternatives,
        )

    def _match_context(
        self,
        payload: IndexedPayload,
        context: Dict[str, Any],
    ) -> List[str]:
        factors = []
        threat_model = context.get("threat_model", {})
        if isinstance(threat_model, dict):
            techniques = threat_model.get("techniques", [])
            if isinstance(techniques, list):
                for technique in techniques:
                    if technique.lower() in payload.category.lower():
                        factors.append(f"Relevant to MITRE technique: {technique}")
        os_hints = context.get("os_hints", [])
        if isinstance(os_hints, list):
            for os_name in os_hints:
                if os_name.lower() in [o.lower() for o in (payload.os_targets or [])]:
                    factors.append(f"OS match: {os_name}")
        return factors

    def _is_noisy(self, payload: IndexedPayload) -> bool:
        text = payload.payload_text
        noise_indicators = ["sleep", "delay", "waitfor", "ping", "nslookup", "curl", "wget"]
        return any(indicator in text.lower() for indicator in noise_indicators)

    def _estimate_danger(self, payload_text: str, category: str) -> float:
        cat_upper = category.upper()
        base = {"RCE": 0.95, "CMDI": 0.9, "SQLI": 0.85, "SSTI": 0.8, "XXE": 0.75,
                 "LFI": 0.6, "XSS": 0.5, "SSRF": 0.7, "OPEN_REDIRECT": 0.3}.get(cat_upper, 0.5)
        destructive = ["drop", "delete", "truncate", "shutdown", "reboot"]
        if any(d in payload_text.lower() for d in destructive):
            base = min(1.0, base + 0.2)
        return base

    def _estimate_confidence(
        self,
        payload: IndexedPayload,
        context: Dict[str, Any],
    ) -> float:
        confidence = 0.5
        if payload.technology or payload.framework or payload.language:
            confidence += 0.15
        if payload.category:
            confidence += 0.1
        target_techs = context.get("technologies", [])
        if isinstance(target_techs, list) and payload.technology:
            if any(t.lower() in str(tt).lower() for t in payload.technology for tt in target_techs):
                confidence += 0.15
        text = payload.payload_text
        if len(text) > 10:
            confidence += 0.05
        return min(1.0, confidence)

    def _build_reason(
        self,
        category: str,
        technology: List[str],
        framework: List[str],
        language: List[str],
        confidence: float,
    ) -> str:
        parts = [f"Payload targets {category} vulnerability"]
        if technology:
            parts.append(f"tailored for {', '.join(technology[:3])}")
        if framework:
            parts.append(f"with {', '.join(framework[:2])} framework support")
        if language:
            parts.append(f"in {', '.join(language[:2])} context")
        parts.append(f"(confidence: {confidence:.0%})")
        return " ".join(parts)

    def _get_category_aliases(self, category: str) -> List[str]:
        aliases = {
            "SQLI": ["SQL Injection", "SQLi", "sql_injection"],
            "XSS": ["Cross Site Scripting", "cross_site_scripting"],
            "LFI": ["Local File Inclusion", "file_inclusion", "path_traversal"],
            "RCE": ["Remote Code Execution", "command_injection", "cmdi"],
            "SSTI": ["Server Side Template Injection", "template_injection"],
            "SSRF": ["Server Side Request Forgery"],
            "XXE": ["XML External Entity"],
            "CMDI": ["Command Injection", "command_injection", "rce"],
        }
        return aliases.get(category.upper(), [category])

    def reason_batch(
        self,
        payloads: List[IndexedPayload],
        target_info: Dict[str, Any],
    ) -> List[ReasoningResult]:
        if not payloads:
            return []
        context = self.context_engine.recommend(target_info)
        results: List[ReasoningResult] = []

        for payload in payloads[:50]:
            explanation = self._explain_selection(payload, target_info, context)
            results.append(ReasoningResult(
                payload=payload,
                score=0.0,
                explanation=explanation,
                category=payload.category,
            ))

        return sorted(results, key=lambda r: r.explanation.confidence if r.explanation else 0, reverse=True)
