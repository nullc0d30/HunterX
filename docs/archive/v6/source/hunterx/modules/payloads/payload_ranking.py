# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..intelligence.knowledge_graph import KnowledgeGraph, NodeType
from ..intelligence.adaptive_memory import AdaptiveMemory
from .payload_policy import PayloadExecutionPolicy, PolicyLevel


class PayloadRankingEngine:
    def __init__(
        self,
        adaptive_memory: Optional[AdaptiveMemory] = None,
        policy: Optional[PayloadExecutionPolicy] = None,
    ):
        self.memory = adaptive_memory
        self.policy = policy or PayloadExecutionPolicy()

    def rank(
        self,
        payloads: List[Dict[str, Any]],
        target_technologies: Optional[List[str]] = None,
        target_frameworks: Optional[List[str]] = None,
        target_languages: Optional[List[str]] = None,
        policy_level: Optional[PolicyLevel] = None,
        knowledge_graph: Optional[KnowledgeGraph] = None,
        top_n: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if not payloads:
            return []

        target_techs = [t.lower() for t in (target_technologies or [])]
        target_fws = [f.lower() for f in (target_frameworks or [])]
        target_langs = [lang.lower() for lang in (target_languages or [])]

        scored: List[Tuple[float, Dict[str, Any]]] = []

        for payload in payloads:
            score = 0.0
            metadata = payload.get("metadata", {})
            p_techs = [t.lower() for t in metadata.get("technology", [])]
            p_fws = [f.lower() for f in metadata.get("framework", [])]
            p_langs = [lang.lower() for lang in metadata.get("language", [])]
            p_cat = payload.get("category", "").lower()

            # Technology match (highest weight)
            tech_overlap = len(set(target_techs) & set(p_techs))
            score += tech_overlap * 3.0

            # Framework match
            fw_overlap = len(set(target_fws) & set(p_fws))
            score += fw_overlap * 3.0

            # Language match
            lang_overlap = len(set(target_langs) & set(p_langs))
            score += lang_overlap * 2.0

            # Search score bonus
            search_score = payload.get("search_score", 0)
            score += search_score

            if knowledge_graph:
                finding_nodes = knowledge_graph.get_nodes_by_type(NodeType.FINDING)
                for node in finding_nodes:
                    if p_cat in node.label.lower():
                        score += 1.0
                        break

            if self.memory:
                blocked = self.memory.is_blocked(
                    payload.get("payload", ""),
                    payload.get("category", ""),
                )
                if blocked:
                    score -= 5.0

                success_entries = self.memory.get_successful_payloads(category=payload.get("category", ""))
                if success_entries:
                    score += min(2.0, len(success_entries) * 0.2)

            if policy_level:
                policy_score = self.policy.score_payload(
                    payload.get("payload", ""),
                    payload.get("category", ""),
                    policy_level,
                )
                score += policy_score

            # Normalize: lower noise is better
            noise = payload.get("metadata", {}).get("noise_level", 0.5)
            score += (1.0 - noise) * 0.5

            scored.append((score, payload))

        scored.sort(key=lambda x: x[0], reverse=True)

        result = [p for _, p in scored]
        if top_n:
            result = result[:top_n]

        return result

    def rank_by_context(
        self,
        payloads: List[Dict[str, Any]],
        context: Dict[str, Any],
        top_n: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        techs = context.get("technologies", [])
        fws = context.get("frameworks", [])
        langs = context.get("languages", [])
        return self.rank(
            payloads=payloads,
            target_technologies=techs,
            target_frameworks=fws,
            target_languages=langs,
            top_n=top_n,
        )

    def filter_by_policy(
        self,
        payloads: List[Dict[str, Any]],
        policy_level: PolicyLevel = PolicyLevel.SAFE,
    ) -> List[Dict[str, Any]]:
        return [p for p in payloads if self.policy.allows(p.get("payload", ""), p.get("category", ""), policy_level)]
