# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..intelligence.knowledge_graph import KnowledgeGraph, NodeType
from ..intelligence.threat_model import ThreatModel
from ...core.planner import Planner, ScanPlan
from ...core.risk_engine import RiskEngine
from .payload_search import PayloadSearchEngine
from .payload_ranking import PayloadRankingEngine
from .payload_policy import PayloadExecutionPolicy, PolicyLevel


class PayloadContextEngine:
    def __init__(
        self,
        search_engine: Optional[PayloadSearchEngine] = None,
        ranking_engine: Optional[PayloadRankingEngine] = None,
        policy: Optional[PayloadExecutionPolicy] = None,
        risk_engine: Optional[RiskEngine] = None,
        planner: Optional[Planner] = None,
    ):
        self.search = search_engine or PayloadSearchEngine()
        self.ranking = ranking_engine or PayloadRankingEngine()
        self.policy = policy or PayloadExecutionPolicy()
        self.risk_engine = risk_engine
        self.planner = planner

    def recommend(
        self,
        target_url: str,
        knowledge_graph: Optional[KnowledgeGraph] = None,
        threat_model: Optional[ThreatModel] = None,
        scan_plan: Optional[ScanPlan] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        technologies: Optional[List[str]] = None,
        frameworks: Optional[List[str]] = None,
        languages: Optional[List[str]] = None,
        category: Optional[str] = None,
        limit: int = 20,
        policy_level: Optional[PolicyLevel] = None,
    ) -> Dict[str, Any]:
        context_techs: List[str] = []
        context_frameworks: List[str] = []
        context_languages: List[str] = []
        context_os: List[str] = []
        waf_detected = False

        if knowledge_graph:
            for node in knowledge_graph.nodes.values():
                if node.node_type == NodeType.TECHNOLOGY:
                    context_techs.append(node.label)
                elif node.node_type == NodeType.FRAMEWORK:
                    context_frameworks.append(node.label)
                elif node.node_type == NodeType.LANGUAGE:
                    context_languages.append(node.label)
                elif node.node_type == NodeType.WAF:
                    waf_detected = True

        if technologies:
            context_techs.extend(technologies)
        if frameworks:
            context_frameworks.extend(frameworks)
        if languages:
            context_languages.extend(languages)

        if headers:
            server = headers.get("Server", "")
            if "nginx" in server.lower():
                context_techs.append("Nginx")
            elif "apache" in server.lower():
                context_techs.append("Apache")
            elif "iis" in server.lower():
                context_techs.append("IIS")

            x_powered = headers.get("X-Powered-By", "")
            if "php" in x_powered.lower():
                context_languages.append("PHP")
            elif "asp.net" in x_powered.lower():
                context_frameworks.append("ASP.NET")

            if "cloudflare" in str(headers).lower():
                context_techs.append("Cloudflare")
                waf_detected = True

        if threat_model:
            for asset in threat_model.assets.values():
                context_techs.extend(asset.technologies)
                context_frameworks.extend(
                    t for t in asset.technologies if t.lower() in [
                        "laravel", "django", "flask", "spring", "rails", "wordpress",
                    ]
                )

        queries: List[str] = []
        if category:
            queries.append(f"{category} exploit")

        for tech in context_techs[:3]:
            if category:
                queries.append(f"{tech} {category}")
            else:
                queries.append(f"{tech} exploit")

        for fw in context_frameworks[:2]:
            if category:
                queries.append(f"{fw} {category}")
            else:
                queries.append(f"{fw} exploit")

        if waf_detected:
            if category:
                queries.append(f"cloudflare {category} bypass")
            else:
                queries.append("waf bypass")

        if not queries:
            queries.append(category.lower() if category else "exploit")

        all_payloads: List[Dict[str, Any]] = []
        seen_hashes: set = set()

        for query in queries:
            results = self.search.search(query, limit=limit // len(queries) + 1)
            for r in results:
                ph = r.payload.payload_hash
                if ph not in seen_hashes:
                    seen_hashes.add(ph)
                    all_payloads.append({
                        "payload": r.payload.payload_text.split("\n")[0] if r.payload.payload_text else "",
                        "category": r.payload.category,
                        "source": r.payload.file_path,
                        "metadata": {
                            "technology": r.payload.technology,
                            "framework": r.payload.framework,
                            "language": r.payload.language,
                            "tags": r.payload.tags,
                        },
                        "search_score": r.score,
                    })

        ranked = self.ranking.rank(
            payloads=all_payloads,
            target_technologies=context_techs,
            target_frameworks=context_frameworks,
            target_languages=context_languages,
            policy_level=policy_level,
            knowledge_graph=knowledge_graph,
        )

        return {
            "target_url": target_url,
            "context": {
                "technologies": list(set(context_techs)),
                "frameworks": list(set(context_frameworks)),
                "languages": list(set(context_languages)),
                "waf_detected": waf_detected,
                "os": list(set(context_os)),
            },
            "recommendations": ranked[:limit],
            "total_candidates": len(all_payloads),
            "total_recommended": min(len(ranked), limit),
            "queries_used": queries,
        }
