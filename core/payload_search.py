# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .payload_index import PayloadIndexer, IndexedPayload
from .payload_metadata import PayloadMetadataEngine
from .utils import logger


@dataclass
class SearchResult:
    payload: IndexedPayload
    score: float = 0.0
    match_type: str = "fts"
    match_highlights: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "match_type": self.match_type,
            "highlights": self.match_highlights,
            "payload": self.payload.to_dict(),
        }


@dataclass
class SearchQuery:
    raw: str
    technology: Optional[str] = None
    framework: Optional[str] = None
    language: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    min_danger: float = 0.0
    max_danger: float = 1.0
    min_noise: float = 0.0
    max_noise: float = 1.0
    os_target: Optional[str] = None
    context: Optional[str] = None
    sort_by: str = "relevance"
    limit: int = 20
    offset: int = 0


TECHNOLOGY_ALIASES: Dict[str, List[str]] = {
    "laravel": ["laravel", "php", "blade"],
    "django": ["django", "python", "jinja"],
    "flask": ["flask", "python", "jinja2", "werkzeug"],
    "spring": ["spring", "java", "spring boot", "spring mvc"],
    "express": ["express", "node.js", "node", "javascript"],
    "rails": ["rails", "ruby", "ruby on rails"],
    "wordpress": ["wordpress", "wp", "php"],
    "nextjs": ["next.js", "nextjs", "react", "javascript"],
    "react": ["react", "react.js", "javascript"],
    "angular": ["angular", "angular.js", "typescript"],
    "vue": ["vue.js", "vuejs", "javascript"],
    "fastapi": ["fastapi", "python", "starlette"],
    "graphql": ["graphql", "apollo", "relay"],
    "jwt": ["jwt", "json web token", "auth"],
    "cloudflare": ["cloudflare", "waf", "cdn"],
    "nginx": ["nginx", "nginx"],
    "apache": ["apache", "apache httpd"],
    "tomcat": ["tomcat", "apache tomcat", "java"],
    "iis": ["iis", "asp.net", "windows"],
}

SEARCH_INTENTS: Dict[str, Dict[str, Any]] = {
    "laravel sql injection": {"framework": "Laravel", "category": "SQLI"},
    "spring ssti": {"framework": "Spring", "category": "SSTI"},
    "cloudflare bypass": {"technology": "Cloudflare", "category": "WAF_BYPASS"},
    "jwt none": {"technology": "JWT", "category": "JWT"},
    "fastapi ssrf": {"framework": "FastAPI", "category": "SSRF"},
    "nodejs prototype pollution": {"language": "Node.js", "category": "PROTOTYPE_POLLUTION"},
    "graphql batching": {"technology": "GraphQL", "tags": ["batching", "dos"]},
    "express rce": {"framework": "Express", "category": "RCE"},
    "django debug": {"framework": "Django", "tags": ["debug", "info_leak"]},
    "wordpress lfi": {"framework": "WordPress", "category": "LFI"},
    "asp.net viewstate": {"technology": "ASP.NET", "tags": ["viewstate", "deserialization"]},
    "php filter chain": {"technology": "PHP", "category": "LFI", "tags": ["php_filter", "chain"]},
    "spring boot actuator": {"framework": "Spring", "tags": ["actuator", "info_leak"]},
    "mongodb injection": {"technology": "MongoDB", "category": "NOSQLI"},
}


class PayloadSearchEngine:
    def __init__(self, indexer: Optional[PayloadIndexer] = None):
        self.indexer = indexer or PayloadIndexer()
        self.metadata_engine = PayloadMetadataEngine()
        self._search_intents = SEARCH_INTENTS
        self._technology_aliases = TECHNOLOGY_ALIASES

    def search(self, query: str, **kwargs) -> List[SearchResult]:
        parsed = self._parse_query(query, **kwargs)
        results = self._execute_search(parsed)
        results = self._rank_results(results, parsed)
        logger.info(f"PayloadSearch: '{query}' found {len(results)} results")
        return results[:parsed.limit]

    def _parse_query(self, query: str, **kwargs) -> SearchQuery:
        sq = SearchQuery(raw=query)

        query_lower = query.lower().strip()

        for intent_str, intent_data in self._search_intents.items():
            if query_lower == intent_str or query_lower.startswith(intent_str):
                if "technology" in intent_data:
                    sq.technology = intent_data["technology"]
                if "framework" in intent_data:
                    sq.framework = intent_data["framework"]
                if "category" in intent_data:
                    sq.category = intent_data["category"]
                if "tags" in intent_data:
                    sq.tags.extend(intent_data["tags"])
                break

        if not sq.technology and not sq.framework and not sq.category:
            for alias, expansions in self._technology_aliases.items():
                if alias in query_lower:
                    if not sq.technology:
                        sq.technology = expansions[0].title()
                    break

        cat_map = {
            "sqli": "SQLI", "sql": "SQLI", "lfi": "LFI", "rce": "RCE",
            "xss": "XSS", "ssti": "SSTI", "ssrf": "SSRF", "xxe": "XXE",
            "redirect": "OPEN_REDIRECT", "crlf": "CRLF", "bypass": "WAF_BYPASS",
            "upload": "FILE_UPLOAD", "idor": "IDOR", "csrf": "CSRF",
            "prototype pollution": "PROTOTYPE_POLLUTION",
            "nosql": "NOSQLI", "ldap": "LDAP_INJECTION",
        }
        for keyword, category in cat_map.items():
            if keyword in query_lower and not sq.category:
                sq.category = category
                break

        sq.limit = kwargs.get("limit", 20)
        sq.offset = kwargs.get("offset", 0)
        if kwargs.get("category"):
            sq.category = kwargs["category"]
        if kwargs.get("technology"):
            sq.technology = kwargs["technology"]
        if kwargs.get("framework"):
            sq.framework = kwargs["framework"]

        return sq

    def _execute_search(self, sq: SearchQuery) -> List[SearchResult]:
        fts_query = self._build_smart_query(sq)
        results = []

        try:
            payloads = self.indexer.search(
                query=fts_query,
                limit=sq.limit * 2,
                offset=sq.offset,
                category_filter=sq.category,
            )
            for p in payloads:
                results.append(SearchResult(
                    payload=p,
                    score=0.5,
                    match_type="fts",
                ))
        except Exception as e:
            logger.debug(f"PayloadSearch: FTS failed ({e})")

        return results

    def _build_smart_query(self, sq: SearchQuery) -> str:
        parts = [sq.raw]

        if sq.technology:
            parts.append(f'"{sq.technology}"')
        if sq.framework:
            parts.append(f'"{sq.framework}"')
        if sq.category:
            parts.append(f'"{sq.category}"')
        if sq.tags:
            for tag in sq.tags:
                parts.append(f'"{tag}"')

        return " ".join(parts)

    def _rank_results(self, results: List[SearchResult], sq: SearchQuery) -> List[SearchResult]:
        for result in results:
            score = 0.0
            p = result.payload

            if sq.technology and sq.technology.lower() in [t.lower() for t in p.technology]:
                score += 3.0

            if sq.framework and sq.framework.lower() in [f.lower() for f in p.framework]:
                score += 3.0

            if sq.category and p.category.upper() == sq.category.upper():
                score += 2.0

            technology_match = sum(1 for t in p.technology if t.lower() in sq.raw.lower())
            score += technology_match * 0.5

            framework_match = sum(1 for f in p.framework if f.lower() in sq.raw.lower())
            score += framework_match * 0.5

            if sq.tags:
                tag_match = sum(1 for t in sq.tags if t.lower() in [x.lower() for x in p.tags])
                score += tag_match

            for term in sq.raw.lower().split():
                if term in p.filename.lower():
                    score += 0.3
                if term in p.payload_text.lower():
                    score += 0.1

            result.score = score

        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def suggest(self, partial: str, limit: int = 5) -> List[str]:
        suggestions = set()

        for intent_str in self._search_intents:
            if partial.lower() in intent_str.lower():
                suggestions.add(intent_str)

        for alias in self._technology_aliases:
            if partial.lower() in alias.lower():
                suggestions.add(f"{alias} exploit")
                suggestions.add(f"{alias} vulnerability")

        prefixes = {
            "la": "laravel", "sp": "spring", "cl": "cloudflare", "no": "nodejs",
            "ex": "express", "dj": "django", "fl": "flask", "wo": "wordpress",
            "gr": "graphql", "jw": "jwt", "ng": "nginx", "ap": "apache",
            "to": "tomcat", "as": "asp.net", "py": "python", "ph": "php",
        }
        for prefix, suggestion in prefixes.items():
            if partial.lower().startswith(prefix):
                suggestions.add(f"{suggestion} exploit")
                suggestions.add(f"{suggestion} vulnerability")

        return sorted(suggestions)[:limit]

    def get_popular_searches(self, limit: int = 10) -> List[str]:
        popular = [
            "laravel sql injection", "spring ssti", "cloudflare bypass",
            "jwt none", "fastapi ssrf", "nodejs prototype pollution",
            "graphql batching", "wordpress lfi", "express rce",
            "django debug", "php filter chain", "spring boot actuator",
            "asp.net viewstate", "mongodb injection", "nosql injection",
        ]
        return popular[:limit]
