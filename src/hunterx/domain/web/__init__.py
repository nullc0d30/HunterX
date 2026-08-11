# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web crawling domain models and helpers.

Canonical contracts for the web crawling & web attack-surface discovery
capability: URL observations, redirects, API/WebSocket/GraphQL endpoints,
authentication boundaries, crawl evidence, run batches, scope/policy/strategy
and deterministic parsers. Pure domain — no I/O.
"""

from __future__ import annotations

from hunterx.domain.web.confidence import WebConfidenceEngine
from hunterx.domain.web.correlator import WebCorrelator, WebCrawlCorrelation
from hunterx.domain.web.history import (
    WebCrawlChange,
    WebCrawlDiff,
    WebCrawlHistory,
)
from hunterx.domain.web.models import (
    APIEndpoint,
    AuthenticationBoundary,
    CrawlEvidence,
    CrawlExecutionSummary,
    CrawlPayload,
    CrawlTarget,
    GraphQLEndpoint,
    HTTPMethod,
    Redirect,
    URLObservation,
    WebCrawlBatch,
    WebCrawlMode,
    WebSocketEndpoint,
    observations_from_payload,
)
from hunterx.domain.web.policy import CrawlPolicy
from hunterx.domain.web.scope import (
    WebScopeDecision,
    WebScopeEnforcer,
    WebScopePolicy,
)
from hunterx.domain.web.strategy import (
    WEB_TOOL_IDS,
    CrawlStrategy,
    CrawlStrategyBuilder,
)
from hunterx.domain.web.urls import (
    ParsedURL,
    URLNormalizer,
    query_to_pairs,
)

__all__ = [
    "APIEndpoint",
    "AuthenticationBoundary",
    "CrawlEvidence",
    "CrawlExecutionSummary",
    "CrawlPayload",
    "CrawlPolicy",
    "CrawlStrategy",
    "CrawlStrategyBuilder",
    "CrawlTarget",
    "GraphQLEndpoint",
    "HTTPMethod",
    "ParsedURL",
    "Redirect",
    "URLObservation",
    "URLNormalizer",
    "WEB_TOOL_IDS",
    "WebCrawlBatch",
    "WebCrawlChange",
    "WebCrawlCorrelation",
    "WebCrawlDiff",
    "WebCrawlHistory",
    "WebCrawlMode",
    "WebConfidenceEngine",
    "WebCorrelator",
    "WebScopeDecision",
    "WebScopeEnforcer",
    "WebScopePolicy",
    "WebSocketEndpoint",
    "observations_from_payload",
    "query_to_pairs",
]
