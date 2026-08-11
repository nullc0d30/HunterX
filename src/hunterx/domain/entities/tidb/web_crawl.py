# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web crawling Target Intelligence Database entities.

System-of-record entities for the web crawling & web attack-surface discovery
capability: origins, URL observations, redirects, API/WebSocket/GraphQL
endpoints, authentication boundaries, crawl run records and crawl evidence.
They extend the existing web-layer entity set (:mod:`hunterx.domain.entities.tidb.web`)
with the crawl-specific projections the capability persists.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class WebOrigin(TidbEntity):
    """An HTTP(S) origin discovered within scope.

    Attributes:
        scheme: origin scheme (``https``).
        host: canonical lowercase host.
        port: effective port (``None`` when default).
        target_id: owning target record id.
        confidence: discovery confidence in ``[0, 1]``.
        is_upgrade_candidate: whether ``http`` appears upgradeable to ``https``.
        key: canonical origin key (``scheme://host[:port]``).

    """

    scheme: str = "https"
    host: str = ""
    port: int | None = None
    target_id: str | None = None
    confidence: float = 1.0
    is_upgrade_candidate: bool = False
    key: str = ""


@dataclass(slots=True)
class URLObservation(TidbEntity):
    """One normalized in-scope URL observation.

    Attributes:
        url: canonical absolute URL.
        method: observed HTTP method.
        origin_id: owning :class:`WebOrigin` record id.
        path: normalized path.
        query: canonicalized query string.
        status_code: last observed HTTP status.
        content_type: last observed response content type.
        source: upstream source (``crawl``, ``katana``, ``sitemap``...).
        tool_id: producing tool.
        confidence: confidence in ``[0, 1]``.
        target_id / target_key: owning target scope.
        correlation_id / mission_id / execution_id: run provenance.
        times_seen: how many runs observed this URL.
        key: canonical dedup key (``method url``).

    """

    url: str
    method: str = "GET"
    origin_id: str | None = None
    path: str = ""
    query: str = ""
    status_code: int | None = None
    content_type: str | None = None
    source: str = "crawl"
    tool_id: str = ""
    confidence: float = 1.0
    target_id: str | None = None
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    times_seen: int = 1
    key: str = ""


@dataclass(slots=True)
class WebRedirect(TidbEntity):
    """An HTTP redirect observed during a crawl.

    Attributes:
        source_url: canonical requesting URL.
        destination_url: canonical redirect target.
        status_code: HTTP status that triggered the redirect.
        redirect_type: ``permanent`` | ``temporary`` | ``not-found``.
        chain: full canonical redirect chain.
        source / tool_id / confidence: provenance.
        target_key / correlation_id / mission_id: run provenance.

    """

    source_url: str
    destination_url: str
    status_code: int = 301
    redirect_type: str = "permanent"
    chain: list[str] = field(default_factory=list)
    source: str = "crawl"
    tool_id: str = ""
    confidence: float = 1.0
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class WebAPIEndpoint(TidbEntity):
    """A discovered HTTP API endpoint.

    Attributes:
        url: canonical endpoint URL.
        method: HTTP method.
        content_type: request content type.
        response_content_type: observed response content type.
        parameters: ``{name, location, type, required}`` maps.
        evidence: evidence fragments backing the discovery.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id.

    """

    url: str
    method: str = "GET"
    content_type: str = ""
    response_content_type: str = ""
    parameters: list[dict[str, object]] = field(default_factory=list)
    evidence: list[dict[str, object]] = field(default_factory=list)
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class WebSocketEndpoint(TidbEntity):
    """A discovered WebSocket endpoint.

    Attributes:
        url: canonical ``wss://``/``ws://`` endpoint URL.
        protocol: ``wss`` | ``ws``.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id.

    """

    url: str
    protocol: str = "wss"
    evidence: list[dict[str, object]] = field(default_factory=list)
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class WebGraphQLEndpoint(TidbEntity):
    """A discovered GraphQL endpoint.

    Attributes:
        url: canonical endpoint URL.
        methods: observed HTTP methods.
        introspection: ``open`` | ``closed`` | ``unknown``.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id.

    """

    url: str
    methods: list[str] = field(default_factory=lambda: ["POST"])
    introspection: str = "unknown"
    evidence: list[dict[str, object]] = field(default_factory=list)
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class AuthenticationBoundary(TidbEntity):
    """A location where authentication gates access.

    Attributes:
        url: canonical URL requiring authentication.
        scheme: detected scheme (``basic``, ``bearer``, ``session``...).
        indicators: evidence strings that triggered the boundary.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id.

    """

    url: str
    scheme: str = "session"
    indicators: list[str] = field(default_factory=list)
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class CrawlExecution(TidbEntity):
    """A persisted web crawl run.

    Attributes:
        mission_id: owning mission id.
        target_key: canonical crawl target.
        target_id: owning target record id.
        mode: crawl mode used.
        status: terminal run status.
        urls_seen / urls_distinct: URL observation counts.
        endpoints / redirects / websockets / graphqls / auth_boundaries:
            artifact counts.
        policy: policy snapshot at run time.
        started_at / completed_at: run timestamps.
        summary: free-form run summary (tools, stats).
        correlation_id: run correlation id.

    """

    mission_id: str = ""
    target_key: str = ""
    target_id: str | None = None
    mode: str = "active"
    status: str = "completed"
    urls_seen: int = 0
    urls_distinct: int = 0
    endpoints: int = 0
    redirects: int = 0
    websockets: int = 0
    graphqls: int = 0
    auth_boundaries: int = 0
    policy: dict[str, object] = field(default_factory=dict)
    started_at: str | None = None
    completed_at: str | None = None
    summary: dict[str, object] = field(default_factory=dict)
    correlation_id: str = ""


@dataclass(slots=True)
class CrawlEvidence(TidbEntity):
    """One piece of evidence backing a crawl observation.

    Attributes:
        url: URL the evidence was observed on.
        evidence_type: ``html`` | ``header`` | ``script`` | ``robots`` |
            ``sitemap`` | ``response``.
        value: evidence value.
        source / tool_id: provenance.
        integrity: optional content hash.
        target_key / correlation_id / mission_id: run provenance.

    """

    url: str
    evidence_type: str = "html"
    value: str = ""
    source: str = "crawl"
    tool_id: str = ""
    integrity: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
