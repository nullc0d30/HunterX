# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Canonical web crawling domain models.

Pure data contracts for the web crawling capability: the normalized URL
observation, web origins, redirects, API/WebSocket/GraphQL endpoints,
authentication boundaries, crawl evidence, the crawl run batch and per-tool
execution summaries. Adapters emit these; the service correlates and persists
them; the query service answers from the TIDB.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hunterx.domain.web.urls import ParsedURL
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: HTTP methods the crawler models by default.
HTTP_METHODS_DEFAULT: tuple[str, ...] = ("GET", "HEAD")


class WebCrawlMode(StrEnum):
    """Execution mode of a web crawl run.

    Values mirror the capability matrix in the sprint: passive (no active
    requests), active (in-process crawler), targeted (explicit seeds), sitemap
    (sitemap.xml), robots (robots.txt), historical (passive/historical URL
    sources), api (API-focused mapping), browser (headless-browser assisted)
    and incremental (only new/changed resources).
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    TARGETED = "targeted"
    SITEMAP = "sitemap"
    ROBOTS = "robots"
    HISTORICAL = "historical"
    API = "api"
    BROWSER = "browser"
    INCREMENTAL = "incremental"


class HTTPMethod(StrEnum):
    """Canonical HTTP methods observed on endpoints."""

    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class CrawlTarget:
    """A single web crawl target.

    Attributes:
        value: canonical target (a host, domain or full URL).
        target_type: ``host`` | ``domain`` | ``url`` | ``ip``.
        target_id: owning target record id when persisted.

    """

    value: str
    target_type: str = "url"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class URLObservation:
    """One observation of a normalized in-scope URL.

    Attributes:
        url: canonical absolute URL.
        method: observed HTTP method.
        origin: canonical ``scheme://host[:port]``.
        path: normalized path.
        query: canonicalized query string (empty when none).
        status_code: last observed HTTP status.
        content_type: last observed response content type.
        source: upstream source (``crawl``, ``katana``, ``sitemap``,
            ``robots``, ``historical``, ``passive``).
        tool_id: tool that produced the observation.
        confidence: confidence in ``[0, 1]``.
        target_id: owning target record id when in-scope.
        target_key: canonical owning host key (used for scoping).
        correlation_id: producing run correlation id.
        mission_id: owning mission id.
        execution_id: producing tool execution id.
        observed_at: UTC ISO observation timestamp.
        record_id: stable identifier.

    """

    url: str
    method: HTTPMethod = HTTPMethod.GET
    origin: str = ""
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
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        if isinstance(self.method, str):
            object.__setattr__(self, "method", _http_method(self.method))

    def key(self) -> str:
        """Return the canonical deduplication key (``method url``)."""
        return f"{self.method.value}:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "method": self.method.value,
            "origin": self.origin,
            "path": self.path,
            "query": self.query,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "source": self.source,
            "tool_id": self.tool_id,
            "confidence": self.confidence,
            "target_id": self.target_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> URLObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url", "")),
            method=_http_method(str(payload.get("method") or "GET")),
            origin=str(payload.get("origin") or ""),
            path=str(payload.get("path") or ""),
            query=str(payload.get("query") or ""),
            status_code=payload.get("status_code"),
            content_type=payload.get("content_type"),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            confidence=float(payload.get("confidence") or 1.0),
            target_id=payload.get("target_id"),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            execution_id=str(payload.get("execution_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class Redirect:
    """An HTTP redirect observed during a crawl.

    Attributes:
        source_url: canonical requesting URL.
        destination_url: canonical redirect target.
        status_code: HTTP status that triggered the redirect.
        redirect_type: ``permanent`` | ``temporary`` | ``not-found``.
        chain: full canonical redirect chain (including both endpoints).
        source: upstream source.
        tool_id: producing tool.
        confidence: confidence in ``[0, 1]``.
        target_key: canonical owning host key.
        correlation_id / mission_id / execution_id / observed_at / record_id.

    """

    source_url: str
    destination_url: str
    status_code: int = 301
    redirect_type: str = "permanent"
    chain: tuple[str, ...] = ()
    source: str = "crawl"
    tool_id: str = ""
    confidence: float = 1.0
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"redirect:{self.source_url}->{self.destination_url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "source_url": self.source_url,
            "destination_url": self.destination_url,
            "status_code": self.status_code,
            "redirect_type": self.redirect_type,
            "chain": list(self.chain),
            "source": self.source,
            "tool_id": self.tool_id,
            "confidence": self.confidence,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Redirect:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            source_url=str(payload.get("source_url", "")),
            destination_url=str(payload.get("destination_url", "")),
            status_code=int(payload.get("status_code") or 301),
            redirect_type=str(payload.get("redirect_type") or "permanent"),
            chain=tuple(payload.get("chain") or ()),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            confidence=float(payload.get("confidence") or 1.0),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class APIEndpoint:
    """A discovered HTTP API endpoint.

    Attributes:
        url: canonical endpoint URL.
        method: HTTP method.
        content_type: request content type (e.g. ``application/json``).
        response_content_type: observed response content type.
        parameters: ``{name, location, type, required}`` parameter maps.
        evidence: evidence fragments backing the discovery.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    url: str
    method: HTTPMethod = HTTPMethod.GET
    content_type: str = ""
    response_content_type: str = ""
    parameters: tuple[dict[str, Any], ...] = ()
    evidence: tuple[dict[str, Any], ...] = ()
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        if isinstance(self.method, str):
            object.__setattr__(self, "method", _http_method(self.method))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"api:{self.method.value}:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "method": self.method.value,
            "content_type": self.content_type,
            "response_content_type": self.response_content_type,
            "parameters": [dict(item) for item in self.parameters],
            "evidence": [dict(item) for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> APIEndpoint:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url", "")),
            method=_http_method(str(payload.get("method") or "GET")),
            content_type=str(payload.get("content_type") or ""),
            response_content_type=str(payload.get("response_content_type") or ""),
            parameters=tuple(
                item for item in payload.get("parameters") or () if isinstance(item, dict)
            ),
            evidence=tuple(item for item in payload.get("evidence") or () if isinstance(item, dict)),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class WebSocketEndpoint:
    """A discovered WebSocket endpoint.

    Attributes:
        url: canonical ``wss://``/``ws://`` endpoint URL.
        protocol: ``wss`` | ``ws``.
        evidence: evidence fragments backing the discovery.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    url: str
    protocol: str = "wss"
    evidence: tuple[dict[str, Any], ...] = ()
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"ws:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "protocol": self.protocol,
            "evidence": [dict(item) for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> WebSocketEndpoint:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url", "")),
            protocol=str(payload.get("protocol") or "wss"),
            evidence=tuple(item for item in payload.get("evidence") or () if isinstance(item, dict)),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class GraphQLEndpoint:
    """A discovered GraphQL endpoint.

    Attributes:
        url: canonical endpoint URL.
        methods: observed HTTP methods (usually ``POST``/``GET``).
        introspection: ``open`` | ``closed`` | ``unknown``.
        evidence: evidence fragments backing the discovery.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    url: str
    methods: tuple[str, ...] = ("POST",)
    introspection: str = "unknown"
    evidence: tuple[dict[str, Any], ...] = ()
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"graphql:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "methods": list(self.methods),
            "introspection": self.introspection,
            "evidence": [dict(item) for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> GraphQLEndpoint:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url", "")),
            methods=tuple(payload.get("methods") or ("POST",)),
            introspection=str(payload.get("introspection") or "unknown"),
            evidence=tuple(item for item in payload.get("evidence") or () if isinstance(item, dict)),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class AuthenticationBoundary:
    """A location where authentication gates access.

    Attributes:
        url: canonical URL that requires authentication.
        scheme: detected scheme (``basic``, ``bearer``, ``oauth``,
            ``cookie``, ``session``, ``login-form``).
        indicators: evidence strings that triggered the boundary (e.g.
            ``401 Unauthorized``, ``WWW-Authenticate``).
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    url: str
    scheme: str = "session"
    indicators: tuple[str, ...] = ()
    confidence: float = 1.0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"auth:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "scheme": self.scheme,
            "indicators": list(self.indicators),
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AuthenticationBoundary:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url", "")),
            scheme=str(payload.get("scheme") or "session"),
            indicators=tuple(payload.get("indicators") or ()),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(slots=True)
class CrawlEvidence:
    """One piece of evidence backing a crawl observation.

    Attributes:
        url: URL the evidence was observed on.
        evidence_type: ``html`` | ``header`` | ``script`` | ``robots`` |
            ``sitemap`` | ``response``.
        value: evidence value (headers, snippet, URL...).
        source: upstream source.
        tool_id: producing tool.
        integrity: optional content hash.
        target_key / correlation_id / mission_id / observed_at / record_id.

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
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"{self.evidence_type}:{self.url}:{self.integrity}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "evidence_type": self.evidence_type,
            "value": self.value,
            "source": self.source,
            "tool_id": self.tool_id,
            "integrity": self.integrity,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CrawlEvidence:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url", "")),
            evidence_type=str(payload.get("evidence_type") or "html"),
            value=str(payload.get("value") or ""),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            integrity=str(payload.get("integrity") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class CrawlExecutionSummary:
    """Outcome of running one crawl tool through the execution engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        urls: number of URL observations produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    urls: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class WebCrawlBatch:
    """The result of one web crawl run.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target that was crawled.
        mode: the crawl mode used.
        urls: correlated URL observations.
        redirects: correlated redirects.
        endpoints: correlated API endpoints.
        websockets: correlated WebSocket endpoints.
        graphqls: correlated GraphQL endpoints.
        auth_boundaries: correlated authentication boundaries.
        evidence: crawl evidence records.
        executions: per-tool execution summaries.
        created_at: UTC ISO run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: CrawlTarget
    mode: WebCrawlMode = WebCrawlMode.ACTIVE
    urls: list[URLObservation] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    endpoints: list[APIEndpoint] = field(default_factory=list)
    websockets: list[WebSocketEndpoint] = field(default_factory=list)
    graphqls: list[GraphQLEndpoint] = field(default_factory=list)
    auth_boundaries: list[AuthenticationBoundary] = field(default_factory=list)
    evidence: list[CrawlEvidence] = field(default_factory=list)
    executions: list[CrawlExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def url_count(self) -> int:
        """Return the number of correlated URL observations."""
        return len(self.urls)

    def distinct_urls(self) -> int:
        """Return the number of distinct URLs (by canonical key)."""
        return len({obs.url for obs in self.urls})

    def add_execution(self, summary: CrawlExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)


@dataclass(frozen=True, slots=True)
class CrawlPayload:
    """Parsed artifact set extracted from a tool's JSON payload."""

    urls: tuple[URLObservation, ...] = ()
    redirects: tuple[Redirect, ...] = ()
    endpoints: tuple[APIEndpoint, ...] = ()
    websockets: tuple[WebSocketEndpoint, ...] = ()
    graphqls: tuple[GraphQLEndpoint, ...] = ()
    auth_boundaries: tuple[AuthenticationBoundary, ...] = ()
    evidence: tuple[CrawlEvidence, ...] = ()


def observations_from_payload(payload: Mapping[str, Any] | None) -> CrawlPayload:
    """Rebuild typed observations from a pipeline JSON payload.

    Adapters serialize their discoveries under the ``crawl`` key of the JSON
    payload they attach to the
    :class:`~hunterx.domain.execution.ExecutionOutput`; typed objects are
    rebuilt so downstream services never touch raw dictionaries.
    """
    if not payload:
        return CrawlPayload()
    container = payload.get("crawl")
    if not isinstance(container, dict):
        return CrawlPayload()
    return CrawlPayload(
        urls=tuple(
            URLObservation.from_dict(entry)
            for entry in container.get("urls") or ()
            if isinstance(entry, dict)
        ),
        redirects=tuple(
            Redirect.from_dict(entry)
            for entry in container.get("redirects") or ()
            if isinstance(entry, dict)
        ),
        endpoints=tuple(
            APIEndpoint.from_dict(entry)
            for entry in container.get("endpoints") or ()
            if isinstance(entry, dict)
        ),
        websockets=tuple(
            WebSocketEndpoint.from_dict(entry)
            for entry in container.get("websockets") or ()
            if isinstance(entry, dict)
        ),
        graphqls=tuple(
            GraphQLEndpoint.from_dict(entry)
            for entry in container.get("graphqls") or ()
            if isinstance(entry, dict)
        ),
        auth_boundaries=tuple(
            AuthenticationBoundary.from_dict(entry)
            for entry in container.get("auth_boundaries") or ()
            if isinstance(entry, dict)
        ),
        evidence=tuple(
            CrawlEvidence.from_dict(entry)
            for entry in container.get("evidence") or ()
            if isinstance(entry, dict)
        ),
    )


def parsed_origin(parsed: ParsedURL) -> str:
    """Return the canonical origin string for a parsed URL."""
    return parsed.origin


def _http_method(value: str) -> HTTPMethod:
    """Coerce an arbitrary string into a canonical :class:`HTTPMethod`."""
    try:
        return HTTPMethod(value.upper())
    except ValueError:
        return HTTPMethod.UNKNOWN
