# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript Intelligence canonical domain models.

Pure data contracts for the JavaScript Intelligence & Client-Side Attack-Surface
Discovery capability: asset acquisitions, per-asset analyses, endpoint/route/
WebSocket/GraphQL/authentication references, third-party services, storage
usage, secret indicators, technology & dependency evidence, configuration,
source maps, workers, WebAssembly references, security-relevant API usage,
dynamic imports, evidence, conflicts, historical changes, run batches and the
per-asset analysis container. No I/O and no execution here.

The TIDB ``javascript_intelligence`` entities
(:mod:`hunterx.domain.entities.tidb.javascript_intelligence`) are the
persistence projection of these models; this module is the runtime surface the
JavaScript intelligence pipeline is built on.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class JSMode(StrEnum):
    """Execution posture of a JavaScript intelligence run.

    ``passive`` performs no acquisition (analyse already-fetched script
    content), ``active`` acquires authorized script resources through the fetch
    seam and ``hybrid`` both acquires and folds in supplied inline content.
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    HYBRID = "hybrid"


class JSAssetKind(StrEnum):
    """The class of JavaScript resource analysed.

    Values mirror the acquisition matrix in the sprint: external scripts,
    inline scripts, bundles, lazy-loaded chunks, dynamic resources, source
    maps, service workers, workers and WebAssembly references.
    """

    EXTERNAL = "external"
    INLINE = "inline"
    BUNDLE = "bundle"
    CHUNK = "chunk"
    DYNAMIC = "dynamic"
    SOURCE_MAP = "source-map"
    SERVICE_WORKER = "service-worker"
    WORKER = "worker"
    WASM = "wasm"


class EndpointKind(StrEnum):
    """The client-side API surface a discovered reference targets."""

    FETCH = "fetch"
    XHR = "xhr"
    AXIOS = "axios"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    EVENTSOURCE = "eventsource"
    BASE_URL = "base-url"
    CUSTOM = "custom"


class ApiType(StrEnum):
    """Canonical API family a reference belongs to."""

    REST = "rest"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    SSE = "sse"
    BASE = "base"
    UNKNOWN = "unknown"


class RouteFramework(StrEnum):
    """Frontend routing framework that produced a route reference."""

    REACT = "react-router"
    VUE = "vue-router"
    ANGULAR = "angular"
    NEXT = "next.js"
    NUXT = "nuxt"
    SVELTE = "svelte"
    OTHER = "other"


class DomainRelation(StrEnum):
    """Relationship of a discovered domain to the owning target."""

    SAME_ORIGIN = "same-origin"
    SAME_ORGANIZATION = "same-organization"
    THIRD_PARTY = "third-party"
    UNKNOWN = "unknown"


class StorageType(StrEnum):
    """Client-side storage surface referenced by a script."""

    LOCAL_STORAGE = "local-storage"
    SESSION_STORAGE = "session-storage"
    INDEXED_DB = "indexed-db"
    COOKIE = "cookie"
    CACHE_STORAGE = "cache-storage"
    SERVICE_WORKER_CACHE = "service-worker-cache"


class SecurityApiKind(StrEnum):
    """Security-relevant browser API used by a script (intelligence only)."""

    INNER_HTML = "innerHTML"
    OUTER_HTML = "outerHTML"
    DOCUMENT_WRITE = "document.write"
    EVAL = "eval"
    FUNCTION_CONSTRUCTOR = "Function"
    POST_MESSAGE = "postMessage"
    WINDOW_LOCATION = "window.location"
    DOCUMENT_LOCATION = "document.location"
    DOM_INSERTION = "dom-insertion"
    STORAGE = "storage"
    COOKIE = "cookie"
    WEBSOCKET = "websocket"
    FETCH = "fetch"
    XHR = "xhr"
    URL_CONSTRUCTION = "url-construction"
    REDIRECT = "redirect"


class SecretClassification(StrEnum):
    """Classification of a potential secret indicator."""

    API_KEY = "api-key"
    ACCESS_TOKEN = "access-token"
    JWT = "jwt"
    PRIVATE_KEY = "private-key"
    OAUTH_CLIENT_SECRET = "oauth-client-secret"
    CLOUD_CREDENTIAL = "cloud-credential"
    PASSWORD = "password"
    WEBHOOK = "webhook"
    AUTHORIZATION_HEADER = "authorization-header"
    CONNECTION_STRING = "connection-string"
    SENSITIVE_URL = "sensitive-url"
    GENERIC_SECRET = "generic-secret"


class ConfidenceTier(StrEnum):
    """Intelligence confidence tier of a finding (NOT a vulnerability severity).

    A string resembling a secret is never automatically a real secret; tiers
    express how strongly the evidence supports the finding.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL_INDICATOR = "critical-indicator"


class ThirdPartyCategory(StrEnum):
    """Canonical category of a third-party service reference."""

    ANALYTICS = "analytics"
    CDN = "cdn"
    PAYMENT = "payment"
    AUTHENTICATION = "authentication"
    MONITORING = "monitoring"
    ERROR_TRACKING = "error-tracking"
    FEATURE_FLAG = "feature-flag"
    MAPS = "maps"
    CLOUD = "cloud"
    MESSAGING = "messaging"
    STORAGE = "storage"
    ADVERTISING = "advertising"
    SOCIAL = "social"
    CHAT = "chat"
    OTHER = "other"


class ConfigurationKind(StrEnum):
    """Category of client-side configuration discovered in a script."""

    API_BASE_URL = "api-base-url"
    FEATURE_FLAG = "feature-flag"
    ENVIRONMENT = "environment"
    BUILD_ID = "build-id"
    RELEASE_ID = "release-id"
    SERVICE_ENDPOINT = "service-endpoint"
    APPLICATION_ID = "application-id"
    CLIENT_ID = "client-id"
    OTHER = "other"


class AuthReferenceKind(StrEnum):
    """Kind of authentication reference discovered client-side."""

    LOGIN_ENDPOINT = "login-endpoint"
    LOGOUT_ENDPOINT = "logout-endpoint"
    TOKEN_ENDPOINT = "token-endpoint"
    OAUTH = "oauth"
    OIDC = "oidc"
    SAML = "saml"
    AUTHORIZATION_URL = "authorization-url"
    CALLBACK_URL = "callback-url"
    PKCE = "pkce"
    JWT = "jwt"
    ACCESS_TOKEN = "access-token"
    REFRESH_TOKEN = "refresh-token"
    SESSION = "session"
    OTHER = "other"


class TechnologyEvidenceKind(StrEnum):
    """Kind of technology evidence produced by the JavaScript analyzers."""

    FRAMEWORK = "framework"
    LIBRARY = "library"
    BUNDLER = "bundler"
    TRANSPILER = "transpiler"
    COMPILER = "compiler"
    TOOLING = "tooling"
    RUNTIME = "runtime"


class ChangeType(StrEnum):
    """Historical change categories for JavaScript intelligence subjects."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class WorkerKind(StrEnum):
    """Kind of web worker discovered."""

    WORKER = "worker"
    SERVICE_WORKER = "service-worker"
    SHARED_WORKER = "shared-worker"


class WasmReferenceKind(StrEnum):
    """Way a WebAssembly resource is referenced."""

    INSTANTIATE = "instantiate"
    INSTANTIATE_STREAMING = "instantiate-streaming"
    RESOURCE = "resource"
    IMPORT = "import"


class ParseStatus(StrEnum):
    """Outcome of parsing a JavaScript resource."""

    PARSED = "parsed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


#: Pipeline payload discriminator for typed JavaScript findings.
FINDINGS_KEY = "javascript"


@dataclass(frozen=True, slots=True)
class JSAcquisition:
    """Metadata of one acquired JavaScript resource.

    Attributes:
        url: canonical absolute URL of the resource (``""`` for inline).
        origin: canonical ``scheme://host[:port]`` of the resource.
        parent_url: page URL that referenced the script (inline scripts keep
            the page URL).
        asset_kind: :class:`JSAssetKind`.
        status_code: HTTP status observed at acquisition.
        content_type: response content type.
        content_length: response content length in bytes.
        etag: ETag response header when available.
        last_modified: Last-Modified header when available.
        sha256: SHA-256 digest of the resource content.
        content_hash: short stable content hash used for deduplication.
        size: size of the analysed content in bytes.
        source: upstream source (``crawl``, ``katana``, ``inline``, ``manual``).
        tool_id: tool that produced the acquisition.
        target_key: canonical owning host key.
        mission_id / execution_id / correlation_id: run provenance.
        acquired_at: UTC ISO acquisition timestamp.
        record_id: stable identifier.

    """

    url: str = ""
    origin: str = ""
    parent_url: str = ""
    asset_kind: JSAssetKind | str = JSAssetKind.EXTERNAL
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    etag: str | None = None
    last_modified: str | None = None
    sha256: str = ""
    content_hash: str = ""
    size: int = 0
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    mission_id: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    acquired_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "asset_kind", _parse_asset_kind(self.asset_kind))

    def key(self) -> str:
        """Return the canonical deduplication key (content based)."""
        if self.content_hash:
            return f"js:{self.content_hash}"
        return f"js:url:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "origin": self.origin,
            "parent_url": self.parent_url,
            "asset_kind": self.asset_kind.value,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "sha256": self.sha256,
            "content_hash": self.content_hash,
            "size": self.size,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
            "acquired_at": self.acquired_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSAcquisition:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url") or ""),
            origin=str(payload.get("origin") or ""),
            parent_url=str(payload.get("parent_url") or ""),
            asset_kind=_parse_asset_kind(payload.get("asset_kind")),
            status_code=payload.get("status_code"),
            content_type=payload.get("content_type"),
            content_length=payload.get("content_length"),
            etag=payload.get("etag"),
            last_modified=payload.get("last_modified"),
            sha256=str(payload.get("sha256") or ""),
            content_hash=str(payload.get("content_hash") or ""),
            size=int(payload.get("size") or 0),
            source=str(payload.get("source") or "crawl"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            acquired_at=str(payload.get("acquired_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSEvidence:
    """One evidence fragment backing a JavaScript intelligence finding.

    Attributes:
        evidence_type: kind of evidence (``string``, ``call``, ``member``,
            ``comment``, ``template``, ``source-map``, ``snippet``).
        value: evidence value — always masked/truncated, never a raw secret.
        location: ``file:line:col``-style location.
        offset: byte offset in the source.
        snippet: short surrounding context (masked).
        rule_id: detection rule identifier.
        rule_version: detection rule version.
        source / tool_id: provenance.
        integrity: content hash of the evidence fragment.
        confidence: evidence confidence in ``[0, 1]``.

    """

    evidence_type: str = "string"
    value: str = ""
    location: str = ""
    offset: int = -1
    snippet: str = ""
    rule_id: str = ""
    rule_version: str = "1.0.0"
    source: str = "javascript"
    tool_id: str = ""
    integrity: str = ""
    confidence: float = 1.0

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"{self.evidence_type}:{self.location}:{self.integrity}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "evidence_type": self.evidence_type,
            "value": self.value,
            "location": self.location,
            "offset": self.offset,
            "snippet": self.snippet,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "source": self.source,
            "tool_id": self.tool_id,
            "integrity": self.integrity,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSEvidence:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            evidence_type=str(payload.get("evidence_type") or "string"),
            value=str(payload.get("value") or ""),
            location=str(payload.get("location") or ""),
            offset=int(payload.get("offset") or -1),
            snippet=str(payload.get("snippet") or ""),
            rule_id=str(payload.get("rule_id") or ""),
            rule_version=str(payload.get("rule_version") or "1.0.0"),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            integrity=str(payload.get("integrity") or ""),
            confidence=float(payload.get("confidence") or 1.0),
        )


@dataclass(frozen=True, slots=True)
class JSEndpoint:
    """A client-side reference to an API endpoint or API base URL.

    Attributes:
        url: extracted URL or path (relative paths are normalised later).
        method: HTTP method when observable (``GET``/``POST``/...).
        kind: :class:`EndpointKind` of the reference.
        api_type: :class:`ApiType`.
        base_url: detected API base URL when distinct from ``url``.
        parameters: parameter names observed in the URL or body.
        headers: header names referenced with the call.
        content_type: request content type when referenced.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    url: str
    method: str = "GET"
    kind: EndpointKind | str = EndpointKind.FETCH
    api_type: ApiType | str = ApiType.REST
    base_url: str = ""
    parameters: tuple[str, ...] = ()
    headers: tuple[str, ...] = ()
    content_type: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_endpoint_kind(self.kind))
        object.__setattr__(self, "api_type", _parse_api_type(self.api_type))
        object.__setattr__(self, "url", str(self.url).strip())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"{self.kind.value}:{self.method}:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "url": self.url,
            "method": self.method,
            "kind": self.kind.value,
            "api_type": self.api_type.value,
            "base_url": self.base_url,
            "parameters": list(self.parameters),
            "headers": list(self.headers),
            "content_type": self.content_type,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSEndpoint:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            url=str(payload.get("url") or ""),
            method=str(payload.get("method") or "GET"),
            kind=_parse_endpoint_kind(payload.get("kind")),
            api_type=_parse_api_type(payload.get("api_type")),
            base_url=str(payload.get("base_url") or ""),
            parameters=tuple(str(item) for item in payload.get("parameters") or ()),
            headers=tuple(str(item) for item in payload.get("headers") or ()),
            content_type=str(payload.get("content_type") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSRoute:
    """A frontend route discovered in a script.

    Attributes:
        route: extracted route pattern.
        pattern: normalised pattern (route templates keep ``:param`` markers).
        parameters: parameter names embedded in the pattern.
        framework: :class:`RouteFramework`.
        parent_application: owning application label when observable.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    route: str
    pattern: str = ""
    parameters: tuple[str, ...] = ()
    framework: RouteFramework | str = RouteFramework.OTHER
    parent_application: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "framework", _parse_route_framework(self.framework))
        object.__setattr__(self, "route", str(self.route).strip())
        if not self.pattern:
            object.__setattr__(self, "pattern", self.route)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"route:{self.framework.value}:{self.route}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "route": self.route,
            "pattern": self.pattern,
            "parameters": list(self.parameters),
            "framework": self.framework.value,
            "parent_application": self.parent_application,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSRoute:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            route=str(payload.get("route") or ""),
            pattern=str(payload.get("pattern") or ""),
            parameters=tuple(str(item) for item in payload.get("parameters") or ()),
            framework=_parse_route_framework(payload.get("framework")),
            parent_application=str(payload.get("parent_application") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSAuthenticationReference:
    """A client-side reference to an authentication mechanism.

    Attributes:
        kind: :class:`AuthReferenceKind`.
        value: the referenced value (URL, parameter name, client id...).
        mechanism: scheme/flow observed (``oauth2``, ``oidc``, ``basic``...).
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    kind: AuthReferenceKind | str = AuthReferenceKind.OTHER
    value: str = ""
    mechanism: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_auth_kind(self.kind))
        object.__setattr__(self, "value", str(self.value).strip())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"auth:{self.kind.value}:{self.value}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "kind": self.kind.value,
            "value": self.value,
            "mechanism": self.mechanism,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSAuthenticationReference:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            kind=_parse_auth_kind(payload.get("kind")),
            value=str(payload.get("value") or ""),
            mechanism=str(payload.get("mechanism") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSExternalDomain:
    """A domain referenced by a script.

    Attributes:
        domain: canonical lowercase domain.
        relation: :class:`DomainRelation` relative to the owning target.
        hostname: full hostname referenced (may be a subdomain).
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    domain: str
    relation: DomainRelation | str = DomainRelation.UNKNOWN
    hostname: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "relation", _parse_domain_relation(self.relation))
        object.__setattr__(self, "domain", str(self.domain).strip().lower())
        if not self.hostname:
            object.__setattr__(self, "hostname", self.domain)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"domain:{self.domain}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "domain": self.domain,
            "relation": self.relation.value,
            "hostname": self.hostname,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSExternalDomain:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            domain=str(payload.get("domain") or ""),
            relation=_parse_domain_relation(payload.get("relation")),
            hostname=str(payload.get("hostname") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSThirdPartyService:
    """A third-party service reference detected in a script.

    Attributes:
        provider: provider/company name (``Google``, ``Sentry``).
        service: service/product name (``Google Analytics``).
        category: :class:`ThirdPartyCategory`.
        domain: referenced provider domain when observable.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    provider: str
    service: str = ""
    category: ThirdPartyCategory | str = ThirdPartyCategory.OTHER
    domain: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "category", _parse_service_category(self.category))
        if not self.service:
            object.__setattr__(self, "service", self.provider)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"svc:{self.category.value}:{self.provider}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "provider": self.provider,
            "service": self.service,
            "category": self.category.value,
            "domain": self.domain,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSThirdPartyService:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            provider=str(payload.get("provider") or ""),
            service=str(payload.get("service") or ""),
            category=_parse_service_category(payload.get("category")),
            domain=str(payload.get("domain") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSStorageIndicator:
    """Client-side storage usage detected in a script.

    Attributes:
        storage_type: :class:`StorageType`.
        key_pattern: storage key/pattern referenced (never a value).
        usage_context: how the storage surface is used (``set``, ``get``,
            ``remove``, ``register``).
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    storage_type: StorageType | str = StorageType.LOCAL_STORAGE
    key_pattern: str = ""
    usage_context: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "storage_type", _parse_storage_type(self.storage_type))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"storage:{self.storage_type.value}:{self.key_pattern}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "storage_type": self.storage_type.value,
            "key_pattern": self.key_pattern,
            "usage_context": self.usage_context,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSStorageIndicator:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            storage_type=_parse_storage_type(payload.get("storage_type")),
            key_pattern=str(payload.get("key_pattern") or ""),
            usage_context=str(payload.get("usage_context") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSSecretIndicator:
    """A potential secret indicator detected in a script (never a raw value).

    Attributes:
        classification: :class:`SecretClassification`.
        masked_value: masked form of the candidate (first 4 chars + ``***``).
        value_hash: SHA-256 of the candidate value.
        location: ``file:line`` location.
        file: owning asset URL (or ``inline``).
        line: 1-based line number when available.
        offset: byte offset when available.
        detection_rule: rule id that matched.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        reasoning: why the candidate is (or is not) likely a real secret.
        tier: :class:`ConfidenceTier`.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    classification: SecretClassification | str = SecretClassification.GENERIC_SECRET
    masked_value: str = ""
    value_hash: str = ""
    location: str = ""
    file: str = ""
    line: int | None = None
    offset: int = -1
    detection_rule: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 0.5
    reasoning: str = ""
    tier: ConfidenceTier | str = ConfidenceTier.LOW
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "classification", _parse_secret_classification(self.classification))
        object.__setattr__(self, "tier", _parse_confidence_tier(self.tier))

    def key(self) -> str:
        """Return the canonical deduplication key (value hash based)."""
        return f"secret:{self.classification.value}:{self.value_hash}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload (never the raw candidate)."""
        return {
            "record_id": self.record_id,
            "classification": self.classification.value,
            "masked_value": self.masked_value,
            "value_hash": self.value_hash,
            "location": self.location,
            "file": self.file,
            "line": self.line,
            "offset": self.offset,
            "detection_rule": self.detection_rule,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "tier": self.tier.value,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSSecretIndicator:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            classification=_parse_secret_classification(payload.get("classification")),
            masked_value=str(payload.get("masked_value") or ""),
            value_hash=str(payload.get("value_hash") or ""),
            location=str(payload.get("location") or ""),
            file=str(payload.get("file") or ""),
            line=payload.get("line"),
            offset=int(payload.get("offset") or -1),
            detection_rule=str(payload.get("detection_rule") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 0.5),
            reasoning=str(payload.get("reasoning") or ""),
            tier=_parse_confidence_tier(payload.get("tier")),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSTechnologyEvidence:
    """A framework/library/tooling detection from a script.

    Attributes:
        kind: :class:`TechnologyEvidenceKind`.
        name: canonical technology name.
        version: detected version (empty when unknown).
        version_confidence: ``confirmed`` | ``probable`` | ``range`` |
            ``unknown``.
        category: taxonomy category hint.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    kind: TechnologyEvidenceKind | str = TechnologyEvidenceKind.LIBRARY
    name: str = ""
    version: str = ""
    version_confidence: str = "unknown"
    category: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_technology_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"tech:{self.name}:{self.version}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "kind": self.kind.value,
            "name": self.name,
            "version": self.version,
            "version_confidence": self.version_confidence,
            "category": self.category,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSTechnologyEvidence:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            kind=_parse_technology_kind(payload.get("kind")),
            name=str(payload.get("name") or ""),
            version=str(payload.get("version") or ""),
            version_confidence=str(payload.get("version_confidence") or "unknown"),
            category=str(payload.get("category") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSDependency:
    """A recognisable package/dependency indicator in a script.

    Attributes:
        name: package name (may include scope).
        version: version when determinable.
        source: indicator origin (``import``, ``require``, ``cdn``,
            ``comment``, ``manifest``).
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    name: str = ""
    version: str = ""
    source: str = "import"
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source_: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"dep:{self.name}:{self.version}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "tool_source": self.source_,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSDependency:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            name=str(payload.get("name") or ""),
            version=str(payload.get("version") or ""),
            source=str(payload.get("source") or "import"),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source_=str(payload.get("tool_source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSConfigurationIndicator:
    """Client-side configuration discovered in a script.

    Attributes:
        kind: :class:`ConfigurationKind`.
        key: configuration key/name.
        value: value (masked when potentially sensitive).
        environment: detected environment name when known.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    kind: ConfigurationKind | str = ConfigurationKind.OTHER
    key: str = ""
    value: str = ""
    environment: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_config_kind(self.kind))

    def dedup_key(self) -> str:
        """Return the canonical deduplication key."""
        return f"config:{self.kind.value}:{self.key}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "kind": self.kind.value,
            "key": self.key,
            "value": self.value,
            "environment": self.environment,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSConfigurationIndicator:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            kind=_parse_config_kind(payload.get("kind")),
            key=str(payload.get("key") or ""),
            value=str(payload.get("value") or ""),
            environment=str(payload.get("environment") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSSourceMap:
    """A source map discovered for a JavaScript asset.

    Attributes:
        map_url: URL of the ``.map`` resource.
        parent_asset: URL of the asset the map belongs to.
        source_root: ``sourceRoot`` value from the map metadata.
        source_files: original source files referenced.
        embedded_sources: whether sources are embedded in the map.
        content_hash: hash of the map content when available.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    map_url: str = ""
    parent_asset: str = ""
    source_root: str = ""
    source_files: tuple[str, ...] = ()
    embedded_sources: bool = False
    content_hash: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"sourcemap:{self.map_url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "map_url": self.map_url,
            "parent_asset": self.parent_asset,
            "source_root": self.source_root,
            "source_files": list(self.source_files),
            "embedded_sources": self.embedded_sources,
            "content_hash": self.content_hash,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSSourceMap:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            map_url=str(payload.get("map_url") or ""),
            parent_asset=str(payload.get("parent_asset") or ""),
            source_root=str(payload.get("source_root") or ""),
            source_files=tuple(str(item) for item in payload.get("source_files") or ()),
            embedded_sources=bool(payload.get("embedded_sources") or False),
            content_hash=str(payload.get("content_hash") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSWorker:
    """A worker/service-worker discovered in a script.

    Attributes:
        kind: :class:`WorkerKind`.
        url: worker script URL (empty for inline workers).
        registration_context: how the worker is created/registered.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    kind: WorkerKind | str = WorkerKind.WORKER
    url: str = ""
    registration_context: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_worker_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"worker:{self.kind.value}:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "kind": self.kind.value,
            "url": self.url,
            "registration_context": self.registration_context,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSWorker:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            kind=_parse_worker_kind(payload.get("kind")),
            url=str(payload.get("url") or ""),
            registration_context=str(payload.get("registration_context") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSWasmReference:
    """A WebAssembly reference discovered in a script.

    Attributes:
        kind: :class:`WasmReferenceKind`.
        url: referenced ``.wasm`` URL when observable.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    kind: WasmReferenceKind | str = WasmReferenceKind.RESOURCE
    url: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _parse_wasm_kind(self.kind))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"wasm:{self.kind.value}:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "kind": self.kind.value,
            "url": self.url,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSWasmReference:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            kind=_parse_wasm_kind(payload.get("kind")),
            url=str(payload.get("url") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSSecurityIndicator:
    """Usage of a security-relevant browser API (intelligence only).

    Attributes:
        api: :class:`SecurityApiKind`.
        context: short masked context around the usage.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    api: SecurityApiKind | str = SecurityApiKind.INNER_HTML
    context: str = ""
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "api", _parse_security_api(self.api))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"security:{self.api.value}:{self.context}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "api": self.api.value,
            "context": self.context,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSSecurityIndicator:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            api=_parse_security_api(payload.get("api")),
            context=str(payload.get("context") or ""),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSDynamicImport:
    """A dynamic import / lazy-loaded chunk reference.

    Attributes:
        specifier: the import specifier (module name or path).
        url: resolved URL when determinable.
        chunk: whether the reference looks like a bundler chunk.
        evidence: evidence fragments.
        confidence: confidence in ``[0, 1]``.
        source / tool_id / target_key / correlation_id / mission_id /
        observed_at / record_id.

    """

    specifier: str = ""
    url: str = ""
    chunk: bool = False
    evidence: tuple[JSEvidence, ...] = ()
    confidence: float = 1.0
    source: str = "javascript"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"import:{self.specifier}:{self.url}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "specifier": self.specifier,
            "url": self.url,
            "chunk": self.chunk,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSDynamicImport:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            specifier=str(payload.get("specifier") or ""),
            url=str(payload.get("url") or ""),
            chunk=bool(payload.get("chunk") or False),
            evidence=tuple(
                JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "javascript"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class JSAnalysisConflict:
    """A preserved contradiction in JavaScript intelligence evidence.

    Attributes:
        subject: the affected asset/artifact identifier.
        artifact_type: which artifact class disagrees.
        observations: disagreeing observations (masked).
        selected: canonical value selected.
        reason: why the value was selected.
        confidence: confidence in the selection in ``[0, 1]``.
        detected_at: UTC ISO detection timestamp.

    """

    subject: str
    artifact_type: str
    observations: tuple[dict[str, Any], ...] = ()
    selected: str = ""
    reason: str = ""
    confidence: float = 0.0
    detected_at: str = field(default_factory=utcnow_iso)

    def key(self) -> str:
        """Return the canonical key of this conflict."""
        return f"js-conflict:{self.subject}:{self.artifact_type}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for reporting."""
        return {
            "subject": self.subject,
            "artifact_type": self.artifact_type,
            "observations": [dict(item) for item in self.observations],
            "selected": self.selected,
            "reason": self.reason,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
        }


@dataclass(frozen=True, slots=True)
class JSChange:
    """A detected difference between historical and current JS state.

    Attributes:
        artifact_type: the affected artifact class.
        subject: canonical subject key.
        change_type: ``added`` | ``removed`` | ``changed``.
        previous: previous value.
        current: current value.
        detected_at: UTC ISO detection timestamp.
        source: producing tool.
        details: extra change context.

    """

    artifact_type: str
    subject: str
    change_type: str
    previous: str = ""
    current: str = ""
    detected_at: str = field(default_factory=utcnow_iso)
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        """Return the canonical key of the changed subject."""
        return f"js:{self.artifact_type}:{self.subject}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for reporting."""
        return {
            "artifact_type": self.artifact_type,
            "subject": self.subject,
            "change_type": self.change_type,
            "previous": self.previous,
            "current": self.current,
            "detected_at": self.detected_at,
            "source": self.source,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class JSExecutionSummary:
    """Outcome of running one JavaScript analysis tool.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        assets: number of asset acquisitions produced.
        endpoints: number of endpoint references produced.
        secrets: number of secret indicators produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    assets: int = 0
    endpoints: int = 0
    secrets: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class JSAssetAnalysis:
    """The complete analysis result for one JavaScript asset.

    Attributes:
        asset: the acquisition metadata.
        parse_status: :class:`ParseStatus`.
        analysis_version: rule/analysis version that produced this result.
        tokens: number of tokens produced.
        strings: number of string/template literals extracted.
        endpoints: extracted endpoint references.
        routes: extracted routes.
        auth: authentication references.
        domains: referenced external domains.
        services: third-party services.
        storage: storage indicators.
        secrets: secret indicators.
        technology: technology evidence.
        dependencies: dependency indicators.
        configuration: configuration indicators.
        source_maps: source map references.
        workers: worker references.
        wasm: WebAssembly references.
        security: security-relevant API usage.
        dynamic_imports: dynamic import references.
        evidence: collected evidence fragments.
        conflicts: analysis conflicts.
        started_at / completed_at: analysis timestamps.
        record_id: stable identifier.

    """

    asset: JSAcquisition
    parse_status: ParseStatus | str = ParseStatus.PARSED
    analysis_version: str = "1.0.0"
    tokens: int = 0
    strings: int = 0
    endpoints: list[JSEndpoint] = field(default_factory=list)
    routes: list[JSRoute] = field(default_factory=list)
    auth: list[JSAuthenticationReference] = field(default_factory=list)
    domains: list[JSExternalDomain] = field(default_factory=list)
    services: list[JSThirdPartyService] = field(default_factory=list)
    storage: list[JSStorageIndicator] = field(default_factory=list)
    secrets: list[JSSecretIndicator] = field(default_factory=list)
    technology: list[JSTechnologyEvidence] = field(default_factory=list)
    dependencies: list[JSDependency] = field(default_factory=list)
    configuration: list[JSConfigurationIndicator] = field(default_factory=list)
    source_maps: list[JSSourceMap] = field(default_factory=list)
    workers: list[JSWorker] = field(default_factory=list)
    wasm: list[JSWasmReference] = field(default_factory=list)
    security: list[JSSecurityIndicator] = field(default_factory=list)
    dynamic_imports: list[JSDynamicImport] = field(default_factory=list)
    evidence: list[JSEvidence] = field(default_factory=list)
    conflicts: list[JSAnalysisConflict] = field(default_factory=list)
    started_at: str = field(default_factory=utcnow_iso)
    completed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "parse_status", _parse_status(self.parse_status))

    def total_findings(self) -> int:
        """Return the number of intelligence findings for the asset."""
        return sum(
            len(items)
            for items in (
                self.endpoints,
                self.routes,
                self.auth,
                self.domains,
                self.services,
                self.storage,
                self.secrets,
                self.technology,
                self.dependencies,
                self.configuration,
                self.source_maps,
                self.workers,
                self.wasm,
                self.security,
                self.dynamic_imports,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the analysis to a JSON-safe payload."""
        return {
            "record_id": self.record_id,
            "asset": self.asset.to_dict(),
            "parse_status": self.parse_status.value,
            "analysis_version": self.analysis_version,
            "tokens": self.tokens,
            "strings": self.strings,
            "endpoints": [item.to_dict() for item in self.endpoints],
            "routes": [item.to_dict() for item in self.routes],
            "auth": [item.to_dict() for item in self.auth],
            "domains": [item.to_dict() for item in self.domains],
            "services": [item.to_dict() for item in self.services],
            "storage": [item.to_dict() for item in self.storage],
            "secrets": [item.to_dict() for item in self.secrets],
            "technology": [item.to_dict() for item in self.technology],
            "dependencies": [item.to_dict() for item in self.dependencies],
            "configuration": [item.to_dict() for item in self.configuration],
            "source_maps": [item.to_dict() for item in self.source_maps],
            "workers": [item.to_dict() for item in self.workers],
            "wasm": [item.to_dict() for item in self.wasm],
            "security": [item.to_dict() for item in self.security],
            "dynamic_imports": [item.to_dict() for item in self.dynamic_imports],
            "evidence": [item.to_dict() for item in self.evidence],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> JSAssetAnalysis:
        """Rebuild an analysis from a :meth:`to_dict` payload."""
        raw_asset = payload.get("asset") or {}
        return cls(
            asset=JSAcquisition.from_dict(raw_asset) if isinstance(raw_asset, dict) else JSAcquisition(),
            parse_status=_parse_status(payload.get("parse_status")),
            analysis_version=str(payload.get("analysis_version") or "1.0.0"),
            tokens=int(payload.get("tokens") or 0),
            strings=int(payload.get("strings") or 0),
            endpoints=[JSEndpoint.from_dict(item) for item in payload.get("endpoints") or () if isinstance(item, dict)],
            routes=[JSRoute.from_dict(item) for item in payload.get("routes") or () if isinstance(item, dict)],
            auth=[
                JSAuthenticationReference.from_dict(item)
                for item in payload.get("auth") or ()
                if isinstance(item, dict)
            ],
            domains=[JSExternalDomain.from_dict(item) for item in payload.get("domains") or () if isinstance(item, dict)],
            services=[
                JSThirdPartyService.from_dict(item)
                for item in payload.get("services") or ()
                if isinstance(item, dict)
            ],
            storage=[JSStorageIndicator.from_dict(item) for item in payload.get("storage") or () if isinstance(item, dict)],
            secrets=[JSSecretIndicator.from_dict(item) for item in payload.get("secrets") or () if isinstance(item, dict)],
            technology=[
                JSTechnologyEvidence.from_dict(item)
                for item in payload.get("technology") or ()
                if isinstance(item, dict)
            ],
            dependencies=[
                JSDependency.from_dict(item) for item in payload.get("dependencies") or () if isinstance(item, dict)
            ],
            configuration=[
                JSConfigurationIndicator.from_dict(item)
                for item in payload.get("configuration") or ()
                if isinstance(item, dict)
            ],
            source_maps=[
                JSSourceMap.from_dict(item) for item in payload.get("source_maps") or () if isinstance(item, dict)
            ],
            workers=[JSWorker.from_dict(item) for item in payload.get("workers") or () if isinstance(item, dict)],
            wasm=[JSWasmReference.from_dict(item) for item in payload.get("wasm") or () if isinstance(item, dict)],
            security=[
                JSSecurityIndicator.from_dict(item)
                for item in payload.get("security") or ()
                if isinstance(item, dict)
            ],
            dynamic_imports=[
                JSDynamicImport.from_dict(item)
                for item in payload.get("dynamic_imports") or ()
                if isinstance(item, dict)
            ],
            evidence=[JSEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)],
            conflicts=[
                JSAnalysisConflict.from_dict(item)
                for item in payload.get("conflicts") or ()
                if isinstance(item, dict)
            ],
            started_at=str(payload.get("started_at") or utcnow_iso()),
            completed_at=str(payload.get("completed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(slots=True)
class JavaScriptBatch:
    """The result of one JavaScript intelligence run.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target analysed.
        mode: the execution posture used.
        analyses: per-asset analyses.
        assets: correlated asset acquisitions (one per content hash).
        endpoints: correlated endpoint references.
        routes: correlated client routes.
        auth: correlated authentication references.
        domains: correlated external domains.
        services: correlated third-party services.
        storage: correlated storage indicators.
        secrets: correlated secret indicators.
        technology: correlated technology evidence.
        dependencies: correlated dependencies.
        configuration: correlated configuration indicators.
        source_maps: correlated source maps.
        workers: correlated worker references.
        wasm: correlated WebAssembly references.
        security: correlated security indicators.
        dynamic_imports: correlated dynamic imports.
        evidence: collected evidence fragments.
        conflicts: recorded analysis conflicts.
        changes: historical changes detected.
        executions: per-tool execution summaries.
        created_at: UTC ISO-8601 run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: JSTarget
    mode: JSMode = JSMode.ACTIVE
    analyses: list[JSAssetAnalysis] = field(default_factory=list)
    assets: list[JSAcquisition] = field(default_factory=list)
    endpoints: list[JSEndpoint] = field(default_factory=list)
    routes: list[JSRoute] = field(default_factory=list)
    auth: list[JSAuthenticationReference] = field(default_factory=list)
    domains: list[JSExternalDomain] = field(default_factory=list)
    services: list[JSThirdPartyService] = field(default_factory=list)
    storage: list[JSStorageIndicator] = field(default_factory=list)
    secrets: list[JSSecretIndicator] = field(default_factory=list)
    technology: list[JSTechnologyEvidence] = field(default_factory=list)
    dependencies: list[JSDependency] = field(default_factory=list)
    configuration: list[JSConfigurationIndicator] = field(default_factory=list)
    source_maps: list[JSSourceMap] = field(default_factory=list)
    workers: list[JSWorker] = field(default_factory=list)
    wasm: list[JSWasmReference] = field(default_factory=list)
    security: list[JSSecurityIndicator] = field(default_factory=list)
    dynamic_imports: list[JSDynamicImport] = field(default_factory=list)
    evidence: list[JSEvidence] = field(default_factory=list)
    conflicts: list[JSAnalysisConflict] = field(default_factory=list)
    changes: list[JSChange] = field(default_factory=list)
    executions: list[JSExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_analysis(self, analysis: JSAssetAnalysis) -> None:
        """Append a per-asset analysis to the batch."""
        self.analyses.append(analysis)

    def add_execution(self, summary: JSExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)

    def asset_count(self) -> int:
        """Return the number of correlated asset acquisitions."""
        return len(self.assets)

    def finding_count(self) -> int:
        """Return the total number of correlated intelligence findings."""
        return sum(
            len(items)
            for items in (
                self.endpoints,
                self.routes,
                self.auth,
                self.domains,
                self.services,
                self.storage,
                self.secrets,
                self.technology,
                self.dependencies,
                self.configuration,
                self.source_maps,
                self.workers,
                self.wasm,
                self.security,
                self.dynamic_imports,
            )
        )

    def secret_count(self) -> int:
        """Return the number of correlated secret indicators."""
        return len(self.secrets)

    def high_confidence_secrets(self, *, min_confidence: float = 0.7) -> int:
        """Return the number of secret indicators above a confidence floor."""
        return sum(1 for indicator in self.secrets if indicator.confidence >= min_confidence)

    def endpoint_count(self) -> int:
        """Return the number of correlated endpoint references."""
        return len(self.endpoints)

    def total_analyses(self) -> int:
        """Return the number of per-asset analyses in the batch."""
        return len(self.analyses)


@dataclass(frozen=True, slots=True)
class JSTarget:
    """A single JavaScript intelligence target.

    Attributes:
        value: canonical target identifier (a hostname, domain, IP or URL).
        target_type: canonical target kind.
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "host"
    target_id: str = ""


def findings_from_payload(payload: Mapping[str, Any] | None) -> list[JSAssetAnalysis]:
    """Extract per-asset analyses from a pipeline JSON payload.

    JavaScript adapters serialize their analyses under the ``javascript`` key
    of the JSON payload they attach to the execution output; typed objects are
    rebuilt so downstream services never touch raw dictionaries.
    """
    if not payload:
        return []
    container = payload.get(FINDINGS_KEY)
    if not isinstance(container, dict):
        return []
    analyses: list[JSAssetAnalysis] = []
    for entry in container.get("analyses") or ():
        if isinstance(entry, dict):
            analyses.append(JSAssetAnalysis.from_dict(entry))
    return analyses


def make_target(value: str) -> JSTarget:
    """Build a :class:`JSTarget` from a plain string, inferring its kind."""
    stripped = str(value).strip()
    lowered = stripped.lower()
    if lowered.startswith(("http://", "https://")):
        return JSTarget(value=stripped, target_type="url")
    try:
        import ipaddress

        ipaddress.ip_address(stripped)
        return JSTarget(value=stripped, target_type="ip")
    except ValueError:
        pass
    if "." in stripped:
        return JSTarget(value=stripped, target_type="host")
    return JSTarget(value=stripped, target_type="host")


def make_mode(mode: JSMode | str) -> JSMode:
    """Coerce a mode into a :class:`JSMode`."""
    if isinstance(mode, JSMode):
        return mode
    return JSMode(str(mode).lower())


# -- parsing helpers --------------------------------------------------------

_ENUM_PARSERS = {
    "asset_kind": JSAssetKind,
    "endpoint_kind": EndpointKind,
    "api_type": ApiType,
    "route_framework": RouteFramework,
    "domain_relation": DomainRelation,
    "storage_type": StorageType,
    "security_api": SecurityApiKind,
    "secret_classification": SecretClassification,
    "confidence_tier": ConfidenceTier,
    "third_party_category": ThirdPartyCategory,
    "configuration_kind": ConfigurationKind,
    "auth_kind": AuthReferenceKind,
    "technology_kind": TechnologyEvidenceKind,
    "worker_kind": WorkerKind,
    "wasm_kind": WasmReferenceKind,
    "parse_status": ParseStatus,
}


def _parse_enum(enum_cls: type, value: object, default: object) -> object:
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value).lower())
    except (ValueError, AttributeError):
        return default


def _parse_asset_kind(value: object) -> JSAssetKind:
    return _parse_enum(JSAssetKind, value, JSAssetKind.EXTERNAL)  # type: ignore[return-value]


def _parse_endpoint_kind(value: object) -> EndpointKind:
    return _parse_enum(EndpointKind, value, EndpointKind.FETCH)  # type: ignore[return-value]


def _parse_api_type(value: object) -> ApiType:
    return _parse_enum(ApiType, value, ApiType.REST)  # type: ignore[return-value]


def _parse_route_framework(value: object) -> RouteFramework:
    return _parse_enum(RouteFramework, value, RouteFramework.OTHER)  # type: ignore[return-value]


def _parse_domain_relation(value: object) -> DomainRelation:
    return _parse_enum(DomainRelation, value, DomainRelation.UNKNOWN)  # type: ignore[return-value]


def _parse_storage_type(value: object) -> StorageType:
    return _parse_enum(StorageType, value, StorageType.LOCAL_STORAGE)  # type: ignore[return-value]


def _parse_security_api(value: object) -> SecurityApiKind:
    return _parse_enum(SecurityApiKind, value, SecurityApiKind.INNER_HTML)  # type: ignore[return-value]


def _parse_secret_classification(value: object) -> SecretClassification:
    return _parse_enum(SecretClassification, value, SecretClassification.GENERIC_SECRET)  # type: ignore[return-value]


def _parse_confidence_tier(value: object) -> ConfidenceTier:
    return _parse_enum(ConfidenceTier, value, ConfidenceTier.LOW)  # type: ignore[return-value]


def _parse_service_category(value: object) -> ThirdPartyCategory:
    return _parse_enum(ThirdPartyCategory, value, ThirdPartyCategory.OTHER)  # type: ignore[return-value]


def _parse_config_kind(value: object) -> ConfigurationKind:
    return _parse_enum(ConfigurationKind, value, ConfigurationKind.OTHER)  # type: ignore[return-value]


def _parse_auth_kind(value: object) -> AuthReferenceKind:
    return _parse_enum(AuthReferenceKind, value, AuthReferenceKind.OTHER)  # type: ignore[return-value]


def _parse_technology_kind(value: object) -> TechnologyEvidenceKind:
    return _parse_enum(TechnologyEvidenceKind, value, TechnologyEvidenceKind.LIBRARY)  # type: ignore[return-value]


def _parse_worker_kind(value: object) -> WorkerKind:
    return _parse_enum(WorkerKind, value, WorkerKind.WORKER)  # type: ignore[return-value]


def _parse_wasm_kind(value: object) -> WasmReferenceKind:
    return _parse_enum(WasmReferenceKind, value, WasmReferenceKind.RESOURCE)  # type: ignore[return-value]


def _parse_status(value: object) -> ParseStatus:
    return _parse_enum(ParseStatus, value, ParseStatus.SKIPPED)  # type: ignore[return-value]
