# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence canonical domain models.

Pure data contracts for the API Discovery & API Attack-Surface Intelligence
capability (Sprint 014 / Wave 8): hosts, located spec documents, canonical API
versions, endpoint operations, parameters, schema fingerprints,
authentication/authorization schemes, rate-limit/pagination/filter indicators,
evidence, conflicts, historical changes, execution summaries, the collection
strategy and the batch that carries everything back to the application layer.
No I/O and no execution here.

The TIDB ``api_intelligence`` entities
(:mod:`hunterx.domain.entities.tidb.api_intelligence`) are the persistence
projection of these models; this module is the runtime surface the API
intelligence pipeline is built on.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ApiKind(StrEnum):
    """Canonical API families a discovered surface can belong to."""

    REST = "rest"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    SOAP = "soap"
    RPC = "rpc"
    UNKNOWN = "unknown"


class ApiSurfaceForm(StrEnum):
    """The evidence form that produced an API discovery.

    ``OPENAPI`` and ``SWAGGER`` come from spec documents; ``GRAPHQL_SDL`` and
    ``GRAPHQL_SCHEMA_SHAPE`` from GraphQL introspection/SDL or observable
    shape; ``WSDL`` and ``POSTMAN`` from their respective documents; the rest
    are derived from web-crawl or client-side hints.
    """

    OPENAPI = "openapi"
    SWAGGER = "swagger"
    GRAPHQL_SDL = "graphql-sdl"
    GRAPHQL_SCHEMA_SHAPE = "graphql-schema-shape"
    WSDL = "wsdl"
    POSTMAN = "postman"
    WEB_CRAWL = "web-crawl"
    JS_HINT = "js-hint"
    UNDOCUMENTED = "undocumented"


class EvidenceStrength(StrEnum):
    """Relative strength of a single API intelligence indicator."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class EvidenceType(StrEnum):
    """The kind of source an evidence fragment came from."""

    SPEC_DOCUMENT = "spec-document"
    HTTP_HEADER = "http-header"
    HTML = "html"
    SCRIPT = "script"
    TIDB_INTELLIGENCE = "tidb-intelligence"
    TOOL_OUTPUT = "tool-output"
    KNOWN_SIGNATURE = "known-signature"


class PaginationStyle(StrEnum):
    """Pagination styles observable on list endpoints."""

    NONE = "none"
    PAGE = "page"
    CURSOR = "cursor"
    OFFSET = "offset"
    UNKNOWN = "unknown"


class ChangeType(StrEnum):
    """Historical change categories for API intelligence subjects."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


#: Pipeline payload discriminator for typed API findings.
FINDINGS_KEY = "apis"


@dataclass(frozen=True, slots=True)
class ApiTarget:
    """A single API intelligence target.

    Attributes:
        value: canonical target identifier (a hostname, domain, IP or URL).
        target_type: canonical target kind (``url``, ``hostname``, ``domain``,
            ``ip``).
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "hostname"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class ApiEvidence:
    """One evidence fragment backing an API intelligence record.

    Attributes:
        evidence_type: kind of evidence.
        value: evidence value (masked/truncated when long).
        source: upstream source.
        strength: relative indicator strength.
        tool_id: producing tool.
        detail: contextual detail.
        integrity: optional content hash.

    """

    evidence_type: EvidenceType | str = EvidenceType.TIDB_INTELLIGENCE
    value: str = ""
    source: str = "api"
    strength: EvidenceStrength | str = EvidenceStrength.MODERATE
    tool_id: str = ""
    detail: str = ""
    integrity: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_type", _parse_evidence_type(self.evidence_type))
        object.__setattr__(self, "strength", _parse_evidence_strength(self.strength))
        object.__setattr__(self, "value", str(self.value).strip())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "evidence_type": self.evidence_type.value,
            "value": self.value,
            "source": self.source,
            "strength": self.strength.value,
            "tool_id": self.tool_id,
            "detail": self.detail,
            "integrity": self.integrity,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApiEvidence:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            evidence_type=_parse_evidence_type(payload.get("evidence_type")),
            value=str(payload.get("value") or ""),
            source=str(payload.get("source") or "api"),
            strength=_parse_evidence_strength(payload.get("strength")),
            tool_id=str(payload.get("tool_id") or ""),
            detail=str(payload.get("detail") or ""),
            integrity=str(payload.get("integrity") or ""),
        )


@dataclass(frozen=True, slots=True)
class APIHostObservation:
    """A discovered API origin/host.

    Attributes:
        origin_key: canonical ``scheme://host[:port]``.
        scheme: origin scheme.
        host: canonical lowercase host.
        port: effective port (``None`` when default).
        base_url: canonical API base URL.
        api_kinds: observed :class:`ApiKind` values.
        documented: whether any spec was located.
        confidence: discovery confidence in ``[0, 1]``.
        evidence: evidence fragments.
        source / tool_id / target_key / correlation_id / mission_id /
        execution_id / observed_at / record_id.

    """

    origin_key: str
    scheme: str = "https"
    host: str = ""
    port: int | None = None
    base_url: str = ""
    api_kinds: tuple[ApiKind, ...] = ()
    documented: bool = False
    confidence: float = 1.0
    evidence: tuple[ApiEvidence, ...] = ()
    source: str = "api"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "api_kinds", tuple(_parse_api_kind(kind) for kind in self.api_kinds))
        object.__setattr__(self, "host", str(self.host).strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"host:{self.origin_key}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "type": "api-host",
            "record_id": self.record_id,
            "origin_key": self.origin_key,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "base_url": self.base_url,
            "api_kinds": [kind.value for kind in self.api_kinds],
            "documented": self.documented,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> APIHostObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            origin_key=str(payload.get("origin_key") or ""),
            scheme=str(payload.get("scheme") or "https"),
            host=str(payload.get("host") or ""),
            port=payload.get("port"),
            base_url=str(payload.get("base_url") or ""),
            api_kinds=tuple(str(item) for item in payload.get("api_kinds") or ()),
            documented=bool(payload.get("documented") or False),
            confidence=float(payload.get("confidence") or 1.0),
            evidence=tuple(
                ApiEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            source=str(payload.get("source") or "api"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            execution_id=str(payload.get("execution_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class APISpecObservation:
    """A located API specification document.

    Attributes:
        source_url: where the spec was located.
        spec_type: ``openapi2``/``openapi3``/``openapi31``/``swagger``/
            ``wsdl``/``graphql-sdl``/``postman``.
        format: ``json``/``yaml``/``xml``/``sdl``.
        spec_version: the spec's own version field.
        title: spec title.
        operation_count / schema_count: parsed artifact counts.
        integrity: content hash.
        size_bytes: document size in bytes.
        origin_key: owning host.
        confidence: discovery confidence in ``[0, 1]``.
        evidence: evidence fragments.

    """

    source_url: str
    spec_type: str = "openapi3"
    format: str = "yaml"
    spec_version: str = ""
    title: str = ""
    operation_count: int = 0
    schema_count: int = 0
    integrity: str = ""
    size_bytes: int = 0
    origin_key: str = ""
    confidence: float = 1.0
    evidence: tuple[ApiEvidence, ...] = ()
    source: str = "api"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"spec:{self.origin_key}:{self.source_url}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "type": "api-spec",
            "record_id": self.record_id,
            "source_url": self.source_url,
            "spec_type": self.spec_type,
            "format": self.format,
            "spec_version": self.spec_version,
            "title": self.title,
            "operation_count": self.operation_count,
            "schema_count": self.schema_count,
            "integrity": self.integrity,
            "size_bytes": self.size_bytes,
            "origin_key": self.origin_key,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> APISpecObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            source_url=str(payload.get("source_url") or ""),
            spec_type=str(payload.get("spec_type") or "openapi3"),
            format=str(payload.get("format") or "yaml"),
            spec_version=str(payload.get("spec_version") or ""),
            title=str(payload.get("title") or ""),
            operation_count=int(payload.get("operation_count") or 0),
            schema_count=int(payload.get("schema_count") or 0),
            integrity=str(payload.get("integrity") or ""),
            size_bytes=int(payload.get("size_bytes") or 0),
            origin_key=str(payload.get("origin_key") or ""),
            confidence=float(payload.get("confidence") or 1.0),
            evidence=tuple(
                ApiEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            source=str(payload.get("source") or "api"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            execution_id=str(payload.get("execution_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ApiParameterObservation:
    """A parameter observed on an API endpoint.

    Attributes:
        name: parameter name.
        location: ``query``/``path``/``header``/``cookie``/``body``.
        required: whether required.
        param_type: canonical type (``string``/``integer``/...).
        schema_digest: digest of the parameter schema.
        nullable: whether nullable.
        default_value: default when declared.
        enum_values: finite allowed values.
        pattern: regex pattern when present.
        source: ``spec``/``web``/``js``.
        confidence: confidence in ``[0, 1]``.

    """

    name: str
    location: str = "query"
    required: bool = False
    param_type: str = "string"
    schema_digest: str = ""
    nullable: bool = False
    default_value: str | None = None
    enum_values: tuple[str, ...] = ()
    pattern: str | None = None
    source: str = "spec"
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "name": self.name,
            "location": self.location,
            "required": self.required,
            "param_type": self.param_type,
            "schema_digest": self.schema_digest,
            "nullable": self.nullable,
            "default_value": self.default_value,
            "enum_values": list(self.enum_values),
            "pattern": self.pattern,
            "source": self.source,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApiParameterObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            name=str(payload.get("name") or ""),
            location=str(payload.get("location") or "query"),
            required=bool(payload.get("required") or False),
            param_type=str(payload.get("param_type") or "string"),
            schema_digest=str(payload.get("schema_digest") or ""),
            nullable=bool(payload.get("nullable") or False),
            default_value=payload.get("default_value"),
            enum_values=tuple(str(item) for item in payload.get("enum_values") or ()),
            pattern=payload.get("pattern"),
            source=str(payload.get("source") or "spec"),
            confidence=float(payload.get("confidence") or 1.0),
        )


@dataclass(frozen=True, slots=True)
class ApiOperationObservation:
    """A canonical endpoint operation.

    Attributes:
        origin_key: owning host.
        method: HTTP method.
        path: raw endpoint path.
        normalized_path: parameter-placeholder-normalized path.
        path_hash: digest of method + normalized path.
        operation_id: spec operation id when present.
        api_kind: :class:`ApiKind`.
        surface_form: :class:`ApiSurfaceForm`.
        documented: spec-derived versus discovered.
        deprecated: spec deprecation marker.
        tags: spec tags.
        content_type / response_content_type: observed content types.
        auth_required: whether authentication appears required.
        pagination: :class:`PaginationStyle`.
        has_filters: whether list filtering appears supported.
        parameters: observed parameters.
        security_schemes: referenced security scheme names.
        confidence: intelligence confidence in ``[0, 1]``.
        sources: provenance tool ids.
        evidence: evidence fragments.

    """

    origin_key: str
    method: str = "GET"
    path: str = ""
    normalized_path: str = ""
    path_hash: str = ""
    operation_id: str = ""
    api_kind: ApiKind | str = ApiKind.REST
    surface_form: ApiSurfaceForm | str = ApiSurfaceForm.UNDOCUMENTED
    documented: bool = False
    deprecated: bool = False
    tags: tuple[str, ...] = ()
    content_type: str = ""
    response_content_type: str = ""
    auth_required: bool = False
    pagination: PaginationStyle | str = PaginationStyle.UNKNOWN
    has_filters: bool = False
    parameters: tuple[ApiParameterObservation, ...] = ()
    security_schemes: tuple[str, ...] = ()
    confidence: float = 1.0
    sources: tuple[str, ...] = ()
    evidence: tuple[ApiEvidence, ...] = ()
    source: str = "api"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "api_kind", _parse_api_kind(self.api_kind))
        object.__setattr__(self, "surface_form", _parse_surface_form(self.surface_form))
        object.__setattr__(self, "pagination", _parse_pagination(self.pagination))
        object.__setattr__(self, "method", str(self.method).strip().upper())
        object.__setattr__(self, "path", str(self.path).strip())
        if not self.normalized_path:
            object.__setattr__(self, "normalized_path", normalize_path(self.path))
        if not self.path_hash:
            object.__setattr__(self, "path_hash", operation_hash(self.method, self.normalized_path))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"op:{self.origin_key}|{self.path_hash}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "type": "api-operation",
            "record_id": self.record_id,
            "origin_key": self.origin_key,
            "method": self.method,
            "path": self.path,
            "normalized_path": self.normalized_path,
            "path_hash": self.path_hash,
            "operation_id": self.operation_id,
            "api_kind": self.api_kind.value,
            "surface_form": self.surface_form.value,
            "documented": self.documented,
            "deprecated": self.deprecated,
            "tags": list(self.tags),
            "content_type": self.content_type,
            "response_content_type": self.response_content_type,
            "auth_required": self.auth_required,
            "pagination": self.pagination.value,
            "has_filters": self.has_filters,
            "parameters": [item.to_dict() for item in self.parameters],
            "security_schemes": list(self.security_schemes),
            "confidence": self.confidence,
            "sources": list(self.sources),
            "evidence": [item.to_dict() for item in self.evidence],
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApiOperationObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            origin_key=str(payload.get("origin_key") or ""),
            method=str(payload.get("method") or "GET"),
            path=str(payload.get("path") or ""),
            normalized_path=str(payload.get("normalized_path") or ""),
            path_hash=str(payload.get("path_hash") or ""),
            operation_id=str(payload.get("operation_id") or ""),
            api_kind=_parse_api_kind(payload.get("api_kind")),
            surface_form=_parse_surface_form(payload.get("surface_form")),
            documented=bool(payload.get("documented") or False),
            deprecated=bool(payload.get("deprecated") or False),
            tags=tuple(str(item) for item in payload.get("tags") or ()),
            content_type=str(payload.get("content_type") or ""),
            response_content_type=str(payload.get("response_content_type") or ""),
            auth_required=bool(payload.get("auth_required") or False),
            pagination=_parse_pagination(payload.get("pagination")),
            has_filters=bool(payload.get("has_filters") or False),
            parameters=tuple(
                ApiParameterObservation.from_dict(item)
                for item in payload.get("parameters") or ()
                if isinstance(item, dict)
            ),
            security_schemes=tuple(str(item) for item in payload.get("security_schemes") or ()),
            confidence=float(payload.get("confidence") or 1.0),
            sources=tuple(str(item) for item in payload.get("sources") or ()),
            evidence=tuple(
                ApiEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            source=str(payload.get("source") or "api"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            execution_id=str(payload.get("execution_id") or ""),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ApiAuthObservation:
    """An authentication/authorization scheme observed on an API host.

    Attributes:
        origin_key: owning host.
        scheme_type: ``basic``/``bearer``/``apikey``/``oauth2``/``oidc``/
            ``session``/``cookie``/``mutual-tls``/``none``.
        name: scheme name from a spec.
        token_location: ``header``/``query``/``cookie``.
        flows: OAuth2 flows present.
        scopes: declared scopes.
        model_type: authorization model (``rbac``/``abac``/``acl``/``scopes``/
            ``none``/``unknown``).
        roles: observed roles.
        documented: whether a spec declared the scheme.
        indicators: evidence strings.
        confidence: confidence in ``[0, 1]``.

    """

    origin_key: str
    scheme_type: str = "none"
    name: str = ""
    token_location: str = "header"
    flows: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    model_type: str = "unknown"
    roles: tuple[str, ...] = ()
    documented: bool = False
    indicators: tuple[str, ...] = ()
    confidence: float = 1.0
    source: str = "spec"
    tool_id: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"auth:{self.origin_key}:{self.scheme_type}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "type": "api-auth",
            "record_id": self.record_id,
            "origin_key": self.origin_key,
            "scheme_type": self.scheme_type,
            "name": self.name,
            "token_location": self.token_location,
            "flows": list(self.flows),
            "scopes": list(self.scopes),
            "model_type": self.model_type,
            "roles": list(self.roles),
            "documented": self.documented,
            "indicators": list(self.indicators),
            "confidence": self.confidence,
            "source": self.source,
            "tool_id": self.tool_id,
            "target_key": self.target_key,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApiAuthObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            origin_key=str(payload.get("origin_key") or ""),
            scheme_type=str(payload.get("scheme_type") or "none"),
            name=str(payload.get("name") or ""),
            token_location=str(payload.get("token_location") or "header"),
            flows=tuple(str(item) for item in payload.get("flows") or ()),
            scopes=tuple(str(item) for item in payload.get("scopes") or ()),
            model_type=str(payload.get("model_type") or "unknown"),
            roles=tuple(str(item) for item in payload.get("roles") or ()),
            documented=bool(payload.get("documented") or False),
            indicators=tuple(str(item) for item in payload.get("indicators") or ()),
            confidence=float(payload.get("confidence") or 1.0),
            source=str(payload.get("source") or "spec"),
            tool_id=str(payload.get("tool_id") or ""),
            target_key=str(payload.get("target_key") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            execution_id=str(payload.get("execution_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ApiRateLimitObservation:
    """Rate-limit indicators observed on an API host.

    Attributes:
        origin_key: owning host.
        style: ``header``/``token-bucket``/``fixed-window``/``unknown``.
        headers: observed rate-limit header names.
        declared: limit text from spec/docs.
        confidence: confidence in ``[0, 1]``.

    """

    origin_key: str
    style: str = "unknown"
    headers: tuple[str, ...] = ()
    declared: str = ""
    confidence: float = 0.5
    source: str = "web"
    correlation_id: str = ""
    mission_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"ratelimit:{self.origin_key}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "type": "api-rate-limit",
            "record_id": self.record_id,
            "origin_key": self.origin_key,
            "style": self.style,
            "headers": list(self.headers),
            "declared": self.declared,
            "confidence": self.confidence,
            "source": self.source,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApiRateLimitObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            origin_key=str(payload.get("origin_key") or ""),
            style=str(payload.get("style") or "unknown"),
            headers=tuple(str(item) for item in payload.get("headers") or ()),
            declared=str(payload.get("declared") or ""),
            confidence=float(payload.get("confidence") or 0.5),
            source=str(payload.get("source") or "web"),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ApiPaginationObservation:
    """Pagination style observed on an endpoint/API.

    Attributes:
        origin_key: owning host.
        style: :class:`PaginationStyle`.
        endpoint: normalized endpoint path when operation-scoped.
        limit_param: observed limit parameter name.
        offset_param / cursor_param: observed offset/cursor parameter names.
        total_source: ``body``/``header``/``unknown``.
        confidence: confidence in ``[0, 1]``.

    """

    origin_key: str
    style: PaginationStyle | str = PaginationStyle.UNKNOWN
    endpoint: str = ""
    limit_param: str = ""
    offset_param: str | None = None
    cursor_param: str | None = None
    total_source: str = "unknown"
    confidence: float = 0.5
    correlation_id: str = ""
    mission_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "style", _parse_pagination(self.style))

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"pagination:{self.origin_key}:{self.endpoint}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "type": "api-pagination",
            "record_id": self.record_id,
            "origin_key": self.origin_key,
            "style": self.style.value,
            "endpoint": self.endpoint,
            "limit_param": self.limit_param,
            "offset_param": self.offset_param,
            "cursor_param": self.cursor_param,
            "total_source": self.total_source,
            "confidence": self.confidence,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApiPaginationObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            origin_key=str(payload.get("origin_key") or ""),
            style=_parse_pagination(payload.get("style")),
            endpoint=str(payload.get("endpoint") or ""),
            limit_param=str(payload.get("limit_param") or ""),
            offset_param=payload.get("offset_param"),
            cursor_param=payload.get("cursor_param"),
            total_source=str(payload.get("total_source") or "unknown"),
            confidence=float(payload.get("confidence") or 0.5),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ApiFilterObservation:
    """Filter capabilities observed on a list endpoint.

    Attributes:
        origin_key: owning host.
        endpoint: normalized endpoint path.
        filter_param: filter parameter name.
        style: ``query``/``field``/``expression``/``unknown``.
        operators: observed filter operators.
        confidence: confidence in ``[0, 1]``.

    """

    origin_key: str
    endpoint: str = ""
    filter_param: str = ""
    style: str = "unknown"
    operators: tuple[str, ...] = ()
    confidence: float = 0.5
    correlation_id: str = ""
    mission_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def key(self) -> str:
        """Return the canonical deduplication key."""
        return f"filter:{self.origin_key}:{self.endpoint}:{self.filter_param}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "type": "api-filter",
            "record_id": self.record_id,
            "origin_key": self.origin_key,
            "endpoint": self.endpoint,
            "filter_param": self.filter_param,
            "style": self.style,
            "operators": list(self.operators),
            "confidence": self.confidence,
            "correlation_id": self.correlation_id,
            "mission_id": self.mission_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ApiFilterObservation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            origin_key=str(payload.get("origin_key") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            filter_param=str(payload.get("filter_param") or ""),
            style=str(payload.get("style") or "unknown"),
            operators=tuple(str(item) for item in payload.get("operators") or ()),
            confidence=float(payload.get("confidence") or 0.5),
            correlation_id=str(payload.get("correlation_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ApiConflict:
    """A disagreement between sources about one API subject.

    Attributes:
        subject: affected key (host/api/operation).
        subject_type: ``host``/``api``/``version``/``operation``.
        observations: disagreeing observations with provenance.
        conflict_type: ``version``/``identity``/``source``/``method``.
        selected: canonical value selected.
        selected_source: provenance of the selected value.
        reason: human-readable explanation.
        confidence: confidence in the selected value in ``[0, 1]``.
        detected_at: UTC ISO detection timestamp.

    """

    subject: str
    subject_type: str = "operation"
    observations: tuple[dict[str, Any], ...] = ()
    conflict_type: str = "identity"
    selected: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    detected_at: str = field(default_factory=utcnow_iso)

    def key(self) -> str:
        """Return the canonical key of this conflict."""
        return f"api:{self.subject_type}:{self.subject}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "subject": self.subject,
            "subject_type": self.subject_type,
            "observations": [dict(item) for item in self.observations],
            "conflict_type": self.conflict_type,
            "selected": self.selected,
            "selected_source": self.selected_source,
            "reason": self.reason,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
        }


@dataclass(frozen=True, slots=True)
class ApiChange:
    """A detected difference between historical and current API state.

    Attributes:
        subject_type: affected record class.
        subject: canonical subject key.
        change_type: ``added``/``removed``/``changed``.
        previous: previous value (empty for added).
        current: current value (empty for removed).
        detected_at: UTC ISO detection timestamp.
        source: producing tool.
        details: extra change context.

    """

    subject_type: str
    subject: str
    change_type: str
    previous: str = ""
    current: str = ""
    detected_at: str = field(default_factory=utcnow_iso)
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        """Return the canonical key of the changed subject."""
        return f"api:{self.subject_type}:{self.subject}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "subject_type": self.subject_type,
            "subject": self.subject,
            "change_type": self.change_type,
            "previous": self.previous,
            "current": self.current,
            "detected_at": self.detected_at,
            "source": self.source,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class ApiExecutionSummary:
    """Outcome of running one API intelligence tool through the engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        operations: number of endpoint operations produced.
        hosts: number of API hosts produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    operations: int = 0
    hosts: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class ApiBatch:
    """The result of one API intelligence run.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target analysed.
        mode: the execution posture used.
        raw: raw observations collected from every source.
        hosts: correlated canonical API hosts.
        specs: located spec documents.
        operations: correlated endpoint operations.
        auth: authentication/authorization observations.
        rate_limits / paginations / filters: derived indicators.
        conflicts: conflicting observations recorded.
        changes: historical changes detected.
        executions: per-tool execution summaries.
        created_at: UTC ISO-8601 run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: ApiTarget
    mode: ReconMode = ReconMode.HYBRID
    raw: list[Any] = field(default_factory=list)
    hosts: list[APIHostObservation] = field(default_factory=list)
    specs: list[APISpecObservation] = field(default_factory=list)
    operations: list[ApiOperationObservation] = field(default_factory=list)
    auth: list[ApiAuthObservation] = field(default_factory=list)
    rate_limits: list[ApiRateLimitObservation] = field(default_factory=list)
    paginations: list[ApiPaginationObservation] = field(default_factory=list)
    filters: list[ApiFilterObservation] = field(default_factory=list)
    conflicts: list[ApiConflict] = field(default_factory=list)
    changes: list[ApiChange] = field(default_factory=list)
    executions: list[ApiExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_observation(self, observation: Any) -> None:
        """Append a raw observation to the batch."""
        self.raw.append(observation)

    def add_host(self, host: APIHostObservation) -> None:
        """Append a correlated API host."""
        self.hosts.append(host)

    def add_spec(self, spec: APISpecObservation) -> None:
        """Append a located spec document."""
        self.specs.append(spec)

    def add_operation(self, operation: ApiOperationObservation) -> None:
        """Append a correlated endpoint operation."""
        self.operations.append(operation)

    def add_auth(self, auth: ApiAuthObservation) -> None:
        """Append an auth observation."""
        self.auth.append(auth)

    def add_rate_limit(self, observation: ApiRateLimitObservation) -> None:
        """Append a rate-limit observation."""
        self.rate_limits.append(observation)

    def add_pagination(self, observation: ApiPaginationObservation) -> None:
        """Append a pagination observation."""
        self.paginations.append(observation)

    def add_filter(self, observation: ApiFilterObservation) -> None:
        """Append a filter observation."""
        self.filters.append(observation)

    def add_conflict(self, conflict: ApiConflict) -> None:
        """Append a conflict."""
        self.conflicts.append(conflict)

    def add_change(self, change: ApiChange) -> None:
        """Append a historical change."""
        self.changes.append(change)

    def add_execution(self, summary: ApiExecutionSummary) -> None:
        """Append an execution summary."""
        self.executions.append(summary)

    def host_count(self) -> int:
        """Return the number of correlated API hosts."""
        return len(self.hosts)

    def operation_count(self) -> int:
        """Return the number of correlated endpoint operations."""
        return len(self.operations)

    def documented_operations(self) -> int:
        """Return the number of spec-documented operations."""
        return sum(1 for operation in self.operations if operation.documented)

    def undocumented_operations(self) -> int:
        """Return the number of undocumented operations."""
        return sum(1 for operation in self.operations if not operation.documented)

    def distinct_origins(self) -> int:
        """Return the number of distinct origins across hosts."""
        return len({host.origin_key for host in self.hosts})

    def change_count(self) -> int:
        """Return the number of recorded changes."""
        return len(self.changes)

    def conflict_count(self) -> int:
        """Return the number of recorded conflicts."""
        return len(self.conflicts)


# -- observation factories --------------------------------------------------


def make_host_observation(
    origin_key: str,
    *,
    scheme: str = "https",
    host: str = "",
    port: int | None = None,
    base_url: str = "",
    api_kinds: tuple[ApiKind | str, ...] = (),
    documented: bool = False,
    confidence: float = 1.0,
    evidence: tuple[ApiEvidence | dict[str, Any], ...] = (),
    source: str = "api",
    tool_id: str = "",
    target_key: str = "",
    correlation_id: str = "",
    mission_id: str = "",
    execution_id: str = "",
) -> APIHostObservation:
    """Build a :class:`APIHostObservation` for an origin key."""
    parsed_host = host or _origin_host(origin_key)
    return APIHostObservation(
        origin_key=origin_key,
        scheme=scheme,
        host=parsed_host,
        port=port,
        base_url=base_url,
        api_kinds=tuple(_parse_api_kind(kind) for kind in api_kinds),
        documented=documented,
        confidence=confidence,
        evidence=tuple(item if isinstance(item, ApiEvidence) else ApiEvidence.from_dict(item) for item in evidence),
        source=source,
        tool_id=tool_id,
        target_key=target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        execution_id=execution_id,
    )


def make_operation_observation(
    origin_key: str,
    method: str,
    path: str,
    *,
    api_kind: ApiKind | str = ApiKind.REST,
    surface_form: ApiSurfaceForm | str = ApiSurfaceForm.UNDOCUMENTED,
    documented: bool = False,
    parameters: tuple[ApiParameterObservation | dict[str, Any], ...] = (),
    confidence: float = 1.0,
    evidence: tuple[ApiEvidence | dict[str, Any], ...] = (),
    source: str = "api",
    tool_id: str = "",
    target_key: str = "",
    correlation_id: str = "",
    mission_id: str = "",
    execution_id: str = "",
) -> ApiOperationObservation:
    """Build an :class:`ApiOperationObservation` for a method/path."""
    return ApiOperationObservation(
        origin_key=origin_key,
        method=method,
        path=path,
        api_kind=_parse_api_kind(api_kind),
        surface_form=_parse_surface_form(surface_form),
        documented=documented,
        parameters=tuple(
            item if isinstance(item, ApiParameterObservation) else ApiParameterObservation.from_dict(item)
            for item in parameters
        ),
        confidence=confidence,
        evidence=tuple(item if isinstance(item, ApiEvidence) else ApiEvidence.from_dict(item) for item in evidence),
        source=source,
        tool_id=tool_id,
        target_key=target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
        execution_id=execution_id,
    )


def observations_from_payload(payload: Mapping[str, Any] | None) -> list[Any]:
    """Extract canonical observations from a pipeline JSON payload.

    API adapters serialise their findings under the ``apis`` key of the JSON
    payload they attach to the execution output. Each entry carries a ``type``
    discriminator (``api-host``/``api-spec``/``api-operation``/``api-auth``/
    ``api-rate-limit``/``api-pagination``/``api-filter``). This helper rebuilds
    the typed records so downstream services never touch raw dictionaries.
    """
    if not payload:
        return []
    entries = payload.get(FINDINGS_KEY)
    if not isinstance(entries, list):
        return []
    observations: list[Any] = []
    builders: dict[str, Any] = {
        "api-host": APIHostObservation.from_dict,
        "api-spec": APISpecObservation.from_dict,
        "api-operation": ApiOperationObservation.from_dict,
        "api-auth": ApiAuthObservation.from_dict,
        "api-rate-limit": ApiRateLimitObservation.from_dict,
        "api-pagination": ApiPaginationObservation.from_dict,
        "api-filter": ApiFilterObservation.from_dict,
    }
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        builder = builders.get(entry.get("type", ""))
        if builder is None:
            continue
        observations.append(builder(entry))
    return observations


# -- path helpers -----------------------------------------------------------


def normalize_path(path: str) -> str:
    """Normalize a path for deduplication (collapse params and segments)."""
    parts = str(path).strip().split("/")
    normalized: list[str] = []
    for part in parts:
        if not part:
            continue
        lowered = part.lower()
        if (
            lowered.startswith("{")
            and lowered.endswith("}")
            or lowered.startswith(":")
            or lowered in ("id", "ids", "uuid", "slug")
        ):
            normalized.append("{param}")
        else:
            normalized.append(lowered)
    return "/" + "/".join(normalized) if normalized else "/"


def operation_hash(method: str, normalized_path: str) -> str:
    """Return a stable digest of a method + normalized path."""
    import hashlib

    return hashlib.sha256(f"{str(method).upper()} {normalized_path}".encode()).hexdigest()[:24]


def origin_of(url: str) -> str:
    """Return the canonical origin key for a URL (``scheme://host[:port]``)."""
    from urllib.parse import urlsplit

    candidate = str(url).strip()
    try:
        parts = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    except ValueError:  # pragma: no cover - defensive
        return "unknown"
    host = (parts.hostname or "").lower()
    if not host:
        return "unknown"
    scheme = (parts.scheme or "https").lower()
    port = parts.port
    if port is not None and port not in _DEFAULT_PORTS.get(scheme, ()):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


_DEFAULT_PORTS: dict[str, tuple[int, ...]] = {"https": (443,), "http": (80,)}


# -- parsing helpers --------------------------------------------------------


def _parse_api_kind(value: object) -> ApiKind:
    if isinstance(value, ApiKind):
        return value
    try:
        return ApiKind(str(value).lower())
    except ValueError:
        return ApiKind.UNKNOWN


def _parse_surface_form(value: object) -> ApiSurfaceForm:
    if isinstance(value, ApiSurfaceForm):
        return value
    try:
        return ApiSurfaceForm(str(value).lower())
    except ValueError:
        return ApiSurfaceForm.UNDOCUMENTED


def _parse_pagination(value: object) -> PaginationStyle:
    if isinstance(value, PaginationStyle):
        return value
    try:
        return PaginationStyle(str(value).lower())
    except ValueError:
        return PaginationStyle.UNKNOWN


def _parse_evidence_type(value: object) -> EvidenceType:
    if isinstance(value, EvidenceType):
        return value
    try:
        return EvidenceType(str(value).lower())
    except ValueError:
        return EvidenceType.TIDB_INTELLIGENCE


def _parse_evidence_strength(value: object) -> EvidenceStrength:
    if isinstance(value, EvidenceStrength):
        return value
    try:
        return EvidenceStrength(str(value).lower())
    except ValueError:
        return EvidenceStrength.MODERATE


def _origin_host(origin_key: str) -> str:
    """Derive the host portion of an origin key."""
    candidate = str(origin_key).strip()
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    return candidate.split(":", 1)[0]
