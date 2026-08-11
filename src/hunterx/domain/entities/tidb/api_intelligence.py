# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence Target Intelligence Database entities.

System-of-record entities for the API Discovery & API Attack-Surface
Intelligence capability (Sprint 014 / Wave 8). They carry the canonical,
evidence-backed API inventory: hosts, located spec documents, versions,
operations, parameters, schemas, authentication/authorization schemes,
rate-limit, pagination and filter indicators, plus the derived intelligence
(conflicts, changes, evidence and run records).

These entities complement the legacy API-surface entities in
:mod:`hunterx.domain.entities.tidb.api` — the Wave-8 canonical inventory is
persisted here and cross-references the existing topology and web-crawl
projections rather than duplicating them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class APIRun(TidbEntity):
    """Observability record for an API intelligence run.

    Attributes:
        mission_id: owning mission id.
        target_key: canonical target the run covered.
        target_id: owning target record id.
        status: terminal run status.
        mode: execution posture (passive/active/hybrid).
        hosts / apis / operations / parameters / schemas / auth_schemes /
            changes / conflicts: artifact counts.
        started_at / completed_at / duration_ms: timing.
        summary: free-form run summary (tools, stats).
        correlation_id: correlation id of the run.

    """

    mission_id: str = ""
    target_key: str = ""
    target_id: str | None = None
    status: str = "running"
    mode: str = "hybrid"
    hosts: int = 0
    apis: int = 0
    operations: int = 0
    parameters: int = 0
    schemas: int = 0
    auth_schemes: int = 0
    changes: int = 0
    conflicts: int = 0
    started_at: str = ""
    completed_at: str | None = None
    duration_ms: int = 0
    summary: dict[str, object] = field(default_factory=dict)
    correlation_id: str = ""


@dataclass(slots=True)
class APIHost(TidbEntity):
    """A canonical discovered API origin/host.

    Attributes:
        target_key: owning target scope.
        scheme: origin scheme (``https``/``http``).
        host: canonical lowercase host.
        port: effective port (``None`` when default).
        base_url: canonical API base URL.
        origin_key: ``scheme://host[:port]``.
        api_kinds: observed :class:`~hunterx.domain.api.models.ApiKind` values.
        api_count / endpoint_count: persisted artifact counts.
        documented: whether any spec document was located.
        confidence: discovery confidence in ``[0, 1]``.
        evidence: evidence fragments backing the discovery.

    """

    target_key: str = ""
    scheme: str = "https"
    host: str = ""
    port: int | None = None
    base_url: str = ""
    origin_key: str = ""
    api_kinds: list[str] = field(default_factory=list)
    api_count: int = 0
    endpoint_count: int = 0
    documented: bool = False
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""


@dataclass(slots=True)
class APISpec(TidbEntity):
    """A located API specification document.

    Attributes:
        host_id: owning :class:`APIHost` record id.
        target_key: owning target scope.
        source_url: where the spec was located.
        spec_type: ``openapi2``/``openapi3``/``openapi31``/``swagger``/
            ``wsdl``/``graphql-sdl``/``postman``.
        format: ``json``/``yaml``/``xml``/``sdl``.
        spec_version: the spec's own version field.
        title: spec title.
        operation_count / schema_count: parsed artifact counts.
        integrity: content hash.
        size_bytes: document size in bytes.
        confidence: discovery confidence in ``[0, 1]``.

    """

    host_id: str = ""
    target_key: str = ""
    source_url: str = ""
    spec_type: str = "openapi3"
    format: str = "yaml"
    spec_version: str = ""
    title: str = ""
    operation_count: int = 0
    schema_count: int = 0
    integrity: str = ""
    size_bytes: int = 0
    confidence: float = 1.0
    correlation_id: str = ""
    mission_id: str = ""
    execution_id: str = ""


@dataclass(slots=True)
class APIVersion(TidbEntity):
    """A canonical API version on a host.

    Attributes:
        host_id: owning :class:`APIHost` record id.
        api_name: canonical API name.
        api_version: canonical version.
        spec_version: version declared by a located spec.
        path_prefix: detected path prefix (``/v1``, ``/api/v2``...).
        documented: whether a spec backs this version.
        operation_count: number of persisted operations.
        endpoint_hash: digest of normalized operations (change detection).

    """

    host_id: str = ""
    api_name: str = ""
    api_version: str = ""
    spec_version: str = ""
    path_prefix: str = ""
    documented: bool = False
    operation_count: int = 0
    endpoint_hash: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIOperation(TidbEntity):
    """A canonical endpoint operation.

    Attributes:
        api_id: owning :class:`APIVersion` record id.
        host_id: owning :class:`APIHost` record id.
        method: HTTP method.
        path: raw endpoint path.
        normalized_path: parameter-placeholder-normalized path.
        path_hash: digest of method + normalized path.
        operation_id: spec operation id when present.
        documented: spec-derived versus discovered.
        deprecated: spec deprecation marker.
        tags: spec tags.
        content_type / response_content_type: observed content types.
        auth_required: whether authentication appears required.
        pagination: ``none``/``page``/``cursor``/``offset``.
        has_filters: whether list filtering appears supported.
        rate_limit_hint: ``none``/``declared``/``observed``.
        parameter_count: number of persisted parameters.
        security_schemes: referenced security scheme names.
        confidence: intelligence confidence in ``[0, 1]``.
        sources: provenance tool ids.

    """

    api_id: str = ""
    host_id: str = ""
    method: str = "GET"
    path: str = ""
    normalized_path: str = ""
    path_hash: str = ""
    operation_id: str = ""
    documented: bool = False
    deprecated: bool = False
    tags: list[str] = field(default_factory=list)
    content_type: str = ""
    response_content_type: str = ""
    auth_required: bool = False
    pagination: str = "unknown"
    has_filters: bool = False
    rate_limit_hint: str = "none"
    parameter_count: int = 0
    security_schemes: list[str] = field(default_factory=list)
    confidence: float = 1.0
    sources: list[str] = field(default_factory=list)
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIParameter(TidbEntity):
    """An operation parameter.

    Attributes:
        operation_id: owning :class:`APIOperation` record id.
        name: parameter name.
        location: ``query``/``path``/``header``/``cookie``/``body``.
        required: whether the parameter is required.
        param_type: canonical type (``string``/``integer``/.../enum name).
        schema_digest: digest of the parameter schema.
        nullable: whether the parameter may be null.
        default_value: default when declared.
        enum_values: finite allowed values.
        pattern: regex pattern when present.
        source: ``spec``/``web``/``js``.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    operation_id: str = ""
    name: str = ""
    location: str = "query"
    required: bool = False
    param_type: str = "string"
    schema_digest: str = ""
    nullable: bool = False
    default_value: str | None = None
    enum_values: list[str] = field(default_factory=list)
    pattern: str | None = None
    source: str = "spec"
    confidence: float = 1.0
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APISchema(TidbEntity):
    """A request/response schema fingerprint (bounded, hashed).

    Attributes:
        operation_id: owning operation when operation-scoped.
        api_id: owning API when API-global.
        name: schema/component name.
        direction: ``request``/``response``.
        kind: ``object``/``array``/``primitive``/``ref``.
        content_type: media type (``application/json``...).
        digest: SHA-256 of the normalized model.
        depth: bounded traversal depth.
        fields: flattened field table (name, type, required, nullable, nested digest).
        source: ``spec``/``web``/``js``.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    operation_id: str | None = None
    api_id: str | None = None
    name: str = ""
    direction: str = "response"
    kind: str = "object"
    content_type: str = ""
    digest: str = ""
    depth: int = 0
    fields: list[dict[str, object]] = field(default_factory=list)
    source: str = "spec"
    confidence: float = 1.0
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIAuthentication(TidbEntity):
    """An authentication scheme observed on an API host.

    Attributes:
        api_id: owning API version when version-scoped.
        host_id: owning API host.
        scheme_type: ``basic``/``bearer``/``apikey``/``oauth2``/``oidc``/
            ``session``/``cookie``/``mutual-tls``/``none``.
        name: scheme name from a spec.
        token_location: ``header``/``query``/``cookie``.
        flows: OAuth2 flows present.
        scopes: declared scopes.
        indicators: evidence strings that triggered the scheme.
        confidence: intelligence confidence in ``[0, 1]``.
        documented: whether a spec declared the scheme.
        source: ``spec``/``web``/``js``/``tidb``.

    """

    api_id: str | None = None
    host_id: str | None = None
    scheme_type: str = "none"
    name: str = ""
    token_location: str = "header"
    flows: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    confidence: float = 1.0
    documented: bool = False
    source: str = "spec"
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIAuthorization(TidbEntity):
    """An authorization model indicator on an API host.

    Attributes:
        api_id: owning API version when version-scoped.
        model_type: ``rbac``/``abac``/``acl``/``scopes``/``none``/``unknown``.
        roles: observed role names.
        scopes: observed OAuth scopes.
        indicators: evidence strings.
        confidence: intelligence confidence in ``[0, 1]``.
        source: ``spec``/``web``/``js``/``tidb``.

    """

    api_id: str | None = None
    model_type: str = "unknown"
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    confidence: float = 1.0
    source: str = "spec"
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIRateLimit(TidbEntity):
    """Rate-limit indicators observed on an API host.

    Attributes:
        api_id: owning API version when version-scoped.
        host_id: owning API host.
        style: ``header``/``token-bucket``/``fixed-window``/``unknown``.
        headers: observed rate-limit header names.
        declared: limit text from spec/docs.
        confidence: intelligence confidence in ``[0, 1]``.
        source: ``spec``/``web``/``tidb``.

    """

    api_id: str | None = None
    host_id: str | None = None
    style: str = "unknown"
    headers: list[str] = field(default_factory=list)
    declared: str = ""
    confidence: float = 0.5
    source: str = "web"
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIPagination(TidbEntity):
    """Pagination style observed on an endpoint/API.

    Attributes:
        api_id: owning API version.
        operation_id: owning operation.
        style: ``none``/``page``/``cursor``/``offset``/``unknown``.
        limit_param: observed limit parameter name.
        offset_param / cursor_param: observed offset/cursor parameter names.
        total_source: ``body``/``header``/``unknown``.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    api_id: str | None = None
    operation_id: str | None = None
    style: str = "unknown"
    limit_param: str = ""
    offset_param: str | None = None
    cursor_param: str | None = None
    total_source: str = "unknown"
    confidence: float = 0.5
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIFilter(TidbEntity):
    """Filter capabilities observed on a list endpoint.

    Attributes:
        operation_id: owning operation.
        filter_param: filter parameter name.
        style: ``query``/``field``/``expression``/``unknown``.
        operators: observed filter operators.
        confidence: intelligence confidence in ``[0, 1]``.

    """

    operation_id: str = ""
    filter_param: str = ""
    style: str = "unknown"
    operators: list[str] = field(default_factory=list)
    confidence: float = 0.5
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIEvidence(TidbEntity):
    """One piece of evidence backing API intelligence.

    Attributes:
        subject_type: ``host``/``spec``/``version``/``operation``/``parameter``/
            ``auth``.
        subject_id: owning record id.
        evidence_type: ``spec-document``/``http-header``/``html``/``script``/
            ``tidb-intelligence``/``tool-output``/``known-signature``.
        value: evidence value.
        source: provenance.
        strength: ``strong``/``moderate``/``weak``.
        tool_id: producing tool.
        detail: detail text.
        integrity: optional content hash.

    """

    subject_type: str = "operation"
    subject_id: str = ""
    evidence_type: str = "tidb-intelligence"
    value: str = ""
    source: str = "api"
    strength: str = "moderate"
    tool_id: str = ""
    detail: str = ""
    integrity: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class APIConflict(TidbEntity):
    """A preserved contradiction in API intelligence evidence.

    Attributes:
        subject: affected key (host/api/operation).
        subject_type: ``host``/``api``/``version``/``operation``.
        conflict_type: ``version``/``identity``/``source``/``method``.
        observations: disagreeing observations.
        selected: canonical value selected.
        selected_source: source of the selected value.
        reason: selection rationale.
        confidence: selection confidence.
        mission_id / correlation_id: provenance.

    """

    subject: str = ""
    subject_type: str = "operation"
    conflict_type: str = "identity"
    observations: list[dict[str, object]] = field(default_factory=list)
    selected: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class APIChange(TidbEntity):
    """A detected temporal change in the API surface.

    Attributes:
        subject_type: affected record class.
        subject: canonical subject key.
        change_type: ``added``/``removed``/``changed``.
        previous / current: values.
        tool_id: producing tool.
        confidence: change confidence.
        mission_id / correlation_id: provenance.

    """

    subject_type: str = "operation"
    subject: str = ""
    change_type: str = "changed"
    previous: str = ""
    current: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""
