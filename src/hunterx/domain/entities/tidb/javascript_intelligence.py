# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript intelligence TIDB entities.

System-of-record entities for the JavaScript Intelligence & Client-Side
Attack-Surface Discovery capability: the per-asset acquisition records, the
correlated findings (endpoints, routes, authentication references, external
domains, third-party services, storage, secrets, technology, dependencies,
configuration, workers, WebAssembly, security APIs, dynamic imports), and the
derived intelligence (conflicts, changes and run records). All JavaScript
intelligence that matters is persisted here — never only in memory, logs or
reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class JSIntelligenceAsset(TidbEntity):
    """A persisted JavaScript asset acquisition.

    Attributes:
        url: canonical URL of the resource (``""`` for inline).
        origin: ``scheme://host[:port]`` of the resource.
        parent_url: page that referenced the script.
        asset_kind: ``external``/``inline``/``bundle``/``chunk``/...
        content_hash: SHA-256 of the content (deduplication key).
        size: analysed content size in bytes.
        status_code / content_type / etag / last_modified: acquisition metadata.
        sha256: SHA-256 digest of the resource.
        source: upstream source (crawl/katana/inline/manual).
        tool_id / target_key / execution_id / correlation_id / mission_id:
            run provenance.

    """

    url: str = ""
    origin: str = ""
    parent_url: str = ""
    asset_kind: str = "external"
    content_hash: str = ""
    size: int = 0
    status_code: int | None = None
    content_type: str = ""
    etag: str = ""
    last_modified: str = ""
    sha256: str = ""
    source: str = "crawl"
    tool_id: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceEndpoint(TidbEntity):
    """A persisted client-side endpoint reference.

    Attributes:
        url: extracted URL or path.
        method: HTTP method when observable.
        kind: ``fetch``/``xhr``/``axios``/``websocket``/``graphql``/...
        api_type: REST/GraphQL/WebSocket/SSE/base.
        base_url: detected API base URL when distinct.
        parameters / headers: observed names.
        confidence: intelligence confidence in ``[0, 1]``.
        evidence: evidence fragments (locations).
        asset_url / target_key / execution_id / correlation_id / mission_id:
            provenance.

    """

    url: str = ""
    method: str = "GET"
    kind: str = "fetch"
    api_type: str = "rest"
    base_url: str = ""
    parameters: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceRoute(TidbEntity):
    """A persisted client route reference.

    Attributes:
        route: extracted route pattern.
        pattern: normalised pattern (param markers kept).
        parameters: parameter names embedded in the pattern.
        framework: routing framework.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    route: str = ""
    pattern: str = ""
    parameters: list[str] = field(default_factory=list)
    framework: str = "other"
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceAuth(TidbEntity):
    """A persisted authentication reference.

    Attributes:
        kind: auth reference kind (login/token/oauth/oidc/saml/...).
        value: the referenced value.
        mechanism: scheme/flow observed.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    kind: str = "other"
    value: str = ""
    mechanism: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceDomain(TidbEntity):
    """A persisted external domain reference.

    Attributes:
        domain: canonical lowercase domain.
        relation: same-origin/same-organization/third-party.
        hostname: full referenced hostname.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    domain: str = ""
    relation: str = "unknown"
    hostname: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceService(TidbEntity):
    """A persisted third-party service reference.

    Attributes:
        provider: provider name.
        service: service/product name.
        category: canonical category (analytics/cdn/payment/...).
        domain: referenced provider domain.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    provider: str = ""
    service: str = ""
    category: str = "other"
    domain: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceStorage(TidbEntity):
    """A persisted client-side storage indicator.

    Attributes:
        storage_type: local/session/indexed-db/cookie/cache.
        key_pattern: referenced key (never a value).
        usage_context: set/get/remove/open.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    storage_type: str = "local-storage"
    key_pattern: str = ""
    usage_context: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceSecret(TidbEntity):
    """A persisted secret indicator — never containing a raw value.

    Attributes:
        classification: secret classification.
        masked_value: masked preview (first chars + ``***``).
        value_hash: SHA-256 of the candidate.
        location / file / line / offset: detection location.
        detection_rule: matching rule id.
        confidence / tier / reasoning: intelligence metadata.
        asset_url / target_key / execution_id / correlation_id / mission_id:
            provenance.

    """

    classification: str = "generic-secret"
    masked_value: str = ""
    value_hash: str = ""
    location: str = ""
    file: str = ""
    line: int | None = None
    offset: int = -1
    detection_rule: str = ""
    confidence: float = 0.5
    tier: str = "low"
    reasoning: str = ""
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceTechnology(TidbEntity):
    """A persisted technology detection.

    Attributes:
        name: canonical technology name.
        kind: framework/library/bundler/transpiler/tooling/runtime.
        version: detected version (``""`` when unknown).
        version_confidence: confirmed/probable/range/unknown.
        category: taxonomy category hint.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    name: str = ""
    kind: str = "library"
    version: str = ""
    version_confidence: str = "unknown"
    category: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceDependency(TidbEntity):
    """A persisted package/dependency indicator.

    Attributes:
        name: package name.
        version: version when determinable.
        source: import/require/cdn.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    name: str = ""
    version: str = ""
    source: str = "import"
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceConfiguration(TidbEntity):
    """A persisted client-side configuration indicator.

    Attributes:
        kind: configuration kind (api-base-url/feature-flag/environment/...).
        key: configuration key/name.
        value: value (masked when potentially sensitive).
        environment: detected environment.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    kind: str = "other"
    key: str = ""
    value: str = ""
    environment: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceWorker(TidbEntity):
    """A persisted worker/service-worker reference.

    Attributes:
        kind: worker/service-worker/shared-worker.
        url: worker script URL.
        registration_context: construct/register.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    kind: str = "worker"
    url: str = ""
    registration_context: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceWasm(TidbEntity):
    """A persisted WebAssembly reference.

    Attributes:
        kind: instantiate/instantiate-streaming/resource.
        url: referenced ``.wasm`` URL when observable.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    kind: str = "resource"
    url: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceSecurity(TidbEntity):
    """A persisted security-relevant API usage (intelligence only).

    Attributes:
        api: the API kind (innerHTML/eval/postMessage/...).
        context: short masked context.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    api: str = ""
    context: str = ""
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceImport(TidbEntity):
    """A persisted dynamic import / lazy-chunk reference.

    Attributes:
        specifier: module name or path.
        url: resolved URL when determinable.
        chunk: whether the reference looks like a bundler chunk.
        confidence / evidence / asset_url / provenance: shared envelope.

    """

    specifier: str = ""
    url: str = ""
    chunk: bool = False
    confidence: float = 1.0
    evidence: list[dict[str, object]] = field(default_factory=list)
    asset_url: str = ""
    target_key: str = ""
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class JSIntelligenceConflict(TidbEntity):
    """A preserved contradiction in JavaScript intelligence evidence.

    Attributes:
        subject: affected artifact identifier.
        artifact_type: artifact class that disagrees.
        observations: disagreeing observations (masked).
        selected: canonical value selected.
        reason: selection rationale.
        confidence: selection confidence.
        mission_id / correlation_id: provenance.

    """

    subject: str = ""
    artifact_type: str = ""
    observations: list[dict[str, object]] = field(default_factory=list)
    selected: str = ""
    reason: str = ""
    confidence: float = 0.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class JSIntelligenceChange(TidbEntity):
    """A detected temporal change in JavaScript state.

    Attributes:
        artifact_type: affected artifact class.
        subject: canonical subject key.
        change_type: added/removed/changed.
        previous / current: values.
        source: producing tool.
        mission_id / correlation_id: provenance.

    """

    artifact_type: str = ""
    subject: str = ""
    change_type: str = "changed"
    previous: str = ""
    current: str = ""
    source: str = ""
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class JSIntelligenceRun(TidbEntity):
    """Observability record for a JavaScript intelligence run.

    Attributes:
        mission_id: owning mission.
        target_key: canonical target the run covered.
        status: running/completed/failed/partial.
        assets / endpoints / routes / secrets / services / dependencies /
        technologies: per-kind finding counts.
        conflicts / changes: derived intelligence counts.
        started_at / completed_at / duration_ms: timing.
        summary: free-form run summary.
        correlation_id: correlation id of the run.

    """

    mission_id: str = ""
    target_key: str = ""
    status: str = "running"
    assets: int = 0
    endpoints: int = 0
    routes: int = 0
    secrets: int = 0
    services: int = 0
    dependencies: int = 0
    technologies: int = 0
    conflicts: int = 0
    changes: int = 0
    started_at: str = ""
    completed_at: str | None = None
    duration_ms: int = 0
    summary: dict[str, object] = field(default_factory=dict)
    correlation_id: str = ""
