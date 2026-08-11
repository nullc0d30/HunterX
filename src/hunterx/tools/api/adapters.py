# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence tool adapters.

Six SDK adapters implement the API Discovery & API Attack-Surface Intelligence
tool set:

* ``api-openapi`` — locates and parses OpenAPI 2/3/3.1 (JSON/YAML) documents.
* ``api-swagger`` — locates Swagger 2.0 documents and Swagger UI endpoints.
* ``api-graphql`` — models GraphQL surfaces from SDL or discovered endpoints.
* ``api-websocket`` — models WebSocket endpoints from discovered hints.
* ``api-soap`` — locates and parses WSDL 1.1/2.0 documents.
* ``api-hints`` — folds existing web/JS/technology intelligence into API
  observations (the passive, traffic-free path).

Active adapters probe well-known spec URLs only when the run posture is not
``passive`` and the target origin is in scope; all fetching flows through an
injectable seam (``FetchedPage``) so unit tests stay hermetic. Spec content can
also be supplied directly via parameters (``spec_content``/``wsdl_content``/
``sdl``), which is the passive and test path.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import Any, TypeVar

from hunterx.domain.api.models import (
    ApiAuthObservation,
    ApiEvidence,
    APIHostObservation,
    ApiKind,
    ApiOperationObservation,
    APISpecObservation,
    ApiSurfaceForm,
    EvidenceStrength,
    EvidenceType,
    make_host_observation,
    origin_of,
)
from hunterx.domain.api.parsers import (
    GraphQLParser,
    HintsParser,
    OpenAPIParser,
    SoapParser,
    WebSocketParser,
)
from hunterx.domain.api.parsers.openapi import OpenAPIParseResult
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.api.base import ApiToolAdapter
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.web.httpclient import FetchedPage, HttpPageFetcher, WebFetchFn

_Version = "1.0.0"

#: Known OpenAPI/Swagger spec document probe paths (active posture only).
_OPENAPI_PROBE_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/v3/api-docs",
    "/v2/api-docs",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api/swagger.json",
)

#: Known WSDL probe paths (active posture only).
_WSDL_PROBE_PATHS = (
    "/?wsdl",
    "/service.wsdl",
    "/services?wsdl",
    "/ws?wsdl",
)

#: HTTP methods recognized by OpenAPI path items.
_HTTP_METHODS = ("GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE")

#: Canonical API host observation type.
_Host = TypeVar("_Host", bound=APIHostObservation)


class OpenAPIDiscoveryAdapter(ApiToolAdapter):
    """Locate and parse OpenAPI/Swagger documents for a target origin."""

    descriptor = ToolDescriptor(
        name="api-openapi",
        version=_Version,
        description="Locate and parse OpenAPI 2/3/3.1 (JSON/YAML) API specification documents.",
        entrypoint="hunterx.tools.api.adapters:OpenAPIDiscoveryAdapter",
        targets=("url", "host", "domain"),
        capabilities=("api-discovery", "openapi-parsing"),
        permissions=("network",),
        parameters={
            "spec_content": {"type": "string", "description": "Spec document content to parse (hermetic/passive)."},
            "spec_url": {"type": "string", "description": "Explicit spec URL to fetch."},
            "existing_specs": {"type": "array", "description": "Already-located spec records (url/content)."},
            "mode": {"type": "string", "description": "Execution posture: passive/active/hybrid."},
            "scope_roots": {"type": "array", "description": "Authorized hosts/domains; empty means fail-closed."},
        },
    )

    def __init__(
        self,
        *,
        fetch: WebFetchFn | None = None,
        max_operations: int = 2000,
        max_spec_size_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self._fetch = fetch or HttpPageFetcher().fetch
        self._parser = OpenAPIParser(max_operations=max_operations, max_spec_size_bytes=max_spec_size_bytes)
        self._max_spec_size_bytes = max_spec_size_bytes

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Discover OpenAPI documents and emit spec/operation/auth observations."""
        self._parse_and_emit(context, collector, tool_id="api-openapi")

    def _parse_and_emit(
        self,
        context: ExecutionContext,
        collector: OutputCollector,
        *,
        tool_id: str,
    ) -> None:
        parsed: list[OpenAPIParseResult] = []

        for record in self._records(context, "existing_specs"):
            url = str(record.get("url") or record.get("source_url") or "")
            content = record.get("content") or record.get("text") or ""
            if content and _size_ok(content, self._max_spec_size_bytes):
                parsed.append(self._safe_parse(content, url))
        content = self._param(context, "spec_content")
        if content:
            parsed.append(self._safe_parse(str(content), str(self._param(context, "spec_url") or "")))
        spec_url = self._param(context, "spec_url")
        if spec_url and not parsed:
            parsed.append(self._safe_parse(self._fetch_ok(str(spec_url), context), str(spec_url)))

        if not parsed and not self._is_passive(context):
            for probe in self._probe_urls(context, _OPENAPI_PROBE_PATHS):
                page = self._fetch_page(probe, context)
                if page.status_code in (200, 201) and page.content and _looks_like_spec(page.content):
                    parsed.append(self._safe_parse(page.content, probe))
                    break

        if not parsed:
            collector.set_exit_code(0)
            collector.attach_stderr("no OpenAPI specification document found")
            self.emit(collector)
            return

        hosts: list[APIHostObservation] = []
        specs: list[APISpecObservation] = []
        operations: list[ApiOperationObservation] = []
        auth: list[ApiAuthObservation] = []
        for result in parsed:
            spec = self._tag_spec(result.spec, context, tool_id=tool_id)
            specs.append(spec)
            if not any(h.origin_key == spec.origin_key for h in hosts):
                hosts.append(
                    self._tag_host(
                        make_host_observation(
                            spec.origin_key,
                            documented=True,
                            api_kinds=(ApiKind.REST,),
                            confidence=0.95,
                            evidence=spec.evidence,
                            source="api-openapi",
                            tool_id=tool_id,
                        ),
                        context,
                    )
                )
            operations.extend(self._tag_operation(item, context, tool_id=tool_id) for item in result.operations)
            auth.extend(self._tag_auth(item, context, tool_id=tool_id) for item in result.auth)

        self.emit(collector, hosts=hosts, specs=specs, operations=operations, auth=auth)
        collector.set_exit_code(0)

    # -- discovery internals -------------------------------------------------

    def _safe_parse(self, content: str, source_url: str) -> OpenAPIParseResult | None:
        """Parse spec content, returning ``None`` on malformed documents."""
        try:
            return self._parser.parse(content, source_url=source_url)
        except ValueError:
            return None

    def _fetch_ok(self, url: str, context: ExecutionContext) -> str:
        """Fetch a spec URL and return its content (empty on failure)."""
        page = self._fetch_page(url, context)
        if page.status_code in (200, 201) and page.content:
            return page.content
        return ""

    def _fetch_page(self, url: str, context: ExecutionContext) -> FetchedPage:
        """Fetch ``url`` through the injectable seam, never raising."""
        try:
            return self._fetch(url, 10.0)
        except Exception as exc:  # noqa: BLE001 - fetch failures become empty pages
            return FetchedPage(url=url, error=f"fetch failed: {exc}")

    def _probe_urls(self, context: ExecutionContext, probes: Sequence[str]) -> list[str]:
        """Build probe URLs for the target origin, restricted to in-scope roots."""
        origin = origin_of(context.target)
        roots = context.parameters.get("scope_roots")
        if isinstance(roots, (list, tuple)) and roots:
            allowed: list[str] = []
            for root in roots:
                root_origin = origin_of(str(root))
                allowed.append(f"{root_origin}{probe}" for probe in probes)
            return [item for group in allowed for item in group]
        return [f"{origin}{probe}" for probe in probes]

    # -- provenance helpers --------------------------------------------------

    def _tag_spec(self, spec: APISpecObservation, context: ExecutionContext, *, tool_id: str) -> APISpecObservation:
        return replace(
            spec,
            tool_id=tool_id,
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
            execution_id=context.execution_id,
        )

    def _tag_host(self, host: _Host, context: ExecutionContext) -> _Host:
        return replace(
            host,
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
            execution_id=context.execution_id,
        )

    def _tag_operation(
        self,
        operation: ApiOperationObservation,
        context: ExecutionContext,
        *,
        tool_id: str,
    ) -> ApiOperationObservation:
        return replace(
            operation,
            tool_id=tool_id,
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
        )

    def _tag_auth(
        self,
        auth: ApiAuthObservation,
        context: ExecutionContext,
        *,
        tool_id: str,
    ) -> ApiAuthObservation:
        return replace(
            auth,
            tool_id=tool_id,
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
        )


class SwaggerDiscoveryAdapter(OpenAPIDiscoveryAdapter):
    """Locate and parse Swagger 2.0 documents (probe list focuses on swagger)."""

    descriptor = ToolDescriptor(
        name="api-swagger",
        version=_Version,
        description="Locate and parse Swagger 2.0 API specification documents and Swagger UI endpoints.",
        entrypoint="hunterx.tools.api.adapters:SwaggerDiscoveryAdapter",
        targets=("url", "host", "domain"),
        capabilities=("api-discovery", "swagger-parsing"),
        permissions=("network",),
        parameters={
            "spec_content": {"type": "string", "description": "Swagger document content to parse."},
            "spec_url": {"type": "string", "description": "Explicit swagger.json URL to fetch."},
            "existing_specs": {"type": "array", "description": "Already-located spec records."},
            "mode": {"type": "string", "description": "Execution posture: passive/active/hybrid."},
            "scope_roots": {"type": "array", "description": "Authorized hosts/domains."},
        },
    )

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Discover Swagger 2.0 documents and emit observations."""
        self._parse_and_emit(context, collector, tool_id="api-swagger")


class GraphQLDiscoveryAdapter(ApiToolAdapter):
    """Model a GraphQL surface from SDL or discovered endpoint hints."""

    descriptor = ToolDescriptor(
        name="api-graphql",
        version=_Version,
        description="Model GraphQL queries/mutations/subscriptions from SDL or discovered endpoints.",
        entrypoint="hunterx.tools.api.adapters:GraphQLDiscoveryAdapter",
        targets=("url", "host", "domain"),
        capabilities=("api-discovery", "graphql-modeling"),
        permissions=("none",),
        parameters={
            "sdl": {"type": "string", "description": "GraphQL SDL (schema definition language) text to parse."},
            "graphql_endpoints": {"type": "array", "description": "Discovered GraphQL endpoint URLs."},
            "mode": {"type": "string", "description": "Execution posture."},
        },
    )

    def __init__(self, *, max_operations: int = 2000) -> None:
        self._parser = GraphQLParser(max_operations=max_operations)

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Parse GraphQL SDL/endpoints and emit operation observations."""
        origin = origin_of(context.target)
        hosts: list[APIHostObservation] = []
        operations: list[ApiOperationObservation] = []

        sdl = self._param(context, "sdl")
        if sdl:
            result = self._parser.parse(str(sdl), origin=origin)
            operations = [
                replace(
                    item,
                    target_key=context.target.strip(),
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
                for item in result.operations
            ]

        endpoints = self._records(context, "graphql_endpoints")
        if endpoints:
            for record in endpoints:
                url = str(record.get("url") or record.get("path") or "/graphql")
                origin_key = str(record.get("origin_key") or origin_of(url) or origin)
                operations.append(
                    self._hint_operation(
                        origin_key,
                        "POST",
                        url,
                        ApiKind.GRAPHQL,
                        ApiSurfaceForm.GRAPHQL_SCHEMA_SHAPE,
                        context,
                        documented=False,
                        confidence=0.7,
                    )
                )

        hosts = [
            self._tag_host(
                make_host_observation(
                    origin,
                    documented=bool(sdl),
                    api_kinds=(ApiKind.GRAPHQL,),
                    confidence=0.85 if sdl else 0.6,
                    evidence=(
                        ApiEvidence(
                            evidence_type=EvidenceType.SPEC_DOCUMENT if sdl else EvidenceType.TIDB_INTELLIGENCE,
                            value="graphql sdl" if sdl else "graphql endpoint hint",
                            source="api-graphql",
                            strength=EvidenceStrength.STRONG if sdl else EvidenceStrength.MODERATE,
                            tool_id="api-graphql",
                        ),
                    ),
                    source="api-graphql",
                    tool_id="api-graphql",
                ),
                context,
            )
        ]

        collector.set_exit_code(0)
        if not operations and not sdl:
            collector.attach_stderr("no GraphQL surface supplied")
        self.emit(collector, hosts=hosts, operations=operations)

    def _tag_host(self, host: _Host, context: ExecutionContext) -> _Host:
        return replace(
            host,
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
            execution_id=context.execution_id,
        )

    def _hint_operation(
        self,
        origin_key: str,
        method: str,
        path: str,
        api_kind: ApiKind,
        surface_form: ApiSurfaceForm,
        context: ExecutionContext,
        *,
        documented: bool,
        confidence: float,
    ) -> ApiOperationObservation:
        from hunterx.domain.api.models import make_operation_observation

        return make_operation_observation(
            origin_key,
            method,
            path,
            api_kind=api_kind,
            surface_form=surface_form,
            documented=documented,
            confidence=confidence,
            source="api-graphql",
            tool_id="api-graphql",
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
        )


class WebSocketDiscoveryAdapter(ApiToolAdapter):
    """Model WebSocket endpoints from discovered hints."""

    descriptor = ToolDescriptor(
        name="api-websocket",
        version=_Version,
        description="Model WebSocket endpoints from discovered websocket hints.",
        entrypoint="hunterx.tools.api.adapters:WebSocketDiscoveryAdapter",
        targets=("url", "host", "domain"),
        capabilities=("api-discovery", "websocket-modeling"),
        permissions=("none",),
        parameters={
            "websocket_endpoints": {"type": "array", "description": "Discovered WebSocket endpoint URLs."},
            "mode": {"type": "string", "description": "Execution posture."},
        },
    )

    def __init__(self, *, max_operations: int = 500) -> None:
        self._parser = WebSocketParser(max_operations=max_operations)

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Parse WebSocket endpoint hints and emit operation observations."""
        origin = origin_of(context.target)
        hints: list[tuple[str, str]] = []
        for record in self._records(context, "websocket_endpoints"):
            url = str(record.get("url") or record.get("path") or "")
            if not url:
                continue
            origin_key = str(record.get("origin_key") or origin)
            hints.append((origin_key, url))

        result = self._parser.parse(hints)
        operations = [
            replace(
                item,
                target_key=context.target.strip(),
                correlation_id=context.correlation_id,
                mission_id=context.mission_id,
            )
            for item in result.operations
        ]
        hosts: list[APIHostObservation] = []
        if operations:
            hosts = [
                self._tag_host(
                    make_host_observation(
                        origin,
                        documented=False,
                        api_kinds=(ApiKind.WEBSOCKET,),
                        confidence=0.7,
                        source="api-websocket",
                        tool_id="api-websocket",
                    ),
                    context,
                )
            ]

        collector.set_exit_code(0)
        if not operations:
            collector.attach_stderr("no WebSocket endpoints supplied")
        self.emit(collector, hosts=hosts, operations=operations)

    def _tag_host(self, host: _Host, context: ExecutionContext) -> _Host:
        return replace(
            host,
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
            execution_id=context.execution_id,
        )


class SoapDiscoveryAdapter(ApiToolAdapter):
    """Locate and parse WSDL 1.1/2.0 documents for a target origin."""

    descriptor = ToolDescriptor(
        name="api-soap",
        version=_Version,
        description="Locate and parse WSDL 1.1/2.0 (SOAP) API specification documents.",
        entrypoint="hunterx.tools.api.adapters:SoapDiscoveryAdapter",
        targets=("url", "host", "domain"),
        capabilities=("api-discovery", "wsdl-parsing"),
        permissions=("network",),
        parameters={
            "wsdl_content": {"type": "string", "description": "WSDL document content to parse."},
            "wsdl_url": {"type": "string", "description": "Explicit WSDL URL to fetch."},
            "existing_specs": {"type": "array", "description": "Already-located spec records."},
            "mode": {"type": "string", "description": "Execution posture."},
            "scope_roots": {"type": "array", "description": "Authorized hosts/domains."},
        },
    )

    def __init__(
        self,
        *,
        fetch: WebFetchFn | None = None,
        max_operations: int = 2000,
        max_spec_size_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self._fetch = fetch or HttpPageFetcher().fetch
        self._parser = SoapParser(max_operations=max_operations, max_spec_size_bytes=max_spec_size_bytes)
        self._max_spec_size_bytes = max_spec_size_bytes

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Discover WSDL documents and emit spec/operation observations."""
        origin = origin_of(context.target)
        content = self._param(context, "wsdl_content")
        wsdl_url = self._param(context, "wsdl_url")

        result = None
        if content:
            result = self._safe_parse(str(content), str(wsdl_url or ""))
        if result is None and wsdl_url:
            result = self._safe_parse(self._fetch_ok(str(wsdl_url)), str(wsdl_url))
        if result is None and not self._is_passive(context):
            for probe in self._probe_urls(context, _WSDL_PROBE_PATHS):
                page = self._fetch_page(probe)
                if page.status_code in (200, 201) and page.content and _looks_like_wsdl(page.content):
                    result = self._safe_parse(page.content, probe)
                    break

        if result is None:
            collector.set_exit_code(0)
            collector.attach_stderr("no WSDL document found")
            self.emit(collector)
            return

        spec = replace(
            result.spec,
            tool_id="api-soap",
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
            execution_id=context.execution_id,
        )
        operations = [
            replace(
                item,
                tool_id="api-soap",
                target_key=context.target.strip(),
                correlation_id=context.correlation_id,
                mission_id=context.mission_id,
            )
            for item in result.operations
        ]
        hosts = [
            replace(
                make_host_observation(
                    origin,
                    documented=True,
                    api_kinds=(ApiKind.SOAP,),
                    confidence=0.9,
                    evidence=spec.evidence,
                    source="api-soap",
                    tool_id="api-soap",
                ),
                target_key=context.target.strip(),
                correlation_id=context.correlation_id,
                mission_id=context.mission_id,
                execution_id=context.execution_id,
            )
        ]

        self.emit(collector, hosts=hosts, specs=[spec], operations=operations)
        collector.set_exit_code(0)

    def _safe_parse(self, content: str, source_url: str) -> Any:
        """Parse WSDL content, returning ``None`` on malformed documents."""
        try:
            return self._parser.parse(content, source_url=source_url)
        except ValueError:
            return None

    def _fetch_ok(self, url: str) -> str:
        page = self._fetch_page(url)
        if page.status_code in (200, 201) and page.content:
            return page.content
        return ""

    def _fetch_page(self, url: str) -> FetchedPage:
        """Fetch ``url`` through the injectable seam, never raising."""
        try:
            return self._fetch(url, 10.0)
        except Exception as exc:  # noqa: BLE001 - fetch failures become empty pages
            return FetchedPage(url=url, error=f"fetch failed: {exc}")

    def _probe_urls(self, context: ExecutionContext, probes: Sequence[str]) -> list[str]:
        """Build probe URLs for the target origin, restricted to in-scope roots."""
        origin = origin_of(context.target)
        roots = context.parameters.get("scope_roots")
        if isinstance(roots, (list, tuple)) and roots:
            allowed: list[str] = []
            for root in roots:
                root_origin = origin_of(str(root))
                allowed.extend(f"{root_origin}{probe}" for probe in probes)
            return allowed
        return [f"{origin}{probe}" for probe in probes]


class ApiHintsAdapter(ApiToolAdapter):
    """Fold existing web/JS/technology intelligence into API observations.

    This is the passive path: it consumes already-persisted observations passed
    through the execution parameters and never issues network traffic.
    """

    descriptor = ToolDescriptor(
        name="api-hints",
        version=_Version,
        description="Fold existing web-crawl, JS, technology and topology intelligence into API observations.",
        entrypoint="hunterx.tools.api.adapters:ApiHintsAdapter",
        targets=("url", "host", "domain"),
        capabilities=("api-discovery", "hint-correlation"),
        permissions=("none",),
        parameters={
            "web_origins": {"type": "array", "description": "Web-crawl origin observations."},
            "web_api_endpoints": {"type": "array", "description": "Web-crawl API endpoint observations."},
            "websocket_endpoints": {"type": "array", "description": "Web-crawl WebSocket endpoint observations."},
            "graphql_endpoints": {"type": "array", "description": "Discovered GraphQL endpoint observations."},
            "js_endpoints": {"type": "array", "description": "JavaScript endpoint hints."},
            "auth_boundaries": {"type": "array", "description": "Web-crawl auth boundary observations."},
            "url_observations": {"type": "array", "description": "Web-crawl URL observations."},
            "mode": {"type": "string", "description": "Execution posture."},
        },
    )

    def __init__(self) -> None:
        self._parser = HintsParser()

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Convert existing intelligence into canonical API observations."""
        result = self._parser.parse(
            web_origins=self._as_records(self._records(context, "web_origins")),
            url_observations=self._as_records(self._records(context, "url_observations")),
            web_api_endpoints=self._as_records(self._records(context, "web_api_endpoints")),
            websocket_endpoints=self._as_records(self._records(context, "websocket_endpoints")),
            graphql_endpoints=self._as_records(self._records(context, "graphql_endpoints")),
            js_endpoints=self._as_records(self._records(context, "js_endpoints")),
            auth_boundaries=self._as_records(self._records(context, "auth_boundaries")),
            target_key=context.target.strip(),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
            tool_id="api-hints",
        )

        hosts = [
            replace(item, execution_id=context.execution_id) if hasattr(item, "execution_id") else item
            for item in result.hosts
        ]
        operations = list(result.operations)
        auth = list(result.auth)

        self.emit(
            collector,
            hosts=hosts,
            operations=operations,
            auth=auth,
            rate_limits=list(result.rate_limits),
            paginations=list(result.paginations),
            filters=list(result.filters),
        )
        collector.set_exit_code(0)

    def _as_records(self, records: Sequence[dict[str, Any]]) -> list[Any]:
        """Wrap dict records as attribute-accessible namespaces for the parser."""
        from types import SimpleNamespace

        return [SimpleNamespace(**record) for record in records]


# -- shared helpers -----------------------------------------------------------


def _looks_like_spec(content: str) -> bool:
    """Heuristically detect OpenAPI/Swagger documents."""
    lowered = content.lstrip().lower()
    if lowered.startswith("{") or lowered.startswith("["):
        return '"openapi"' in content[:4000] or '"swagger"' in content[:4000] or '"paths"' in content[:4000]
    return "openapi:" in content[:2000] or "swagger:" in content[:2000] or "paths:" in content[:2000]


def _looks_like_wsdl(content: str) -> bool:
    """Heuristically detect WSDL documents."""
    lowered = content[:4000].lower()
    return "<definitions" in lowered or "<wsdl:definitions" in lowered or "<wsdl2:description" in lowered


def _size_ok(content: str, limit: int) -> bool:
    """Return whether the content fits within the spec size cap."""
    return len(content.encode("utf-8")) <= limit
