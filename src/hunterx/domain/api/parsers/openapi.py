# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""OpenAPI / Swagger document parser.

In-process parser that normalizes OpenAPI 2.0 (``swagger``) and OpenAPI
3.0/3.1 (``openapi``) JSON/YAML documents into canonical API intelligence
observations: the located spec, endpoint operations with parameters, and
authentication/authorization schemes. Parsing is deterministic and bounded:
the document is parsed with ``pyyaml`` (JSON is a YAML subset) and schemas are
fingerprinted rather than stored in full.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml

from hunterx.domain.api.models import (
    ApiAuthObservation,
    ApiEvidence,
    ApiKind,
    ApiOperationObservation,
    ApiParameterObservation,
    APISpecObservation,
    ApiSurfaceForm,
    EvidenceStrength,
    EvidenceType,
    normalize_path,
    operation_hash,
)

#: HTTP methods recognized by OpenAPI path items.
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

#: Parameter locations allowed by the OpenAPI specification.
_PARAM_LOCATIONS = ("query", "header", "path", "cookie")


@dataclass(frozen=True, slots=True)
class OpenAPIParseResult:
    """The parsed contents of one OpenAPI/Swagger document.

    Attributes:
        spec: the located spec observation.
        operations: endpoint operations parsed from the document.
        auth: authentication/authorization schemes parsed from the document.

    """

    spec: APISpecObservation
    operations: tuple[ApiOperationObservation, ...] = ()
    auth: tuple[ApiAuthObservation, ...] = ()

    def __len__(self) -> int:
        """Return the number of operations."""
        return len(self.operations)


class OpenAPIParser:
    """Parse an OpenAPI 2/3/3.1 document into canonical observations.

    Usage::

        parser = OpenAPIParser()
        result = parser.parse(document_text, source_url="https://.../openapi.json")
    """

    def __init__(self, *, max_operations: int = 2000, max_spec_size_bytes: int = 5 * 1024 * 1024) -> None:
        self._max_operations = max_operations
        self._max_spec_size_bytes = max_spec_size_bytes

    def parse(self, document: str | bytes, *, source_url: str = "") -> OpenAPIParseResult:
        """Parse a JSON or YAML OpenAPI/Swagger document."""
        raw = _as_text(document)
        if len(raw.encode("utf-8")) > self._max_spec_size_bytes:
            raise ValueError(f"spec document exceeds size cap of {self._max_spec_size_bytes} bytes")
        data = _load_document(raw)
        return self.parse_mapping(data, source_url=source_url, raw=raw)

    def parse_mapping(
        self,
        data: Mapping[str, Any],
        *,
        source_url: str = "",
        raw: str | None = None,
    ) -> OpenAPIParseResult:
        """Parse a loaded OpenAPI document mapping."""
        spec_type = _detect_spec_type(data)
        title = str(data.get("info", {}).get("title") or "") if isinstance(data.get("info"), dict) else ""
        spec_version = str(data["info"].get("version") or "") if isinstance(data.get("info"), dict) else ""
        integrity = _content_hash(data, raw)
        size_bytes = len((raw or json.dumps(data)).encode("utf-8"))
        origin = _origin_from_servers(data, source_url)

        operations = self._parse_operations(data, origin, source_url)
        auth = self._parse_auth(origin, _security_schemes(data), source_url)
        components = data.get("components") if isinstance(data.get("components"), dict) else {}
        schema_count = _count_schemas(components)

        spec = APISpecObservation(
            source_url=source_url,
            spec_type=spec_type,
            format=_format_of(data, raw),
            spec_version=spec_version,
            title=title,
            operation_count=len(operations),
            schema_count=schema_count,
            integrity=integrity,
            size_bytes=size_bytes,
            origin_key=origin,
            confidence=1.0,
            evidence=(
                ApiEvidence(
                    evidence_type=EvidenceType.SPEC_DOCUMENT,
                    value=f"OpenAPI {spec_type} document",
                    source=source_url or "openapi",
                    strength=EvidenceStrength.STRONG,
                    tool_id="api-openapi",
                    integrity=integrity,
                ),
            ),
            source="api-openapi",
            tool_id="api-openapi",
        )

        return OpenAPIParseResult(
            spec=spec,
            operations=tuple(operations),
            auth=tuple(auth),
        )

    def _parse_operations(
        self,
        data: Mapping[str, Any],
        origin: str,
        source_url: str,
    ) -> list[ApiOperationObservation]:
        operations: list[ApiOperationObservation] = []
        paths = data.get("paths") or {}
        if not isinstance(paths, dict):
            return operations
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                    continue
                if len(operations) >= self._max_operations:
                    return operations
                operations.append(self._build_operation(path, method, operation, origin, source_url))
        return operations

    def _build_operation(
        self,
        path: str,
        method: str,
        operation: Mapping[str, Any],
        origin: str,
        source_url: str,
    ) -> ApiOperationObservation:
        normalized = normalize_path(path)
        parameters = self._parse_parameters(operation)
        security = operation.get("security") or []
        security_names = _security_names(security)
        deprecated = bool(operation.get("deprecated") or False)
        tags = tuple(str(item) for item in (operation.get("tags") or ()) if item)

        return ApiOperationObservation(
            origin_key=origin,
            method=method.upper(),
            path=path,
            normalized_path=normalized,
            path_hash=operation_hash(method, normalized),
            operation_id=str(operation.get("operationId") or ""),
            api_kind=ApiKind.REST,
            surface_form=ApiSurfaceForm.SWAGGER if _is_swagger2(operation) else ApiSurfaceForm.OPENAPI,
            documented=True,
            deprecated=deprecated,
            tags=tags,
            content_type=_request_media_type(operation),
            response_content_type=_response_media_type(operation),
            auth_required=bool(security_names),
            parameters=parameters,
            security_schemes=security_names,
            confidence=1.0,
            sources=(source_url or "api-openapi",),
            evidence=(
                ApiEvidence(
                    evidence_type=EvidenceType.SPEC_DOCUMENT,
                    value=f"openapi operation {method.upper()} {path}",
                    source=source_url or "openapi",
                    strength=EvidenceStrength.STRONG,
                    tool_id="api-openapi",
                ),
            ),
            source="api-openapi",
            tool_id="api-openapi",
        )

    def _parse_parameters(
        self,
        operation: Mapping[str, Any],
    ) -> tuple[ApiParameterObservation, ...]:
        parameters: list[ApiParameterObservation] = []
        raw = operation.get("parameters") or []
        if not isinstance(raw, list):
            return ()
        for item in raw:
            if not isinstance(item, dict):
                continue
            location = str(item.get("in") or "query").lower()
            if location not in _PARAM_LOCATIONS:
                location = "query"
            schema = item.get("schema") if isinstance(item.get("schema"), dict) else {}
            param_type = str(schema.get("type") or item.get("type") or "string")
            parameters.append(
                ApiParameterObservation(
                    name=str(item.get("name") or ""),
                    location=location,
                    required=bool(item.get("required") or False),
                    param_type=param_type,
                    schema_digest=_schema_digest(schema),
                    nullable=bool(schema.get("nullable") or False),
                    default_value=_stringify(schema.get("default")) or _stringify(item.get("default")),
                    enum_values=tuple(str(value) for value in schema.get("enum") or ()),
                    pattern=schema.get("pattern"),
                    source="spec",
                    confidence=1.0,
                )
            )
        return tuple(parameters)

    def _parse_auth(
        self,
        origin: str,
        security_schemes: Mapping[str, Mapping[str, Any]],
        source_url: str,
    ) -> list[ApiAuthObservation]:
        auth: list[ApiAuthObservation] = []
        for name, scheme in security_schemes.items():
            if not isinstance(scheme, dict):
                continue
            scheme_type = _scheme_type(scheme)
            token_location = "header"
            if scheme_type == "apikey":
                token_location = str(scheme.get("in") or "header")
            flows = tuple((scheme.get("flows") or {}).keys()) if scheme_type in ("oauth2", "oidc") else ()
            auth.append(
                ApiAuthObservation(
                    origin_key=origin,
                    scheme_type=scheme_type,
                    name=name,
                    token_location=token_location,
                    flows=flows,
                    documented=True,
                    indicators=(f"openapi security scheme {name}",),
                    confidence=1.0,
                    source="api-openapi",
                    tool_id="api-openapi",
                )
            )
        return auth


def _detect_spec_type(data: Mapping[str, Any]) -> str:
    """Detect the OpenAPI dialect (``swagger2``/``openapi3``/``openapi31``)."""
    if "swagger" in data:
        return "swagger2"
    openapi = str(data.get("openapi") or "")
    if openapi.startswith("3.1"):
        return "openapi31"
    return "openapi3"


def _is_swagger2(operation: Mapping[str, Any]) -> bool:
    """Swagger 2 operations use ``consumes``/``produces`` and inline types."""
    return "consumes" in operation or "produces" in operation


def _load_document(raw: str) -> Mapping[str, Any]:
    """Load a JSON or YAML document as a mapping."""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:  # pragma: no cover - defensive
        raise ValueError(f"invalid YAML document: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("OpenAPI document must be a mapping")
    return data


def _content_hash(data: Mapping[str, Any], raw: str | None) -> str:
    """Return a stable digest of the document content."""
    if raw is not None:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    canonical = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _origin_from_servers(data: Mapping[str, Any], source_url: str) -> str:
    """Derive the origin from servers/host fields or the source URL."""
    from urllib.parse import urlsplit

    servers = data.get("servers") or []
    if isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict) and server.get("url"):
                url = str(server["url"])
                if url.startswith(("http://", "https://")):
                    parts = urlsplit(url)
                    if parts.hostname:
                        return _origin_from_url(url)
    host = data.get("host")
    schemes = data.get("schemes") or ["https"]
    if host:
        scheme = "https"
        if isinstance(schemes, list) and schemes:
            scheme = str(schemes[0]).lower()
        return f"{scheme}://{str(host).lower()}"
    if source_url:
        return _origin_from_url(source_url)
    return "unknown"


def _origin_from_url(url: str) -> str:
    """Return the canonical origin of a URL."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:  # pragma: no cover - defensive
        return "unknown"
    if not parts.hostname:
        return "unknown"
    port = parts.port
    if port not in (None, 80, 443):
        return f"{parts.scheme}://{parts.hostname.lower()}:{port}"
    return f"{parts.scheme}://{parts.hostname.lower()}"


def _security_schemes(data: Mapping[str, Any]) -> dict[str, Any]:
    components = data.get("components")
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        return dict(components["securitySchemes"])
    if isinstance(data.get("securityDefinitions"), dict):
        return dict(data["securityDefinitions"])
    return {}


def _scheme_type(scheme: Mapping[str, Any]) -> str:
    """Normalize a security scheme to a canonical scheme type."""
    if scheme.get("type") == "apiKey":
        return "apikey"
    if scheme.get("type") == "http":
        value = str(scheme.get("scheme") or "").lower()
        return "bearer" if value == "bearer" else ("basic" if value == "basic" else "http")
    if scheme.get("type") == "oauth2":
        return "oauth2"
    if scheme.get("type") == "openIdConnect":
        return "oidc"
    if scheme.get("type") == "mutualTLS":
        return "mutual-tls"
    return "none"


def _security_names(security: object) -> tuple[str, ...]:
    """Extract security scheme names from an operation security requirement."""
    if not isinstance(security, list):
        return ()
    names: list[str] = []
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for name in requirement:
            if name not in names:
                names.append(str(name))
    return tuple(names)


def _schema_digest(schema: Mapping[str, Any]) -> str:
    """Digest a schema fragment deterministically."""
    canonical = json.dumps(schema, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _stringify(value: object) -> str | None:
    """Return a string repr for scalar defaults."""
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value)


def _request_media_type(operation: Mapping[str, Any]) -> str:
    """Extract the request media type from requestBody or consumes."""
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict) and isinstance(request_body.get("content"), dict):
        for media in request_body["content"]:
            return str(media)
    consumes = operation.get("consumes")
    if isinstance(consumes, list) and consumes:
        return str(consumes[0])
    return ""


def _response_media_type(operation: Mapping[str, Any]) -> str:
    """Extract the first response media type."""
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return ""
    for status in ("200", "201", "204", "default"):
        response = responses.get(status)
        if isinstance(response, dict) and isinstance(response.get("content"), dict):
            for media in response["content"]:
                return str(media)
    produces = operation.get("produces")
    if isinstance(produces, list) and produces:
        return str(produces[0])
    return ""


def _count_schemas(components: Mapping[str, Any]) -> int:
    """Count schema definitions in components."""
    schemas = components.get("schemas")
    if isinstance(schemas, dict):
        return len(schemas)
    return 0


def _format_of(data: Mapping[str, Any], raw: str | None) -> str:
    """Determine the document format."""
    if raw is not None and raw.lstrip().startswith("{"):
        return "json"
    return "yaml"


def _as_text(document: str | bytes) -> str:
    """Decode bytes safely."""
    if isinstance(document, bytes):
        return document.decode("utf-8", errors="replace")
    return str(document)
