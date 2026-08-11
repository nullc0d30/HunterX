# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web/JS hint fold-in parser.

Converts already-persisted web-crawl, JavaScript, technology and topology
observations into canonical API intelligence raw observations. This is the
passive path: it consumes existing TIDB intelligence and never issues network
traffic, so it is safe for passive postures and unit tests.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.api.models import (
    ApiAuthObservation,
    ApiEvidence,
    ApiFilterObservation,
    ApiKind,
    ApiOperationObservation,
    ApiPaginationObservation,
    ApiRateLimitObservation,
    ApiSurfaceForm,
    EvidenceStrength,
    EvidenceType,
    make_host_observation,
    normalize_path,
    operation_hash,
    origin_of,
)


@dataclass(frozen=True, slots=True)
class HintsParseResult:
    """The observations folded in from existing intelligence.

    Attributes:
        hosts: host observations derived from web origins.
        operations: endpoint operations derived from crawl/JS hints.
        auth: auth-observation hints.
        rate_limits / paginations / filters: derived indicator hints.

    """

    hosts: tuple[Any, ...] = ()
    operations: tuple[ApiOperationObservation, ...] = ()
    auth: tuple[ApiAuthObservation, ...] = ()
    rate_limits: tuple[ApiRateLimitObservation, ...] = ()
    paginations: tuple[ApiPaginationObservation, ...] = ()
    filters: tuple[ApiFilterObservation, ...] = ()

    def __len__(self) -> int:
        """Return the total number of folded-in observations."""
        return (
            len(self.hosts)
            + len(self.operations)
            + len(self.auth)
            + len(self.rate_limits)
            + len(self.paginations)
            + len(self.filters)
        )


class HintsParser:
    """Fold existing web/JS/technology intelligence into API observations.

    Records may be dataclasses (TIDB/web-crawl models) or plain mappings; both
    are handled through attribute/dict access.
    """

    def parse(
        self,
        *,
        web_origins: Sequence[Any] = (),
        url_observations: Sequence[Any] = (),
        web_api_endpoints: Sequence[Any] = (),
        websocket_endpoints: Sequence[Any] = (),
        graphql_endpoints: Sequence[Any] = (),
        js_endpoints: Sequence[Any] = (),
        auth_boundaries: Sequence[Any] = (),
        technology_observations: Sequence[Any] = (),
        target_key: str = "",
        correlation_id: str = "",
        mission_id: str = "",
        tool_id: str = "api-hints",
    ) -> HintsParseResult:
        """Convert existing intelligence into canonical API observations."""
        hosts = _hosts_from_origins(web_origins, target_key, correlation_id, mission_id, tool_id)
        operations: list[ApiOperationObservation] = []
        operations.extend(
            _operations_from_web_endpoints(
                web_api_endpoints,
                target_key,
                correlation_id,
                mission_id,
                tool_id,
            )
        )
        operations.extend(
            _operations_from_websocket_endpoints(
                websocket_endpoints,
                target_key,
                correlation_id,
                mission_id,
                tool_id,
            )
        )
        operations.extend(
            _operations_from_graphql_endpoints(
                graphql_endpoints,
                target_key,
                correlation_id,
                mission_id,
                tool_id,
            )
        )
        operations.extend(_operations_from_js_hints(js_endpoints, target_key, correlation_id, mission_id, tool_id))
        auth = _auth_from_boundaries(auth_boundaries, correlation_id, mission_id, tool_id)
        indicators = _indicators_from_urls(url_observations, correlation_id, mission_id)
        return HintsParseResult(
            hosts=tuple(hosts),
            operations=tuple(operations),
            auth=tuple(auth),
            rate_limits=tuple(indicators["rate_limits"]),
            paginations=tuple(indicators["paginations"]),
            filters=tuple(indicators["filters"]),
        )


def _hosts_from_origins(
    web_origins: Sequence[Any],
    target_key: str,
    correlation_id: str,
    mission_id: str,
    tool_id: str,
) -> list[Any]:
    hosts: list[Any] = []
    for origin in web_origins:
        origin_key = str(_get(origin, "key", "") or _get(origin, "origin_key", "") or "")
        if not origin_key:
            continue
        hosts.append(
            make_host_observation(
                origin_key,
                scheme=str(_get(origin, "scheme", "https") or "https"),
                host=str(_get(origin, "host", "") or ""),
                port=_get(origin, "port", None),
                confidence=float(_get(origin, "confidence", 1.0) or 1.0),
                evidence=(
                    ApiEvidence(
                        evidence_type=EvidenceType.TIDB_INTELLIGENCE,
                        value="web origin observation",
                        source="web.crawl",
                        strength=EvidenceStrength.MODERATE,
                        tool_id=tool_id,
                    ),
                ),
                source="web.crawl",
                tool_id=tool_id,
                target_key=target_key,
                correlation_id=correlation_id,
                mission_id=mission_id,
            )
        )
    return hosts


def _operations_from_web_endpoints(
    web_api_endpoints: Sequence[Any],
    target_key: str,
    correlation_id: str,
    mission_id: str,
    tool_id: str,
) -> list[ApiOperationObservation]:
    operations: list[ApiOperationObservation] = []
    for endpoint in web_api_endpoints:
        origin_key = _origin_of_record(endpoint)
        method = str(_get(endpoint, "method", "GET") or "GET").upper()
        path = str(_get(endpoint, "path", "") or _get(endpoint, "url", "") or "")
        if not path:
            continue
        operations.append(
            _hint_operation(
                origin_key,
                method,
                path,
                ApiKind.REST,
                ApiSurfaceForm.WEB_CRAWL,
                target_key,
                correlation_id,
                mission_id,
                tool_id,
            )
        )
    return operations


def _operations_from_websocket_endpoints(
    websocket_endpoints: Sequence[Any],
    target_key: str,
    correlation_id: str,
    mission_id: str,
    tool_id: str,
) -> list[ApiOperationObservation]:
    operations: list[ApiOperationObservation] = []
    for endpoint in websocket_endpoints:
        origin_key = _origin_of_record(endpoint)
        path = str(_get(endpoint, "path", "") or _get(endpoint, "url", "") or "")
        if not path:
            continue
        operations.append(
            _hint_operation(
                origin_key,
                "WS",
                path,
                ApiKind.WEBSOCKET,
                ApiSurfaceForm.WEB_CRAWL,
                target_key,
                correlation_id,
                mission_id,
                tool_id,
            )
        )
    return operations


def _operations_from_graphql_endpoints(
    graphql_endpoints: Sequence[Any],
    target_key: str,
    correlation_id: str,
    mission_id: str,
    tool_id: str,
) -> list[ApiOperationObservation]:
    operations: list[ApiOperationObservation] = []
    for endpoint in graphql_endpoints:
        origin_key = _origin_of_record(endpoint)
        path = str(_get(endpoint, "path", "") or _get(endpoint, "url", "") or "/graphql")
        operations.append(
            _hint_operation(
                origin_key,
                "POST",
                path or "/graphql",
                ApiKind.GRAPHQL,
                ApiSurfaceForm.GRAPHQL_SCHEMA_SHAPE,
                target_key,
                correlation_id,
                mission_id,
                tool_id,
            )
        )
    return operations


def _operations_from_js_hints(
    js_endpoints: Sequence[Any],
    target_key: str,
    correlation_id: str,
    mission_id: str,
    tool_id: str,
) -> list[ApiOperationObservation]:
    operations: list[ApiOperationObservation] = []
    for endpoint in js_endpoints:
        origin_key = _origin_of_record(endpoint)
        path = str(_get(endpoint, "path", "") or _get(endpoint, "url", "") or "")
        if not path:
            continue
        methods = _get(endpoint, "methods", ()) or ("GET",)
        if isinstance(methods, str):
            methods = (methods,)
        for method in methods:
            operations.append(
                _hint_operation(
                    origin_key,
                    str(method).upper() if str(method).upper() != "WS" else "WS",
                    path,
                    ApiKind.REST,
                    ApiSurfaceForm.JS_HINT,
                    target_key,
                    correlation_id,
                    mission_id,
                    tool_id,
                )
            )
    return operations


def _auth_from_boundaries(
    auth_boundaries: Sequence[Any],
    correlation_id: str,
    mission_id: str,
    tool_id: str,
) -> list[ApiAuthObservation]:
    auth: list[ApiAuthObservation] = []
    for boundary in auth_boundaries:
        origin_key = _origin_of_record(boundary)
        url = str(_get(boundary, "url", "") or "")
        scheme_type = str(_get(boundary, "auth_type", "") or _get(boundary, "scheme_type", "") or "").lower()
        if not origin_key and url:
            origin_key = origin_of(url)
        auth.append(
            ApiAuthObservation(
                origin_key=origin_key or "unknown",
                scheme_type=_auth_scheme(scheme_type),
                documented=False,
                indicators=(f"auth boundary: {scheme_type or 'unknown'}",),
                confidence=0.6,
                source="web.crawl",
                tool_id=tool_id,
                correlation_id=correlation_id,
                mission_id=mission_id,
            )
        )
    return auth


def _indicators_from_urls(
    url_observations: Sequence[Any],
    correlation_id: str,
    mission_id: str,
) -> dict[str, list[Any]]:
    rate_limits: list[ApiRateLimitObservation] = []
    paginations: list[ApiPaginationObservation] = []
    filters: list[ApiFilterObservation] = []
    for url_observation in url_observations:
        origin_key = _origin_of_record(url_observation)
        url = str(_get(url_observation, "url", "") or "")
        query = str(_get(url_observation, "query", "") or "")
        if not origin_key and url:
            origin_key = origin_of(url)
        if not origin_key:
            continue
        params = _query_params(query)
        lower = {item.lower() for item in params}
        if lower & {"limit", "page", "offset", "cursor", "per_page"}:
            if "cursor" in lower:
                style = "cursor"
            elif lower & {"page", "per_page"}:
                style = "page"
            else:
                style = "offset"
            paginations.append(
                ApiPaginationObservation(
                    origin_key=origin_key,
                    style=style,
                    endpoint=url,
                    limit_param=("limit" if "limit" in lower else "per_page"),
                    offset_param=("offset" if "offset" in lower else None),
                    cursor_param=("cursor" if "cursor" in lower else None),
                    confidence=0.7,
                    correlation_id=correlation_id,
                    mission_id=mission_id,
                )
            )
        if lower & {"filter", "q", "search", "query"}:
            for param in ("filter", "q", "search", "query"):
                if param in lower:
                    filters.append(
                        ApiFilterObservation(
                            origin_key=origin_key,
                            endpoint=url,
                            filter_param=param,
                            style="query",
                            confidence=0.6,
                            correlation_id=correlation_id,
                            mission_id=mission_id,
                        )
                    )
                    break
    return {"rate_limits": rate_limits, "paginations": paginations, "filters": filters}


def _hint_operation(
    origin_key: str,
    method: str,
    path: str,
    api_kind: ApiKind,
    surface_form: ApiSurfaceForm,
    target_key: str,
    correlation_id: str,
    mission_id: str,
    tool_id: str,
) -> ApiOperationObservation:
    """Build a canonical operation from a web/JS hint."""
    normalized = normalize_path(path)
    return ApiOperationObservation(
        origin_key=origin_key,
        method=method,
        path=path,
        normalized_path=normalized,
        path_hash=operation_hash(method, normalized),
        api_kind=api_kind,
        surface_form=surface_form,
        documented=False,
        confidence=0.6,
        sources=(tool_id,),
        evidence=(
            ApiEvidence(
                evidence_type=EvidenceType.TIDB_INTELLIGENCE,
                value=f"{api_kind.value} hint {method} {path}",
                source=surface_form.value,
                strength=EvidenceStrength.MODERATE,
                tool_id=tool_id,
            ),
        ),
        source=surface_form.value,
        tool_id=tool_id,
        target_key=target_key,
        correlation_id=correlation_id,
        mission_id=mission_id,
    )


def _origin_of_record(record: Any) -> str:
    """Extract the origin key from a record (object or mapping)."""
    origin = str(_get(record, "origin_key", "") or _get(record, "origin", "") or "")
    if origin:
        return origin
    url = str(_get(record, "url", "") or "")
    if url:
        return origin_of(url)
    return "unknown"


def _query_params(query: str) -> list[str]:
    """Split a query string into parameter names."""
    from urllib.parse import parse_qs

    if not query:
        return []
    try:
        parsed = parse_qs(query)
    except ValueError:  # pragma: no cover - defensive
        return []
    return list(parsed.keys())


def _auth_scheme(value: str) -> str:
    """Normalize auth boundary hints into canonical scheme types."""
    lowered = value.strip().lower()
    if lowered in ("basic", "bearer", "apikey", "oauth2", "oidc", "session", "cookie", "mutual-tls", "none"):
        return lowered
    if "basic" in lowered:
        return "basic"
    if "bearer" in lowered or "jwt" in lowered or "token" in lowered:
        return "bearer"
    if "oauth" in lowered:
        return "oauth2"
    if "key" in lowered:
        return "apikey"
    return "none"


def _get(record: Any, name: str, default: Any = None) -> Any:
    """Read an attribute from an object or a key from a mapping."""
    if record is None:
        return default
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)
