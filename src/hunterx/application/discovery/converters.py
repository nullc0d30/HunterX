# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery — payload converters.

Turn raw adapter payloads into canonical discovered assets and attack-surface
observation payloads. One converter per payload family (recon, dns, livehost,
tech, web, content, parameter, javascript, api, auth); each returns the assets
the pipeline deduplicates and the observations fed to
:meth:`AttackSurfaceService.on_observation` — never target-specific.

Every converter is pure: it reads the execution payload (parsed via the domain
model helpers) and returns plain structures. Execution, state tracking and
surface intake live in :mod:`hunterx.application.discovery.service`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.api.models import (
    ApiAuthObservation,
    APIHostObservation,
    ApiOperationObservation,
    APISpecObservation,
)
from hunterx.domain.api.models import (
    observations_from_payload as api_observations_from_payload,
)
from hunterx.domain.auth.models import (
    AuthEndpointObservation,
    AuthFlowObservation,
    AuthObservation,
    AuthSurfaceObservation,
)
from hunterx.domain.auth.models import (
    observations_from_payload as auth_observations_from_payload,
)
from hunterx.domain.discovery.canonical import canonical_host, canonical_url, is_hostname, is_ip
from hunterx.domain.discovery.enums import DiscoveryLayer
from hunterx.domain.discovery.models import DiscoveredAsset, DiscoveryEvidence
from hunterx.domain.dns.models import records_from_payload as dns_records_from_payload
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.javascript.models import findings_from_payload as js_findings_from_payload
from hunterx.domain.livehost.models import observations_from_payload as live_observations_from_payload
from hunterx.domain.recon.models import records_from_payload as recon_records_from_payload
from hunterx.domain.technology.models import observations_from_payload as tech_observations_from_payload


@dataclass(frozen=True, slots=True)
class Observation:
    """One attack-surface observation payload for the intake bridge.

    Attributes:
        observation_type: canonical observation type (classified to a surface
            kind by the registry: ``subdomain``, ``host``, ``port``, ``api``,
            ``graphql``, ``javascript``, ``auth``, ``workflow``, ...).
        content: payload content consumed by the intake helpers (URLs,
            endpoints, parameters, technologies, objects, workflows...).
        asset_key: canonical asset identity (URL, host, ``host:port``...).
        source: provenance source label.
        session_state: optional session state for authenticated discovery.

    """

    observation_type: str
    content: Any = None
    asset_key: str = ""
    source: str = ""
    session_state: str = ""


@dataclass(slots=True)
class ConversionResult:
    """The outcome of one payload conversion.

    Attributes:
        assets: canonical :class:`DiscoveredAsset` records for deduplication.
        observations: attack-surface observation payloads for intake.
        records: raw typed records (kept for reporting).

    """

    assets: list[DiscoveredAsset] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    records: list[Any] = field(default_factory=list)

    def add(self, other: ConversionResult) -> None:
        """Merge another conversion result into this one."""
        self.assets.extend(other.assets)
        self.observations.extend(other.observations)
        self.records.extend(other.records)


# -- asset helpers -----------------------------------------------------------


def _layer(kind: str) -> DiscoveryLayer:
    """Map a canonical asset kind to its discovery layer."""
    if kind in ("host", "subdomain", "domain", "ip", "cidr"):
        return DiscoveryLayer.ASSET
    if kind in ("port", "service"):
        return DiscoveryLayer.SERVICE
    if kind == "technology":
        return DiscoveryLayer.APPLICATION
    if kind in ("parameter", "path_variable", "json_field", "form_field", "header", "cookie", "file", "upload", "download"):
        return DiscoveryLayer.INPUT
    if kind in ("object", "object_identifier", "sink", "source"):
        return DiscoveryLayer.OBJECT
    if kind in ("auth_surface", "auth_state", "authorization_context"):
        return DiscoveryLayer.STATE
    if kind in ("workflow", "state_transition"):
        return DiscoveryLayer.WORKFLOW
    return DiscoveryLayer.SURFACE


def _asset(
    kind: str,
    name: str,
    *,
    provider: str,
    tool_id: str = "",
    source: str = "",
    evidence: str = "",
    confidence: float = 1.0,
    attributes: dict[str, Any] | None = None,
) -> DiscoveredAsset:
    """Build a canonical discovered asset with a single provenance record."""
    return DiscoveredAsset(
        kind=kind,
        name=name,
        layer=_layer(kind),
        attributes=dict(attributes or {}),
        evidence=[
            DiscoveryEvidence(
                provider=provider,
                tool_id=tool_id or provider,
                source=source,
                evidence=evidence,
                confidence=confidence,
            )
        ],
    )


def _observation(
    observation_type: str,
    content: Any,
    asset_key: str,
    *,
    provider: str,
    session_state: str = "",
) -> Observation:
    """Build one observation payload."""
    return Observation(
        observation_type=observation_type,
        content=content,
        asset_key=asset_key,
        source=provider,
        session_state=session_state,
    )


def _collect_urls(content: Any, *keys: str) -> list[str]:
    """Collect URL-like strings from a payload container."""
    urls: list[str] = []
    if isinstance(content, dict):
        for key in keys:
            entries = content.get(key)
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        for field_name in ("url", "endpoint", "route", "path"):
                            if entry.get(field_name):
                                urls.append(str(entry[field_name]))
                                break
                    elif isinstance(entry, str) and entry.strip():
                        urls.append(entry.strip())
    return urls


# -- converters --------------------------------------------------------------

# Each converter signature: ``convert(context, payload) -> ConversionResult``.


def convert_recon(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a recon payload (``discoveries``) into assets + observations."""
    result = ConversionResult()
    for record in recon_records_from_payload(payload):
        kind = record.kind.value
        name = record.name.strip().lower()
        result.records.append(record)
        provider = record.tool_id or context.tool_id
        if kind in ("subdomain", "hostname", "domain"):
            asset_kind = "subdomain" if kind in ("subdomain", "domain") else "host"
            result.assets.append(_asset(asset_kind, name, provider=provider, tool_id=record.tool_id, source=record.source, confidence=record.confidence, attributes=dict(record.details)))
            result.observations.append(_observation(asset_kind, dict(record.details), name, provider=provider))
        elif kind in ("ip-address", "cidr"):
            asset_kind = "ip" if kind == "ip-address" else "cidr"
            result.assets.append(_asset(asset_kind, name, provider=provider, tool_id=record.tool_id, source=record.source, confidence=record.confidence, attributes=dict(record.details)))
            result.observations.append(_observation("host", dict(record.details), name, provider=provider))
        elif kind == "dns-record":
            rtype = str(record.details.get("record_type") or "")
            result.assets.append(_asset("dns_record", f"{name} {rtype}".strip(), provider=provider, tool_id=record.tool_id, source=record.source, confidence=record.confidence, attributes=dict(record.details)))
            result.observations.append(_observation("dns_record", dict(record.details), name, provider=provider))
        else:
            result.assets.append(_asset(kind, name, provider=provider, tool_id=record.tool_id, source=record.source, confidence=record.confidence, attributes=dict(record.details)))
    return result


def convert_dns(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a DNS payload (``dns_records``) into assets + observations."""
    result = ConversionResult()
    for record in dns_records_from_payload(payload):
        provider = record.tool_id or context.tool_id
        result.records.append(record)
        owner = record.name.lower()
        value = record.value.strip()
        rtype = record.record_type.value
        owner_kind = "subdomain" if owner.count(".") > 1 else "host"
        result.assets.append(_asset(owner_kind, canonical_host(owner), provider=provider, tool_id=record.tool_id, source=record.source, confidence=record.confidence, attributes={"record_type": rtype}))
        result.observations.append(_observation(owner_kind, {"record_type": rtype}, canonical_host(owner), provider=provider))
        if rtype in ("A", "AAAA") and is_ip(value):
            result.assets.append(_asset("ip", value, provider=provider, tool_id=record.tool_id, source=record.source, confidence=record.confidence, attributes={"record_type": rtype, "owner": owner}))
            result.observations.append(_observation("host", {"record_type": rtype}, value, provider=provider))
        elif rtype in ("CNAME", "MX", "NS", "PTR") and is_hostname(value):
            result.assets.append(_asset("host", canonical_host(value), provider=provider, tool_id=record.tool_id, source=record.source, confidence=record.confidence, attributes={"record_type": rtype, "owner": owner}))
            result.observations.append(_observation("host", {"record_type": rtype}, canonical_host(value), provider=provider))
    return result


def convert_livehost(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a livehost payload (``observations``) into assets + observations."""
    result = ConversionResult()
    hosts, ports, services, tls, http = live_observations_from_payload(payload)
    result.records.extend([*hosts, *ports, *services, *tls, *http])
    for host in hosts:
        provider = host.tool_id or context.tool_id
        address = host.address
        result.assets.append(_asset("host", canonical_host(address), provider=provider, tool_id=host.tool_id, source=host.source, confidence=host.confidence, attributes={"state": host.state.value, "ip_version": host.ip_version}))
        result.observations.append(_observation("host", {"state": host.state.value, "ip_version": host.ip_version}, canonical_host(address), provider=provider))
    for port in ports:
        provider = port.tool_id or context.tool_id
        name = canonical_host(port.address) if is_hostname(port.address) else port.address
        asset_name = f"{name}:{port.port}"
        result.assets.append(_asset("port", asset_name, provider=provider, tool_id=port.tool_id, source=port.source, confidence=port.confidence, attributes={"port": port.port, "state": port.state.value, "protocol": port.protocol.value}))
        result.observations.append(_observation("port", {"port": port.port, "state": port.state.value, "protocol": port.protocol.value}, asset_name, provider=provider))
    for service in services:
        provider = service.tool_id or context.tool_id
        name = f"{canonical_host(service.address) if is_hostname(service.address) else service.address}:{service.port}"
        result.assets.append(_asset("service", name, provider=provider, tool_id=service.tool_id, source=service.source, confidence=service.confidence, attributes={"port": service.port, "name": getattr(service, "name", ""), "product": getattr(service, "product", "")}))
        result.observations.append(_observation("service", {"port": service.port, "name": getattr(service, "name", "")}, name, provider=provider))
    for http_obs in http:
        provider = http_obs.tool_id or context.tool_id
        url = canonical_url(f"{http_obs.scheme}://{http_obs.host or http_obs.address}:{http_obs.port}/")
        result.assets.append(_asset("url", url, provider=provider, tool_id=http_obs.tool_id, source=http_obs.source, confidence=http_obs.confidence, attributes={"status_code": http_obs.status_code, "server": http_obs.server, "title": http_obs.title}))
        result.observations.append(_observation("url", {"status_code": http_obs.status_code, "server": http_obs.server, "title": http_obs.title}, url, provider=provider))
    return result


def convert_tech(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a technology payload (``technologies``) into assets + observations."""
    result = ConversionResult()
    grouped: dict[str, list[str]] = {}
    for observation in tech_observations_from_payload(payload):
        result.records.append(observation)
        provider = observation.tool_id or context.tool_id
        asset = observation.asset.strip()
        name = observation.canonical_name or observation.raw_name
        if name:
            result.assets.append(_asset("technology", name, provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"version": observation.version, "category": observation.category.value if hasattr(observation.category, "value") else str(observation.category)}))
            grouped.setdefault(asset, []).append(name)
    for asset, technologies in grouped.items():
        result.observations.append(_observation("technology", {"technologies": technologies}, canonical_host(asset) if is_hostname(asset) else asset, provider=context.tool_id))
    return result


def convert_web(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a web-crawl payload (``crawl``) into assets + observations."""
    result = ConversionResult()
    if not isinstance(payload, dict):
        return result
    crawl = payload.get("crawl")
    if not isinstance(crawl, dict):
        return result
    provider = context.tool_id
    target = context.target.strip()
    urls = [_absolute_url(url, target) for url in _collect_urls(crawl, "urls")]
    endpoints = [_absolute_url(url, target) for url in _collect_urls(crawl, "endpoints")]
    websockets = [_absolute_url(url, target) for url in _collect_urls(crawl, "websockets")]
    graphqls = [_absolute_url(url, target) for url in _collect_urls(crawl, "graphqls")]
    auth_boundaries = [_absolute_url(url, target) for url in _collect_urls(crawl, "auth_boundaries")]
    for url in urls:
        result.assets.append(_asset("url", canonical_url(url), provider=provider, tool_id=context.tool_id, source="crawl"))
    for url in endpoints:
        result.assets.append(_asset("api_endpoint", canonical_url(url), provider=provider, tool_id=context.tool_id, source="crawl"))
    for url in websockets:
        result.assets.append(_asset("websocket", url, provider=provider, tool_id=context.tool_id, source="crawl"))
    for url in graphqls:
        result.assets.append(_asset("graphql_operation", canonical_url(url), provider=provider, tool_id=context.tool_id, source="crawl"))
    for url in auth_boundaries:
        result.assets.append(_asset("auth_surface", canonical_url(url), provider=provider, tool_id=context.tool_id, source="crawl"))
    result.records.append(crawl)
    target = context.target.strip()
    if urls:
        result.observations.append(_observation("url", {"urls": urls}, target, provider=provider))
    if endpoints:
        result.observations.append(_observation("api", {"endpoints": endpoints}, target, provider=provider))
    if websockets:
        result.observations.append(_observation("websocket", {"endpoints": websockets}, target, provider=provider))
    if graphqls:
        result.observations.append(_observation("graphql", {"endpoints": graphqls}, target, provider=provider))
    if auth_boundaries:
        result.observations.append(_observation("auth", {"endpoints": auth_boundaries}, target, provider=provider))
    return result


def convert_content(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a content-discovery payload (``content``) into assets + observations."""
    result = ConversionResult()
    if not isinstance(payload, dict):
        return result
    content = payload.get("content")
    if not isinstance(content, dict):
        return result
    requests = content.get("requests") or []
    urls: list[str] = []
    for request in requests:
        if isinstance(request, dict) and request.get("url"):
            url = canonical_url(_absolute_url(str(request["url"]), context.target))
            urls.append(url)
            result.assets.append(_asset("endpoint", url, provider=context.tool_id, tool_id=context.tool_id, source="content", attributes={"status_code": request.get("status"), "method": request.get("method")}))
    if urls:
        result.observations.append(_observation("endpoint", {"endpoints": urls}, context.target.strip(), provider=context.tool_id))
    return result


def convert_parameter(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a parameter-discovery payload (``parameters``) into assets + observations."""
    result = ConversionResult()
    if not isinstance(payload, dict):
        return result
    container = payload.get("parameters")
    if not isinstance(container, dict):
        return result
    findings = container.get("findings") or []
    result.records.append(container)
    parameter_names: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        url = canonical_url(str(finding.get("url") or "")) if finding.get("url") else ""
        names = finding.get("parameters") or finding.get("parameter") or []
        if isinstance(names, str):
            names = [names]
        for name in names:
            parameter_names.append(str(name))
            result.assets.append(_asset("parameter", str(name), provider=context.tool_id, tool_id=context.tool_id, source="parameter", attributes={"url": url}))
    if parameter_names:
        result.observations.append(_observation("parameter", {"parameters": parameter_names}, context.target.strip(), provider=context.tool_id))
    return result


def convert_javascript(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert a JavaScript payload (``javascript``) into assets + observations."""
    result = ConversionResult()
    for analysis in js_findings_from_payload(payload):
        result.records.append(analysis)
        provider = context.tool_id
        asset_url = analysis.asset.url if analysis.asset is not None else context.target
        base = _absolute_url(asset_url, context.target)
        endpoints = [_absolute_url(item, base) for item in _endpoints(analysis)]
        routes = [item for item in _routes(analysis)]
        for url in endpoints:
            result.assets.append(_asset("javascript_endpoint", canonical_url(url) if "://" in url else url, provider=provider, tool_id=context.tool_id, source="javascript"))
        for route in routes:
            result.assets.append(_asset("client_route", route, provider=provider, tool_id=context.tool_id, source="javascript"))
        if endpoints:
            result.observations.append(_observation("javascript", {"endpoints": endpoints}, _absolute_url(asset_url, context.target), provider=provider))
    return result


def _endpoints(analysis: Any) -> list[str]:
    """Collect endpoint URLs from a JS asset analysis."""
    urls: list[str] = []
    for endpoint in getattr(analysis, "endpoints", None) or ():
        url = getattr(endpoint, "url", "") or ""
        if url:
            urls.append(str(url))
    return urls


def _routes(analysis: Any) -> list[str]:
    """Collect client routes from a JS asset analysis."""
    routes: list[str] = []
    for route in getattr(analysis, "routes", None) or ():
        value = getattr(route, "route", "") or ""
        if value:
            routes.append(str(value))
    return routes


def _absolute_url(url: str, fallback_origin: str) -> str:
    """Resolve a possibly-relative URL against a fallback origin."""
    value = str(url or "").strip()
    if "://" in value:
        return value
    origin = str(fallback_origin or "").rstrip("/")
    if not origin:
        return value
    return f"{origin}{value if value.startswith('/') else '/' + value}"


def convert_api(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert an API payload (``apis``) into assets + observations."""
    result = ConversionResult()
    for observation in api_observations_from_payload(payload):
        result.records.append(observation)
        provider = observation.tool_id or context.tool_id
        if isinstance(observation, APIHostObservation):
            origin = observation.origin_key
            host = origin.split("://", 1)[-1] if "://" in origin else origin
            host = host.split(":", 1)[0]
            result.assets.append(_asset("host", canonical_host(host), provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"scheme": observation.scheme, "documented": observation.documented}))
            result.observations.append(_observation("host", {"api": True, "documented": observation.documented}, canonical_host(host), provider=provider))
        elif isinstance(observation, APISpecObservation):
            url = _absolute_url(observation.source_url or observation.origin_key, context.target)
            result.assets.append(_asset("api_endpoint", canonical_url(url), provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"spec_type": observation.spec_type, "format": observation.format}))
            result.observations.append(_observation("api", {"endpoints": [canonical_url(url)], "documented": True, "spec_type": observation.spec_type}, canonical_url(url), provider=provider))
        elif isinstance(observation, ApiOperationObservation):
            origin = (observation.origin_key or "").rstrip("/")
            path = observation.path or "/"
            if "://" in path:
                url = path
            else:
                url = f"{origin}{path if path.startswith('/') else '/' + path}" if origin else path
            url = canonical_url(_absolute_url(url, context.target))
            parameters = [
                {"name": parameter.name, "location": parameter.location, "required": parameter.required}
                for parameter in observation.parameters
            ]
            api_kind = observation.api_kind.value if hasattr(observation.api_kind, "value") else str(observation.api_kind)
            if api_kind == "graphql":
                result.assets.append(_asset("graphql_operation", url, provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"method": observation.method, "path": path}))
                result.observations.append(_observation("graphql", {"endpoints": [url], "parameters": parameters, "method": observation.method}, url, provider=provider))
            else:
                result.assets.append(_asset("api_endpoint", url, provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"method": observation.method, "path": path, "api_kind": api_kind}))
                result.observations.append(_observation("api", {"endpoints": [url], "parameters": parameters, "method": observation.method}, url, provider=provider))
        elif isinstance(observation, ApiAuthObservation):
            origin = _absolute_url(observation.origin_key, context.target)
            result.assets.append(_asset("auth_surface", origin, provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"scheme_type": observation.scheme_type, "model_type": observation.model_type}))
            result.observations.append(_observation("auth", {"endpoints": [origin], "scheme_type": observation.scheme_type, "authorization_state": [observation.model_type]}, origin, provider=provider))
    return result


def convert_auth(context: ExecutionContext, payload: dict[str, Any] | None) -> ConversionResult:
    """Convert an auth payload (``auth``) into assets + observations."""
    result = ConversionResult()
    endpoints: list[str] = []
    for observation in auth_observations_from_payload(payload):
        result.records.append(observation)
        provider = observation.tool_id or context.tool_id
        if isinstance(observation, (AuthSurfaceObservation, AuthEndpointObservation)):
            url = observation.url
            endpoints.append(url)
            kind = observation.surface_kind.value if isinstance(observation, AuthSurfaceObservation) and hasattr(observation.surface_kind, "value") else ""
            result.assets.append(_asset("auth_surface", url, provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"kind": kind, "method": observation.method if isinstance(observation, AuthEndpointObservation) else ""}))
            result.observations.append(_observation("auth", {"endpoints": [url], "kind": kind}, url, provider=provider))
        elif isinstance(observation, AuthFlowObservation):
            name = observation.name or observation.origin
            result.assets.append(_asset("workflow", f"auth:{name}", provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"flow_kind": observation.flow_kind.value if hasattr(observation.flow_kind, "value") else str(observation.flow_kind), "start_state": observation.start_state.value if hasattr(observation.start_state, "value") else str(observation.start_state), "end_state": observation.end_state.value if hasattr(observation.end_state, "value") else str(observation.end_state)}))
            result.observations.append(_observation("workflow", {"workflow": {"name": name, "flow_kind": observation.flow_kind.value if hasattr(observation.flow_kind, "value") else str(observation.flow_kind), "steps": list(observation.steps)}}, observation.origin or context.target, provider=provider))
        elif isinstance(observation, AuthObservation):
            name = observation.origin
            result.assets.append(_asset("auth_surface", name, provider=provider, tool_id=observation.tool_id, source=observation.source, confidence=observation.confidence, attributes={"kind": observation.kind.value if hasattr(observation.kind, "value") else str(observation.kind), "name": observation.name}))
            result.observations.append(_observation("auth", {"endpoints": [name], "kind": observation.kind.value if hasattr(observation.kind, "value") else str(observation.kind)}, name, provider=provider))
    if endpoints:
        result.observations.append(_observation("auth", {"endpoints": endpoints}, context.target, provider=context.tool_id))
    return result


#: Converter lookup keyed by payload family.
CONVERTERS: dict[str, Any] = {
    "recon": convert_recon,
    "dns": convert_dns,
    "livehost": convert_livehost,
    "tech": convert_tech,
    "web": convert_web,
    "content": convert_content,
    "parameter": convert_parameter,
    "javascript": convert_javascript,
    "api": convert_api,
    "auth": convert_auth,
}


__all__ = ["CONVERTERS", "ConversionResult", "Observation"]
