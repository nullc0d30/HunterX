# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Surface-kind registry.

The registry is the extensibility seam for the attack-surface model: adapters
for a new target technology register their own surface kinds (with a layer and
observation-type classification) *without* touching core orchestration logic.
Core traversal and scheduling code only depends on ``SurfaceLayer`` and the
kind strings — never on a closed set of kinds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.attack_surface.enums import SurfaceKind, SurfaceLayer
from hunterx.domain.attack_surface.models import layer_for


@dataclass(frozen=True, slots=True)
class SurfaceKindSpec:
    """Metadata describing a surface kind.

    Attributes:
        kind: canonical kind string.
        layer: the graph layer the kind belongs to.
        observation_types: observation-type strings that classify to this kind.
        capability_hints: capability ids commonly applicable to this kind
            (validated against the live platform catalog by the capability
            mapper — never authoritative on their own).
        description: human description.

    """

    kind: str
    layer: SurfaceLayer = SurfaceLayer.SURFACE
    observation_types: tuple[str, ...] = ()
    capability_hints: tuple[str, ...] = ()
    description: str = ""


#: Built-in specs keyed by SurfaceKind. Registration happens once at import;
#: adapters may register additional kinds at runtime.
_BUILTIN_SPECS: dict[str, SurfaceKindSpec] = {
    SurfaceKind.TARGET.value: SurfaceKindSpec(
        SurfaceKind.TARGET.value,
        SurfaceLayer.TARGET,
        ("target",),
        ("asset_discovery", "subdomain_enumeration", "port_discovery"),
        "the authorized objective of a mission",
    ),
    SurfaceKind.HOST.value: SurfaceKindSpec(
        SurfaceKind.HOST.value,
        SurfaceLayer.ASSET,
        ("host", "hostname", "ip", "cidr"),
        ("port_discovery", "service_detection", "technology_fingerprint"),
        "a reachable host or address",
    ),
    SurfaceKind.SUBDOMAIN.value: SurfaceKindSpec(
        SurfaceKind.SUBDOMAIN.value,
        SurfaceLayer.ASSET,
        ("subdomain", "domain"),
        ("asset_discovery", "port_discovery", "service_detection"),
        "a discovered subdomain",
    ),
    SurfaceKind.PORT.value: SurfaceKindSpec(
        SurfaceKind.PORT.value,
        SurfaceLayer.SERVICE,
        ("port",),
        ("service_detection", "technology_fingerprint"),
        "an open network port",
    ),
    SurfaceKind.SERVICE.value: SurfaceKindSpec(
        SurfaceKind.SERVICE.value,
        SurfaceLayer.SERVICE,
        ("service",),
        ("service_detection", "technology_fingerprint", "vulnerability_scanning"),
        "a network service",
    ),
    SurfaceKind.TECHNOLOGY.value: SurfaceKindSpec(
        SurfaceKind.TECHNOLOGY.value,
        SurfaceLayer.APPLICATION,
        ("technology", "tech"),
        ("known-vulnerable-component", "dependency-vulnerability", "security-misconfiguration"),
        "a detected technology/framework",
    ),
    SurfaceKind.URL.value: SurfaceKindSpec(
        SurfaceKind.URL.value,
        SurfaceLayer.SURFACE,
        ("url",),
        ("endpoint_enumeration", "parameter_discovery", "api_mapping", "security-misconfiguration"),
        "a discovered URL",
    ),
    SurfaceKind.ROUTE.value: SurfaceKindSpec(
        SurfaceKind.ROUTE.value,
        SurfaceLayer.SURFACE,
        ("route",),
        ("endpoint_enumeration", "parameter_discovery", "vulnerability_scanning"),
        "an application route",
    ),
    SurfaceKind.ENDPOINT.value: SurfaceKindSpec(
        SurfaceKind.ENDPOINT.value,
        SurfaceLayer.SURFACE,
        ("endpoint",),
        ("parameter_discovery", "endpoint_enumeration", "api_mapping", "http-access-differential"),
        "a reachable endpoint",
    ),
    SurfaceKind.METHOD.value: SurfaceKindSpec(
        SurfaceKind.METHOD.value,
        SurfaceLayer.SURFACE,
        ("method",),
        ("security-misconfiguration", "http-access-differential"),
        "an HTTP method a surface accepts",
    ),
    SurfaceKind.API_ENDPOINT.value: SurfaceKindSpec(
        SurfaceKind.API_ENDPOINT.value,
        SurfaceLayer.SURFACE,
        ("api",),
        ("api-security", "authorization", "api_mapping", "http-access-differential"),
        "an API endpoint",
    ),
    SurfaceKind.GRAPHQL_OPERATION.value: SurfaceKindSpec(
        SurfaceKind.GRAPHQL_OPERATION.value,
        SurfaceLayer.SURFACE,
        ("graphql",),
        ("graphql-security", "authorization", "api-security"),
        "a GraphQL operation",
    ),
    SurfaceKind.WEBSOCKET.value: SurfaceKindSpec(
        SurfaceKind.WEBSOCKET.value,
        SurfaceLayer.SURFACE,
        ("websocket",),
        ("api-security", "http-access-differential"),
        "a WebSocket endpoint",
    ),
    SurfaceKind.REDIRECT.value: SurfaceKindSpec(
        SurfaceKind.REDIRECT.value,
        SurfaceLayer.SURFACE,
        ("redirect",),
        ("open-redirect",),
        "a redirect behaviour",
    ),
    SurfaceKind.CLIENT_ROUTE.value: SurfaceKindSpec(
        SurfaceKind.CLIENT_ROUTE.value,
        SurfaceLayer.SURFACE,
        ("client_route",),
        ("javascript_analysis", "xss"),
        "a client-side route",
    ),
    SurfaceKind.JAVASCRIPT_ENDPOINT.value: SurfaceKindSpec(
        SurfaceKind.JAVASCRIPT_ENDPOINT.value,
        SurfaceLayer.SURFACE,
        ("javascript",),
        ("javascript_analysis", "xss", "sensitive-information-exposure"),
        "a JavaScript-referenced endpoint",
    ),
    SurfaceKind.SINK.value: SurfaceKindSpec(
        SurfaceKind.SINK.value,
        SurfaceLayer.OBJECT,
        ("sink",),
        ("xss", "javascript_analysis"),
        "a client-side sink",
    ),
    SurfaceKind.SOURCE.value: SurfaceKindSpec(
        SurfaceKind.SOURCE.value,
        SurfaceLayer.OBJECT,
        ("source",),
        ("xss", "javascript_analysis"),
        "a client-side source",
    ),
    SurfaceKind.CLOUD_RESOURCE.value: SurfaceKindSpec(
        SurfaceKind.CLOUD_RESOURCE.value,
        SurfaceLayer.SURFACE,
        ("cloud_resource", "saas"),
        ("cloud-exposure", "cloud_ownership_mapping"),
        "a cloud/SaaS resource",
    ),
    SurfaceKind.PARAMETER.value: SurfaceKindSpec(
        SurfaceKind.PARAMETER.value,
        SurfaceLayer.INPUT,
        ("parameter",),
        ("sql-injection", "nosql-injection", "xss", "ssti", "command-injection", "lfi", "xxe"),
        "an input parameter",
    ),
    SurfaceKind.PATH_VARIABLE.value: SurfaceKindSpec(
        SurfaceKind.PATH_VARIABLE.value,
        SurfaceLayer.INPUT,
        ("path_variable",),
        ("lfi", "path-traversal", "sql-injection", "ssti"),
        "a path variable",
    ),
    SurfaceKind.JSON_FIELD.value: SurfaceKindSpec(
        SurfaceKind.JSON_FIELD.value,
        SurfaceLayer.INPUT,
        ("json_field",),
        ("nosql-injection", "sql-injection", "xss", "ssti", "xxe"),
        "a JSON body field",
    ),
    SurfaceKind.FORM_FIELD.value: SurfaceKindSpec(
        SurfaceKind.FORM_FIELD.value,
        SurfaceLayer.INPUT,
        ("form_field",),
        ("sql-injection", "xss", "command-injection", "lfi", "ssti"),
        "a form field",
    ),
    SurfaceKind.HEADER.value: SurfaceKindSpec(
        SurfaceKind.HEADER.value,
        SurfaceLayer.INPUT,
        ("header",),
        ("security-misconfiguration", "cors-misconfiguration", "sensitive-information-exposure", "ssti"),
        "an HTTP header",
    ),
    SurfaceKind.COOKIE.value: SurfaceKindSpec(
        SurfaceKind.COOKIE.value,
        SurfaceLayer.INPUT,
        ("cookie",),
        ("authentication", "sensitive-information-exposure"),
        "an HTTP cookie",
    ),
    SurfaceKind.FILE.value: SurfaceKindSpec(
        SurfaceKind.FILE.value,
        SurfaceLayer.INPUT,
        ("file",),
        ("lfi", "xxe", "sensitive-information-exposure"),
        "a file surface",
    ),
    SurfaceKind.UPLOAD.value: SurfaceKindSpec(
        SurfaceKind.UPLOAD.value,
        SurfaceLayer.INPUT,
        ("upload",),
        ("command-injection", "xxe", "lfi", "security-misconfiguration"),
        "an upload surface",
    ),
    SurfaceKind.DOWNLOAD.value: SurfaceKindSpec(
        SurfaceKind.DOWNLOAD.value,
        SurfaceLayer.INPUT,
        ("download",),
        ("lfi", "sensitive-information-exposure"),
        "a download surface",
    ),
    SurfaceKind.OBJECT.value: SurfaceKindSpec(
        SurfaceKind.OBJECT.value,
        SurfaceLayer.OBJECT,
        ("object",),
        ("idor", "authorization"),
        "a target-specific object",
    ),
    SurfaceKind.OBJECT_IDENTIFIER.value: SurfaceKindSpec(
        SurfaceKind.OBJECT_IDENTIFIER.value,
        SurfaceLayer.OBJECT,
        ("object_identifier", "identifier"),
        ("idor", "authorization"),
        "an object identifier",
    ),
    SurfaceKind.AUTH_SURFACE.value: SurfaceKindSpec(
        SurfaceKind.AUTH_SURFACE.value,
        SurfaceLayer.STATE,
        ("auth", "authentication", "authentication_surface"),
        ("authentication",),
        "an authentication surface",
    ),
    SurfaceKind.AUTH_STATE.value: SurfaceKindSpec(
        SurfaceKind.AUTH_STATE.value,
        SurfaceLayer.STATE,
        ("auth_state", "session"),
        ("authentication",),
        "an authentication/session state",
    ),
    SurfaceKind.AUTHORIZATION_CONTEXT.value: SurfaceKindSpec(
        SurfaceKind.AUTHORIZATION_CONTEXT.value,
        SurfaceLayer.STATE,
        ("authorization", "authorization_surface"),
        ("authorization", "api-security"),
        "an authorization context",
    ),
    SurfaceKind.WORKFLOW.value: SurfaceKindSpec(
        SurfaceKind.WORKFLOW.value,
        SurfaceLayer.WORKFLOW,
        ("workflow",),
        ("http-access-differential", "authorization"),
        "a business workflow",
    ),
    SurfaceKind.STATE_TRANSITION.value: SurfaceKindSpec(
        SurfaceKind.STATE_TRANSITION.value,
        SurfaceLayer.WORKFLOW,
        ("state_transition",),
        ("http-access-differential", "authorization"),
        "a state transition within a workflow",
    ),
    SurfaceKind.UNKNOWN.value: SurfaceKindSpec(
        SurfaceKind.UNKNOWN.value,
        SurfaceLayer.SURFACE,
        ("other", "unknown"),
        ("http-access-differential", "security-misconfiguration"),
        "an unclassified surface",
    ),
}


class SurfaceKindRegistry:
    """Extensible registry of surface-kind specs.

    Core orchestration logic only consults layers and kind strings; new target
    technologies add kinds through :meth:`register` without any core change.
    """

    def __init__(self, specs: dict[str, SurfaceKindSpec] | None = None) -> None:
        self._specs: dict[str, SurfaceKindSpec] = dict(specs or _BUILTIN_SPECS)
        self._by_observation: dict[str, str] = {}
        for kind, spec in self._specs.items():
            for observation_type in spec.observation_types:
                self._by_observation.setdefault(observation_type, kind)

    def register(self, spec: SurfaceKindSpec) -> SurfaceKindSpec:
        """Register a surface kind spec (idempotent by kind)."""
        self._specs[spec.kind] = spec
        for observation_type in spec.observation_types:
            self._by_observation.setdefault(observation_type, spec.kind)
        return spec

    def register_kind(
        self,
        kind: str,
        *,
        layer: SurfaceLayer = SurfaceLayer.SURFACE,
        observation_types: tuple[str, ...] = (),
        capability_hints: tuple[str, ...] = (),
        description: str = "",
    ) -> SurfaceKindSpec:
        """Register a surface kind from primitives (adapter convenience)."""
        return self.register(
            SurfaceKindSpec(
                kind=kind,
                layer=layer,
                observation_types=observation_types,
                capability_hints=capability_hints,
                description=description,
            )
        )

    def get(self, kind: str) -> SurfaceKindSpec | None:
        """Return the spec for a kind string (``None`` when unregistered)."""
        return self._specs.get(kind)

    def kinds(self) -> list[str]:
        """Return all registered kind strings sorted."""
        return sorted(self._specs)

    def layer(self, kind: str) -> SurfaceLayer:
        """Return the layer for a kind (built-in fallback, else ``SURFACE``)."""
        spec = self._specs.get(kind)
        if spec is not None:
            return spec.layer
        try:
            return layer_for(SurfaceKind(kind))
        except ValueError:
            return SurfaceLayer.SURFACE

    def default_capabilities(self, kind: str) -> tuple[str, ...]:
        """Return the capability hints for a kind."""
        spec = self._specs.get(kind)
        return spec.capability_hints if spec is not None else ()

    def classify(self, observation_type: str) -> str:
        """Classify an observation-type string into a surface kind.

        Observation types that name no known kind classify to ``UNKNOWN`` (an
        honest "we saw a surface but cannot categorise it yet" — never an
        assumption).
        """
        normalized = str(observation_type or "").strip().lower()
        if not normalized:
            return SurfaceKind.UNKNOWN.value
        return self._by_observation.get(normalized, SurfaceKind.UNKNOWN.value)

    def classify_from(self, observation: dict[str, Any]) -> str:
        """Classify a raw observation mapping into a surface kind string."""
        if not isinstance(observation, dict):
            return SurfaceKind.UNKNOWN.value
        observation_type = str(observation.get("observation_type") or "")
        return self.classify(observation_type)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the registry to a JSON-safe mapping."""
        return {
            "kinds": [
                {
                    "kind": spec.kind,
                    "layer": spec.layer.value,
                    "observation_types": list(spec.observation_types),
                    "capability_hints": list(spec.capability_hints),
                    "description": spec.description,
                }
                for spec in self._specs.values()
            ]
        }


__all__ = ["SurfaceKindRegistry", "SurfaceKindSpec"]
