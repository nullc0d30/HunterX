# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API-surface Target Intelligence Database entities.

Discovered API endpoints and their security posture: REST, GraphQL, SOAP and
RPC services plus authentication/authorization models.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class API(TidbEntity):
    """A discovered API.

    Attributes:
        target_id: owning target.
        name: API name.
        base_url: API base URL.
        api_version: API version.
        auth_scheme: default authentication scheme.
        spec_source: swagger|openapi|wsdl|... .
        discovered_by: tool/step that discovered it.

    """

    target_id: str
    name: str = ""
    base_url: str = ""
    api_version: str | None = None
    auth_scheme: str | None = None
    spec_source: str | None = None
    discovered_by: str | None = None


@dataclass(slots=True)
class RESTEndpoint(TidbEntity):
    """A REST endpoint.

    Attributes:
        api_id: owning API.
        method: HTTP method.
        path: endpoint path.
        auth_required: whether authentication is required.
        content_type: response content type.
        response_meta: response metadata map.

    """

    api_id: str
    method: str = "GET"
    path: str = ""
    auth_required: bool = False
    content_type: str | None = None
    response_meta: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class GraphQLEndpoint(TidbEntity):
    """A GraphQL endpoint.

    Attributes:
        api_id: owning API.
        path: endpoint path.
        introspection_enabled: whether introspection is enabled.
        query_limits: map of query/rate limits.

    """

    api_id: str
    path: str = "/graphql"
    introspection_enabled: bool = False
    query_limits: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class SOAPEndpoint(TidbEntity):
    """A SOAP web service endpoint.

    Attributes:
        api_id: owning API.
        path: endpoint path.
        wsdl_url: WSDL location.
        operations: list of SOAP operation names.

    """

    api_id: str
    path: str = ""
    wsdl_url: str | None = None
    operations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RPCService(TidbEntity):
    """A remote procedure call service.

    Attributes:
        api_id: owning API.
        name: service name.
        protocol: rpc protocol (gRPC, XML-RPC, JSON-RPC, ...).
        endpoints: list of RPC endpoint/method references.

    """

    api_id: str
    name: str
    protocol: str = "json-rpc"
    endpoints: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AuthenticationScheme(TidbEntity):
    """An authentication scheme observed on an API.

    Attributes:
        api_id: owning API.
        name: scheme name.
        scheme_type: basic|bearer|oauth2|apikey|cookie|mutual-tls|none.
        config: scheme-specific configuration map.

    """

    api_id: str
    name: str = "default"
    scheme_type: str = "bearer"
    config: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class AuthorizationModel(TidbEntity):
    """An authorization model observed on an API.

    Attributes:
        api_id: owning API.
        name: model name.
        model_type: rbac|abac|acl|scopes|none.
        roles: list of role names when RBAC.
        scopes: list of OAuth scopes.

    """

    api_id: str
    name: str = "default"
    model_type: str = "none"
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
