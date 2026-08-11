# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API surface classification.

Assigns every raw API intelligence record a canonical :class:`ApiKind` (REST,
GraphQL, WebSocket, SOAP, RPC, unknown) and an :class:`ApiSurfaceForm` (where
the record came from). Classification is a pure, deterministic function of the
record's evidence — spec type, path patterns, content types, headers, query
tokens and known signatures — so the same inputs always yield the same kind
and form, and every result is explainable through the signals that matched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hunterx.domain.api.models import (
    ApiKind,
    ApiOperationObservation,
    APISpecObservation,
    ApiSurfaceForm,
)

#: Path substrings that strongly indicate GraphQL.
_GRAPHQL_PATH_RE = re.compile(r"(^|/)(graphql|gql|graphiql|gql-)(/|$|\?)", re.IGNORECASE)
#: Path substrings that indicate WebSocket upgrade endpoints.
_WEBSOCKET_PATH_RE = re.compile(r"(^|/)(ws|wss|websocket|socket|sockjs|socket\.io)(/|$|\?)", re.IGNORECASE)
#: Path substrings that indicate SOAP service endpoints.
_SOAP_PATH_RE = re.compile(r"(^|/)(soap|services\b|axis2|ws)(/|$|\?)", re.IGNORECASE)
#: Common RPC-style surrogates.
_RPC_PATH_RE = re.compile(r"(^|/)(rpc|jsonrpc|grpc|connectrpc)(/|$|\?)", re.IGNORECASE)
#: Common API path prefixes (REST).
_REST_PATH_RE = re.compile(r"(^|/)(api|rest|v\d+)(/|$|\?)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Classification:
    """The classification result for one record.

    Attributes:
        api_kind: canonical API family.
        surface_form: evidence form.
        confidence: classification confidence in ``[0, 1]``.
        signals: matched signal descriptions (explainability).

    """

    api_kind: ApiKind
    surface_form: ApiSurfaceForm
    confidence: float
    signals: tuple[str, ...] = ()


class ApiClassifier:
    """Classify raw API intelligence records deterministically.

    Usage::

        classifier = ApiClassifier()
        classification = classifier.classify_observation(observation)
    """

    def classify_spec(self, spec: APISpecObservation) -> Classification:
        """Classify a located spec document."""
        spec_type = str(spec.spec_type or "").lower()
        if spec_type in ("openapi2", "openapi3", "openapi31", "swagger"):
            return Classification(ApiKind.REST, ApiSurfaceForm.OPENAPI, 1.0, ("spec-type:rest",))
        if spec_type == "wsdl":
            return Classification(ApiKind.SOAP, ApiSurfaceForm.WSDL, 1.0, ("spec-type:soap",))
        if spec_type == "graphql-sdl":
            return Classification(ApiKind.GRAPHQL, ApiSurfaceForm.GRAPHQL_SDL, 1.0, ("spec-type:graphql",))
        if spec_type == "postman":
            return Classification(ApiKind.REST, ApiSurfaceForm.POSTMAN, 0.9, ("spec-type:postman",))
        return Classification(ApiKind.UNKNOWN, ApiSurfaceForm.UNDOCUMENTED, 0.3, ("spec-type:unknown",))

    def classify_operation(self, operation: ApiOperationObservation) -> Classification:
        """Classify an endpoint operation from its path and content signals."""
        path = operation.path or ""
        content = f"{operation.content_type or ''} {operation.response_content_type or ''}"
        signals: list[str] = []

        if self._is_graphql(path, content):
            signals.append("path-or-content:graphql")
            return Classification(
                ApiKind.GRAPHQL,
                operation.surface_form,
                min(operation.confidence, 0.95),
                tuple(signals),
            )
        if self._is_websocket(path, content):
            signals.append("path-or-content:websocket")
            return Classification(
                ApiKind.WEBSOCKET,
                operation.surface_form,
                min(operation.confidence, 0.95),
                tuple(signals),
            )
        if self._is_soap(path, content):
            signals.append("path-or-content:soap")
            return Classification(
                ApiKind.SOAP,
                operation.surface_form,
                min(operation.confidence, 0.9),
                tuple(signals),
            )
        if self._is_rpc(path, content):
            signals.append("path-or-content:rpc")
            return Classification(
                ApiKind.RPC,
                operation.surface_form,
                min(operation.confidence, 0.85),
                tuple(signals),
            )

        # REST is the default posture for HTTP operations.
        if operation.method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            signals.append("http-method:rest-default")
            confidence = min(operation.confidence, 0.8)
            if self._is_rest(path):
                signals.append("path:rest")
                confidence = min(operation.confidence, 0.9)
            return Classification(ApiKind.REST, operation.surface_form, confidence, tuple(signals))

        return Classification(ApiKind.UNKNOWN, operation.surface_form, 0.3, ("no-signal",))

    def classify_origin(self, origin_key: str, api_kinds: list[str] | None = None) -> Classification:
        """Classify an origin from its API kind hints."""
        kinds = {str(item).lower() for item in (api_kinds or ())}
        if not kinds:
            lowered = origin_key.lower()
            if "graphql" in lowered:
                kinds = {ApiKind.GRAPHQL.value}
            elif "ws" in lowered or "socket" in lowered:
                kinds = {ApiKind.WEBSOCKET.value}
            elif "soap" in lowered:
                kinds = {ApiKind.SOAP.value}
            else:
                kinds = {ApiKind.REST.value}
        parsed: list[ApiKind] = []
        for item in kinds:
            try:
                parsed.append(ApiKind(item))
            except ValueError:
                continue
        return Classification(
            parsed[0] if len(parsed) == 1 else ApiKind.UNKNOWN,
            ApiSurfaceForm.UNDOCUMENTED,
            0.7 if parsed else 0.3,
            (f"origin-kinds:{','.join(sorted(kinds))}",),
        )

    def _is_graphql(self, path: str, content: str) -> bool:
        if _GRAPHQL_PATH_RE.search(path):
            return True
        return "graphql" in content.lower() or "application/graphql" in content.lower()

    def _is_websocket(self, path: str, content: str) -> bool:
        return bool(_WEBSOCKET_PATH_RE.search(path)) or "websocket" in content.lower()

    def _is_soap(self, path: str, content: str) -> bool:
        return bool(_SOAP_PATH_RE.search(path)) or "soap" in content.lower() or "wsdl" in content.lower()

    def _is_rpc(self, path: str, content: str) -> bool:
        return bool(
            _RPC_PATH_RE.search(path)
            or "jsonrpc" in content.lower()
            or "grpc" in content.lower()
            or "application/json-rpc" in content.lower()
        )

    def _is_rest(self, path: str) -> bool:
        return bool(_REST_PATH_RE.search(path))
