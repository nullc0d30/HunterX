# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack-vector selection.

Phase 2. Maps a discovered surface to the attack vectors that actually apply:
a query parameter selects QUERY, a header selects HEADERS, a JSON field selects
JSON/API_BODY, a form field selects FORM, an upload selects MULTIPART, a GraphQL
operation selects GRAPHQL, an object identifier selects OBJECT_IDENTIFIER, a
workflow selects WORKFLOW_STATE, and so on. Only applicable vectors are
scheduled — never every vector against every surface.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.adaptive_attack.enums import AttackVector
from hunterx.domain.attack_surface.enums import AuthContextState, SurfaceKind
from hunterx.domain.attack_surface.models import SurfaceNode

#: Surface-kind string → applicable vectors (default rules). Kinds are strings
#: so adapters can register new mappings without core changes.
_DEFAULT_MAPPING: dict[str, tuple[AttackVector, ...]] = {
    SurfaceKind.PARAMETER.value: (AttackVector.QUERY,),
    SurfaceKind.PATH_VARIABLE.value: (AttackVector.PATH,),
    SurfaceKind.HEADER.value: (AttackVector.HEADERS,),
    SurfaceKind.COOKIE.value: (AttackVector.COOKIES,),
    SurfaceKind.JSON_FIELD.value: (AttackVector.JSON, AttackVector.API_BODY),
    SurfaceKind.FORM_FIELD.value: (AttackVector.FORM, AttackVector.API_BODY),
    SurfaceKind.FILE.value: (AttackVector.FILE, AttackVector.QUERY),
    SurfaceKind.UPLOAD.value: (AttackVector.MULTIPART,),
    SurfaceKind.DOWNLOAD.value: (AttackVector.DOWNLOAD, AttackVector.FILE),
    SurfaceKind.OBJECT.value: (AttackVector.OBJECT_IDENTIFIER, AttackVector.QUERY),
    SurfaceKind.OBJECT_IDENTIFIER.value: (AttackVector.OBJECT_IDENTIFIER, AttackVector.PATH, AttackVector.QUERY),
    SurfaceKind.API_ENDPOINT.value: (AttackVector.API_BODY, AttackVector.QUERY),
    SurfaceKind.GRAPHQL_OPERATION.value: (AttackVector.GRAPHQL, AttackVector.API_BODY),
    SurfaceKind.WEBSOCKET.value: (AttackVector.API_BODY,),
    SurfaceKind.REDIRECT.value: (AttackVector.REDIRECT, AttackVector.QUERY),
    SurfaceKind.CLIENT_ROUTE.value: (AttackVector.CLIENT_SIDE,),
    SurfaceKind.JAVASCRIPT_ENDPOINT.value: (AttackVector.CLIENT_SIDE,),
    SurfaceKind.SINK.value: (AttackVector.CLIENT_SIDE,),
    SurfaceKind.SOURCE.value: (AttackVector.CLIENT_SIDE,),
    SurfaceKind.AUTH_SURFACE.value: (AttackVector.AUTH_STATE, AttackVector.FORM),
    SurfaceKind.AUTH_STATE.value: (AttackVector.AUTH_STATE,),
    SurfaceKind.AUTHORIZATION_CONTEXT.value: (AttackVector.AUTHORIZATION_CONTEXT,),
    SurfaceKind.WORKFLOW.value: (AttackVector.WORKFLOW_STATE,),
    SurfaceKind.STATE_TRANSITION.value: (AttackVector.WORKFLOW_STATE,),
    SurfaceKind.ENDPOINT.value: (AttackVector.QUERY,),
    SurfaceKind.URL.value: (AttackVector.QUERY,),
    SurfaceKind.ROUTE.value: (AttackVector.QUERY,),
    SurfaceKind.UNKNOWN.value: (AttackVector.QUERY,),
}


class VectorSelector:
    """Selects the applicable attack vectors for a discovered surface.

    Args:
        extra_mapping: kind string → extra vectors merged over the defaults.

    """

    def __init__(self, extra_mapping: dict[str, tuple[AttackVector, ...]] | None = None) -> None:
        self._mapping: dict[str, tuple[AttackVector, ...]] = {
            kind: tuple(vectors) for kind, vectors in _DEFAULT_MAPPING.items()
        }
        if extra_mapping:
            for kind, vectors in extra_mapping.items():
                self._mapping[kind] = tuple(dict.fromkeys((*self._mapping.get(kind, ()), *vectors)))

    def register(self, kind: str, vectors: tuple[AttackVector, ...]) -> None:
        """Register applicable vectors for a surface kind (adapter extension)."""
        self._mapping[kind] = tuple(dict.fromkeys(vectors))

    def select(self, surface: SurfaceNode) -> list[AttackVector]:
        """Return the applicable vectors for ``surface``.

        Context adjustments refine the defaults: a POST surface selects
        body-carrying vectors (FORM/API_BODY), a JSON content type selects
        JSON, a fetch hint selects URL, an object hint on an endpoint selects
        OBJECT_IDENTIFIER, and an XML content type selects XML.
        """
        vectors = list(self._mapping.get(surface.kind_value(), ()))
        context = surface.context
        method = context.method.upper() if context.method else ""
        content_type = context.content_type.lower() if context.content_type else ""

        if method in ("POST", "PUT", "PATCH"):
            for vector in (AttackVector.API_BODY, AttackVector.FORM):
                if vector not in vectors:
                    vectors.append(vector)
        if ("application/json" in content_type or "application/graphql" in content_type) and AttackVector.JSON not in vectors:
            vectors.append(AttackVector.JSON)
        if ("application/xml" in content_type or "text/xml" in content_type) and AttackVector.XML not in vectors:
            vectors.append(AttackVector.XML)
        if "multipart" in content_type and AttackVector.MULTIPART not in vectors:
            vectors.append(AttackVector.MULTIPART)
        if context.fetch_hint and AttackVector.URL not in vectors:
            vectors.append(AttackVector.URL)
        if context.object_hint:
            for vector in (AttackVector.OBJECT_IDENTIFIER, AttackVector.QUERY, AttackVector.PATH):
                if vector not in vectors:
                    vectors.append(vector)
        if context.auth_state in (AuthContextState.AUTHENTICATED, AuthContextState.MULTI_USER) and AttackVector.AUTHORIZATION_CONTEXT not in vectors:
            vectors.append(AttackVector.AUTHORIZATION_CONTEXT)
        return vectors

    def supports(self, surface: SurfaceNode, vector: AttackVector) -> bool:
        """Return ``True`` when ``vector`` applies to ``surface``."""
        return vector in self.select(surface)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the mapping to a JSON-safe form."""
        return {
            "mappings": {
                kind: [vector.value for vector in vectors] for kind, vectors in sorted(self._mapping.items())
            }
        }


__all__ = ["VectorSelector"]
