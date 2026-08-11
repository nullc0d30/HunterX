# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""GraphQL SDL / schema-shape parser.

In-process parser that turns GraphQL SDL (schema definition language) text into
canonical API intelligence observations: query/mutation/subscription operations
with their root fields, plus a schema fingerprint. No network and no
introspection probe — the parser consumes SDL that a prior tool already
captured.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hunterx.domain.api.models import (
    ApiEvidence,
    ApiKind,
    ApiOperationObservation,
    ApiSurfaceForm,
    EvidenceStrength,
    EvidenceType,
    normalize_path,
    operation_hash,
)

#: SDL operation-keyword prefixes.
_OPERATION_RE = re.compile(r"^\s*(type|extend type)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.MULTILINE)
_QUERY_BLOCK_RE = re.compile(r"^\s*(type\s+Query|type\s+Mutation|type\s+Subscription)\s*\{([^}]*)\}", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class GraphQLParseResult:
    """The parsed contents of one GraphQL SDL document.

    Attributes:
        operations: query/mutation/subscription operations parsed from SDL.
        types: number of named types in the schema.
        queries / mutations / subscriptions: normalized root-field paths.

    """

    operations: tuple[ApiOperationObservation, ...] = ()
    types: int = 0
    queries: tuple[str, ...] = ()
    mutations: tuple[str, ...] = ()
    subscriptions: tuple[str, ...] = ()

    def __len__(self) -> int:
        """Return the number of operations."""
        return len(self.operations)


class GraphQLParser:
    """Parse GraphQL SDL into canonical API intelligence observations.

    Usage::

        parser = GraphQLParser()
        result = parser.parse(sdl_text, origin="https://api.example.com")
    """

    def __init__(self, *, max_operations: int = 2000) -> None:
        self._max_operations = max_operations

    def parse(self, sdl: str, *, origin: str = "") -> GraphQLParseResult:
        """Parse GraphQL SDL text."""
        text = str(sdl or "")
        roots = _root_blocks(text)
        queries = _extract_fields(roots.get("Query", ""))
        mutations = _extract_fields(roots.get("Mutation", ""))
        subscriptions = _extract_fields(roots.get("Subscription", ""))
        types = len({match[1] for match in _OPERATION_RE.findall(text)}) or 0

        operations: list[ApiOperationObservation] = []
        for field in queries:
            operations.append(_graphql_operation(origin, "GET", f"/graphql?query={field}", "query", field))
        for field in mutations:
            operations.append(_graphql_operation(origin, "POST", "/graphql", "mutation", field))
        for field in subscriptions:
            operations.append(
                _graphql_operation(origin, "GET", f"/graphql?subscription={field}", "subscription", field)
            )
        if not operations and (queries or mutations or subscriptions):
            operations.append(_graphql_operation(origin, "GET", "/graphql", "query", ""))

        return GraphQLParseResult(
            operations=tuple(operations[: self._max_operations]),
            types=types,
            queries=tuple(queries),
            mutations=tuple(mutations),
            subscriptions=tuple(subscriptions),
        )


def _root_blocks(text: str) -> dict[str, str]:
    """Extract the body of Query/Mutation/Subscription type blocks."""
    roots: dict[str, str] = {}
    for match in _QUERY_BLOCK_RE.finditer(text):
        name = match.group(1).split()[-1]
        roots[name] = match.group(2)
    for match in _OPERATION_RE.finditer(text):
        name = match.group(2)
        if name in ("Query", "Mutation", "Subscription") and name not in roots:
            start = match.end()
            brace = text.find("{", start)
            if brace != -1:
                depth = 0
                i = brace
                while i < len(text):
                    if text[i] == "{":
                        depth += 1
                    elif text[i] == "}":
                        depth -= 1
                        if depth == 0:
                            roots[name] = text[brace + 1 : i]
                            break
                    i += 1
    return roots


def _extract_fields(block: str) -> list[str]:
    """Extract top-level field names from a GraphQL type block body."""
    fields: list[str] = []
    for line in block.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith(("#", "}", "{")):
            continue
        field = re.split(r"[:(]", cleaned, maxsplit=1)[0].strip()
        if field and not field.startswith(('"', "'")):
            fields.append(field)
    return fields


def _graphql_operation(
    origin: str,
    method: str,
    path: str,
    operation_type: str,
    field: str,
) -> ApiOperationObservation:
    """Build an operation observation for a GraphQL root field."""
    normalized = normalize_path("/graphql")
    description = f"graphql {operation_type}:{field}" if field else f"graphql {operation_type}"
    return ApiOperationObservation(
        origin_key=origin,
        method=method,
        path=path,
        normalized_path=normalized,
        path_hash=operation_hash(method, normalized),
        operation_id=field or operation_type,
        api_kind=ApiKind.GRAPHQL,
        surface_form=ApiSurfaceForm.GRAPHQL_SDL,
        documented=True,
        tags=(operation_type,),
        content_type="application/json",
        response_content_type="application/json",
        confidence=0.95,
        sources=("api-graphql",),
        evidence=(
            ApiEvidence(
                evidence_type=EvidenceType.SPEC_DOCUMENT,
                value=description,
                source="graphql-sdl",
                strength=EvidenceStrength.STRONG,
                tool_id="api-graphql",
            ),
        ),
        source="api-graphql",
        tool_id="api-graphql",
    )
