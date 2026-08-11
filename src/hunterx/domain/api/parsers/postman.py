# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Postman collection parser.

In-process parser that models a Postman collection (JSON) into canonical API
intelligence observations. Used for documented REST surfaces.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.api.models import (
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

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


@dataclass(frozen=True, slots=True)
class PostmanParseResult:
    """The parsed contents of one Postman collection.

    Attributes:
        spec: the located spec observation.
        operations: endpoint operations parsed from the collection.

    """

    spec: APISpecObservation
    operations: tuple[ApiOperationObservation, ...] = ()

    def __len__(self) -> int:
        """Return the number of operations."""
        return len(self.operations)


class PostmanParser:
    """Parse a Postman collection JSON document into canonical operations."""

    def __init__(self, *, max_operations: int = 2000) -> None:
        self._max_operations = max_operations

    def parse(
        self,
        document: str | bytes | Mapping[str, Any],
        *,
        source_url: str = "",
    ) -> PostmanParseResult:
        """Parse a Postman collection."""
        if isinstance(document, Mapping):
            data = dict(document)
            raw = ""
        else:
            raw = _as_text(document)
            try:
                data = json.loads(raw)
            except (ValueError, TypeError) as exc:  # pragma: no cover - defensive
                raise ValueError(f"invalid Postman collection: {exc}") from exc
            if not isinstance(data, dict):
                raise ValueError("Postman collection must be an object")

        info = data.get("info") or {}
        title = str(info.get("name") or "")
        origin = _origin(source_url)
        operations = self._parse_items(data.get("item") or [], origin, source_url)
        spec = APISpecObservation(
            source_url=source_url,
            spec_type="postman",
            format="json",
            spec_version=str(info.get("version") or ""),
            title=title,
            operation_count=len(operations),
            schema_count=0,
            integrity=hashlib.sha256((raw or title).encode("utf-8")).hexdigest()[:32],
            size_bytes=len(raw.encode("utf-8")) if raw else 0,
            origin_key=origin,
            confidence=0.9,
            evidence=(
                ApiEvidence(
                    evidence_type=EvidenceType.SPEC_DOCUMENT,
                    value="postman collection",
                    source=source_url or "postman",
                    strength=EvidenceStrength.STRONG,
                    tool_id="api-hints",
                ),
            ),
            source="api-hints",
            tool_id="api-hints",
        )
        return PostmanParseResult(spec=spec, operations=tuple(operations[: self._max_operations]))

    def _parse_items(
        self,
        items: Sequence[Any],
        origin: str,
        source_url: str,
    ) -> list[ApiOperationObservation]:
        operations: list[ApiOperationObservation] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):
                operations.extend(self._parse_items(item["item"], origin, source_url))
                continue
            request = item.get("request")
            if not isinstance(request, dict):
                continue
            method = str(request.get("method") or "GET").upper()
            url = request.get("url") or {}
            path = _url_path(url)
            if method.lower() not in _HTTP_METHODS or not path:
                continue
            normalized = normalize_path(path)
            parameters = self._parse_url_params(url)
            operations.append(
                ApiOperationObservation(
                    origin_key=origin,
                    method=method,
                    path=path,
                    normalized_path=normalized,
                    path_hash=operation_hash(method, normalized),
                    operation_id=str(item.get("name") or ""),
                    api_kind=ApiKind.REST,
                    surface_form=ApiSurfaceForm.POSTMAN,
                    documented=True,
                    content_type=_body_content_type(request),
                    parameters=parameters,
                    confidence=0.9,
                    sources=(source_url or "postman",),
                    evidence=(
                        ApiEvidence(
                            evidence_type=EvidenceType.SPEC_DOCUMENT,
                            value=f"postman request {method} {path}",
                            source=source_url or "postman",
                            strength=EvidenceStrength.STRONG,
                            tool_id="api-hints",
                        ),
                    ),
                    source="api-hints",
                    tool_id="api-hints",
                )
            )
        return operations

    def _parse_url_params(self, url: object) -> tuple[ApiParameterObservation, ...]:
        """Parse query parameters from a Postman URL object."""
        if not isinstance(url, dict):
            return ()
        query = url.get("query") or []
        parameters: list[ApiParameterObservation] = []
        for item in query:
            if not isinstance(item, dict):
                continue
            parameters.append(
                ApiParameterObservation(
                    name=str(item.get("key") or ""),
                    location="query",
                    required=bool(item.get("disabled") is not True and item.get("value") not in (None, "")),
                    param_type="string",
                    default_value=_stringify(item.get("value")),
                    source="spec",
                    confidence=0.9,
                )
            )
        return tuple(parameters)


def _url_path(url: object) -> str:
    """Extract the path from a Postman URL (string or object)."""
    if isinstance(url, str):
        from urllib.parse import urlsplit

        return urlsplit(url).path or "/"
    if isinstance(url, dict):
        raw_path = url.get("path") or []
        if isinstance(raw_path, list):
            return "/" + "/".join(str(part) for part in raw_path if part)
        if isinstance(raw_path, str):
            return raw_path or "/"
    return "/"


def _body_content_type(request: Mapping[str, Any]) -> str:
    """Extract the request body content type."""
    body = request.get("body")
    if isinstance(body, dict):
        mode = body.get("mode")
        if mode == "graphql":
            return "application/json"
        if mode == "urlencoded":
            return "application/x-www-form-urlencoded"
        if mode == "raw":
            options = body.get("options")
            if isinstance(options, dict):
                raw = options.get("raw")
                if isinstance(raw, dict) and raw.get("language") == "json":
                    return "application/json"
            return "text/plain"
        return str(mode) if mode else ""
    return ""


def _origin(source_url: str) -> str:
    """Derive the origin from a collection's source URL."""
    from hunterx.domain.api.models import origin_of

    return origin_of(source_url) if source_url else "unknown"


def _stringify(value: object) -> str | None:
    """Return a string repr for scalar defaults."""
    if value is None:
        return None
    return str(value)


def _as_text(document: str | bytes) -> str:
    """Decode bytes safely."""
    if isinstance(document, bytes):
        return document.decode("utf-8", errors="replace")
    return str(document)
