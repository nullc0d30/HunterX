# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""WebSocket endpoint parser.

In-process parser that models discovered WebSocket endpoints from web-crawl
and client-side observations into canonical API intelligence operations. No
network activity: the parser consumes already-observed endpoint hints.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

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


@dataclass(frozen=True, slots=True)
class WebSocketParseResult:
    """The parsed WebSocket endpoints.

    Attributes:
        operations: WebSocket endpoint operations.

    """

    operations: tuple[ApiOperationObservation, ...] = ()

    def __len__(self) -> int:
        """Return the number of endpoints."""
        return len(self.operations)


class WebSocketParser:
    """Parse WebSocket endpoint hints into canonical operations.

    Usage::

        parser = WebSocketParser()
        result = parser.parse([("https://api.example.com", "/socket"), ...])
    """

    def __init__(self, *, max_operations: int = 500) -> None:
        self._max_operations = max_operations

    def parse(self, hints: Sequence[tuple[str, str]] | Sequence[dict[str, Any]]) -> WebSocketParseResult:
        """Parse WebSocket endpoint hints to operations.

        Each hint is an ``(origin_key, path)`` tuple or a dict with
        ``origin_key``/``path`` keys.
        """
        operations: list[ApiOperationObservation] = []
        for hint in hints:
            if len(operations) >= self._max_operations:
                break
            origin, path = _unpack_hint(hint)
            if not origin or not path:
                continue
            normalized = normalize_path(path)
            operations.append(
                ApiOperationObservation(
                    origin_key=origin,
                    method="WS",
                    path=path,
                    normalized_path=normalized,
                    path_hash=operation_hash("WS", normalized),
                    api_kind=ApiKind.WEBSOCKET,
                    surface_form=ApiSurfaceForm.UNDOCUMENTED,
                    documented=False,
                    tags=("websocket",),
                    confidence=0.85,
                    sources=("api-websocket",),
                    evidence=(
                        ApiEvidence(
                            evidence_type=EvidenceType.TIDB_INTELLIGENCE,
                            value=f"websocket endpoint {path}",
                            source="api-websocket",
                            strength=EvidenceStrength.MODERATE,
                            tool_id="api-websocket",
                        ),
                    ),
                    source="api-websocket",
                    tool_id="api-websocket",
                )
            )
        return WebSocketParseResult(operations=tuple(operations))


def _unpack_hint(hint: tuple[str, str] | dict[str, Any]) -> tuple[str, str]:
    """Normalize a hint to an ``(origin, path)`` pair."""
    if isinstance(hint, dict):
        return str(hint.get("origin_key") or ""), str(hint.get("path") or "")
    if isinstance(hint, (tuple, list)) and len(hint) >= 2:
        return str(hint[0]), str(hint[1])
    return "", ""
