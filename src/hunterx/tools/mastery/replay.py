# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool result replay.

Supports replaying a stored tool result through parser, normalizer and
evidence mapping without re-running the external tool. Required for
debugging, regression testing, parser/knowledge upgrades and historical
analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from hunterx.tools.mastery.regression import (
    NormalizerFn,
    ParserFn,
    ParserRegressionEngine,
)


@dataclass(frozen=True, slots=True)
class StoredToolResult:
    """A persisted tool execution result that can be replayed.

    Attributes:
        execution_id: original execution identifier.
        tool_id: the tool that produced the result.
        tool_version: tool version at execution time.
        raw: the preserved raw artifact (string or JSON structure).
        structured_output: previously parsed structured output (optional).
        metadata: parser metadata (target id, mission id, scope id, ...).
        provenance: provenance metadata.

    """

    execution_id: str
    tool_id: str
    tool_version: str = ""
    raw: Any = ""
    structured_output: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Outcome of replaying a stored tool result.

    Attributes:
        execution_id: original execution identifier.
        tool_id: tool identifier.
        parser_id: parser used.
        normalizer_id: normalizer used.
        record_count: records produced by the parser.
        observations: observations produced by the normalizer.
        success: whether replay completed without error.
        error: error message when replay failed.

    """

    execution_id: str
    tool_id: str
    parser_id: str = ""
    normalizer_id: str = ""
    record_count: int = 0
    observations: list[dict[str, Any]] = field(default_factory=list)
    success: bool = True
    error: str = ""


class ToolResultReplay:
    """Replay stored tool results through parser + normalizer pairs."""

    def __init__(
        self,
        engine: ParserRegressionEngine | None = None,
        parser_for: dict[str, str] | None = None,
    ) -> None:
        self._engine = engine or ParserRegressionEngine()
        #: tool_id -> parser_id used to replay that tool's output.
        self._parser_for: dict[str, str] = dict(parser_for or {})

    @property
    def engine(self) -> ParserRegressionEngine:
        """The underlying regression engine (parsers/normalizers)."""
        return self._engine

    def register_tool_parser(self, tool_id: str, parser_id: str) -> None:
        """Bind ``tool_id`` to a parser id for replay."""
        self._parser_for[tool_id] = parser_id

    def replay(self, stored: StoredToolResult, parser_id: str | None = None) -> ReplayResult:
        """Replay ``stored`` through its parser and normalizer.

        Args:
            stored: the stored tool result.
            parser_id: explicit parser id; defaults to the tool's bound parser
                or the built-in ``json`` parser.

        """
        pid = parser_id or self._parser_for.get(stored.tool_id, "json")
        metadata = dict(stored.metadata)
        metadata["tool_id"] = stored.tool_id
        metadata["tool_version"] = stored.tool_version

        try:
            records = self._resolve_parser(pid)(stored.raw, metadata)
        except Exception as exc:  # noqa: BLE001 - replay must not raise
            return ReplayResult(
                execution_id=stored.execution_id,
                tool_id=stored.tool_id,
                parser_id=pid,
                success=False,
                error=str(exc),
            )

        normalizer = self._engine_parser().get(pid)
        observations: list[dict[str, Any]] = []
        if normalizer is not None:
            for record in records:
                observation = normalizer(record, metadata)
                observations.append(_to_dict(observation))
        else:
            observations = [dict(r) for r in records]

        return ReplayResult(
            execution_id=stored.execution_id,
            tool_id=stored.tool_id,
            parser_id=pid,
            normalizer_id=self._normalizer_id(pid),
            record_count=len(records),
            observations=observations,
            success=True,
        )

    # -- internal helpers ---------------------------------------------------

    def _resolve_parser(self, parser_id: str) -> ParserFn:
        from hunterx.tools.intelligence.normalizers import _parse_records

        # Bind tool-specific parsers registered via the public engine API.
        custom = self._engine._parsers.get(parser_id)  # noqa: SLF001 - intentional introspection
        if custom is not None:
            return custom
        return _parse_records

    def _engine_parser(self) -> dict[str, NormalizerFn]:
        return self._engine._normalizers  # noqa: SLF001 - intentional introspection

    def _normalizer_id(self, parser_id: str) -> str:
        meta = self._engine._metadata.get(parser_id, {})  # noqa: SLF001
        return str(meta.get("normalizer_id", parser_id))


def _to_dict(observation: Any) -> dict[str, Any]:
    if isinstance(observation, dict):
        return dict(observation)
    if hasattr(observation, "observation_kind"):
        return {
            "observation_kind": observation.observation_kind,
            "value": observation.value,
            "normalized_value": observation.normalized_value,
            "confidence": observation.confidence,
            "correlation_key": observation.correlation_key,
        }
    return {"value": str(observation)}


def load_stored_result(path: str) -> StoredToolResult:
    """Load a stored result envelope from a JSON file on disk."""
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    return StoredToolResult(
        execution_id=str(payload.get("execution_id", "")),
        tool_id=str(payload.get("tool_id", "")),
        tool_version=str(payload.get("tool_version", "")),
        raw=payload.get("raw", ""),
        structured_output=payload.get("structured_output", {}),
        metadata=payload.get("metadata", {}),
        provenance=payload.get("provenance", {}),
    )


def save_stored_result(result: StoredToolResult, path: str) -> None:
    """Persist a stored result envelope to a JSON file on disk."""
    payload = {
        "execution_id": result.execution_id,
        "tool_id": result.tool_id,
        "tool_version": result.tool_version,
        "raw": result.raw,
        "structured_output": result.structured_output,
        "metadata": result.metadata,
        "provenance": result.provenance,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
