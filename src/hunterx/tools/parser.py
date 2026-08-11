# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parser engine.

Parsers convert raw tool output (stdout, files, JSON) into a structured,
schema-shaped representation that the normalizer can consume. A parser is a
callable mapping ``(tool_name, raw)`` to a list of structured records.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hunterx.domain.exceptions import ToolExecutionError

#: A parser maps raw output to a list of structured records.
Parser = Callable[[str, Any], list[dict[str, Any]]]


class ParserEngine:
    """Route raw output to the right parser and apply it.

    The default parser accepts raw JSON (list or single dict) and returns it
    as records. Tool-specific parsers may be registered by tool name.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}

    def register(self, tool: str, parser: Parser) -> None:
        """Register a parser for a tool name."""
        self._parsers[tool] = parser

    @staticmethod
    def _default(tool: str, raw: Any) -> list[dict[str, Any]]:
        del tool  # the default parser is format-driven, not tool-specific
        if isinstance(raw, str):
            import json

            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ToolExecutionError("Raw output is not valid JSON for the default parser.") from exc
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
        if isinstance(raw, dict):
            return [raw]
        raise ToolExecutionError(f"Raw output of type {type(raw).__name__} is not parseable as records.")

    def parse(self, tool: str, raw: Any) -> list[dict[str, Any]]:
        """Parse ``raw`` using the registered parser for ``tool``.

        Raises:
            ToolExecutionError: if parsing fails.

        """
        parser = self._parsers.get(tool, self._default)
        try:
            records = parser(tool, raw)
        except ToolExecutionError:
            raise
        except Exception as exc:
            raise ToolExecutionError(f"Parser for '{tool}' failed: {exc}") from exc
        return records
