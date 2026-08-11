# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""CLI output rendering."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

import yaml


class OutputRenderer:
    """Render command results in a requested format.

    Formats: ``text`` (default), ``json``, ``yaml`` and ``csv``.
    """

    def render(self, data: Any, *, fmt: str = "text") -> str:
        """Render ``data`` into ``fmt`` and return a string."""
        formatter = {
            "json": self._json,
            "yaml": self._yaml,
            "csv": self._csv,
            "text": self._text,
        }.get(fmt)
        if formatter is None:
            raise ValueError(f"Unsupported output format '{fmt}'.")
        return formatter(data)

    @staticmethod
    def _json(data: Any) -> str:
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def _yaml(data: Any) -> str:
        return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)

    @staticmethod
    def _text(data: Any) -> str:
        if isinstance(data, str):
            return data
        if isinstance(data, list):
            if not data:
                return ""
            if isinstance(data[0], dict):
                return OutputRenderer._table(data)
            return "\n".join(str(item) for item in data)
        if isinstance(data, dict):
            return "\n".join(f"{key}: {value}" for key, value in data.items())
        return str(data)

    @staticmethod
    def _table(rows: list[dict[str, Any]]) -> str:
        if not rows:
            return ""
        headers = list(rows[0].keys())
        lines = ["\t".join(headers)]
        for row in rows:
            lines.append("\t".join(str(row.get(header, "")) for header in headers))
        return "\n".join(lines)

    @staticmethod
    def _csv(data: Any) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            writer.writerow(data[0].keys())
            for row in data:
                writer.writerow(row.values())
        else:
            writer.writerow(data if isinstance(data, (list, tuple)) else [data])
        return buffer.getvalue()
