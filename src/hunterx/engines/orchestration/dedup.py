# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution deduplication.

Prevents duplicate tool execution when the same target, tool, version, relevant
input and configuration would be executed within the configured freshness
window. Explicit forced refresh bypasses the cache.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.time import utcnow_iso


def execution_hash(
    *,
    tool_id: str,
    target: str,
    tool_version: str = "",
    parameters: dict[str, Any] | None = None,
    configuration: str = "",
) -> str:
    """Compute a deterministic execution hash from the execution identity.

    The hash covers the tool, target, version, normalized parameters and
    configuration so that identical executions deduplicate deterministically.
    """
    payload = {
        "tool_id": tool_id,
        "target": target,
        "tool_version": tool_version,
        "parameters": _sorted_parameters(parameters or {}),
        "configuration": configuration,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sorted_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    """Recursively sort parameter keys for a deterministic hash."""
    result: dict[str, Any] = {}
    for key in sorted(parameters):
        value = parameters[key]
        if isinstance(value, dict):
            result[key] = _sorted_parameters(value)
        elif isinstance(value, (list, tuple, set)):
            result[key] = [repr(item) for item in value]
        else:
            result[key] = value
    return result


@dataclass(slots=True)
class ExecutionRecord:
    """A recorded execution for deduplication.

    Attributes:
        execution_id: the recorded execution identifier.
        input_hash: the execution input hash.
        tool_id: executed tool.
        target: executed target.
        completed_at: UTC ISO-8601 completion timestamp.
        status: terminal status.
        result_summary: JSON-safe summary of the normalized result.

    """

    execution_id: str = ""
    input_hash: str = ""
    tool_id: str = ""
    target: str = ""
    completed_at: str = field(default_factory=utcnow_iso)
    status: str = "completed"
    result_summary: dict[str, Any] = field(default_factory=dict)


class ExecutionDeduplicator:
    """In-memory execution deduplicator with a freshness window.

    A freshness window of ``0`` disables deduplication (every execution is
    considered fresh). ``forced_refresh`` always bypasses the deduplicator.
    """

    def __init__(self, *, freshness_window_seconds: int = 0) -> None:
        self._freshness = freshness_window_seconds
        self._records: dict[str, ExecutionRecord] = {}

    @property
    def freshness_window_seconds(self) -> int:
        """Return the configured freshness window."""
        return self._freshness

    def record(self, record: ExecutionRecord) -> None:
        """Record an execution for deduplication."""
        self._records[record.input_hash] = record

    def lookup(self, input_hash: str) -> ExecutionRecord | None:
        """Return a fresh cached record for ``input_hash`` or ``None``."""
        record = self._records.get(input_hash)
        if record is None:
            return None
        if not self._fresh_fresh(record):
            return None
        return record

    def is_duplicate(self, input_hash: str) -> bool:
        """Return ``True`` when ``input_hash`` has a fresh cached execution."""
        return self.lookup(input_hash) is not None

    def clear(self) -> None:
        """Clear every cached record."""
        self._records.clear()

    def _fresh_fresh(self, record: ExecutionRecord) -> bool:
        """Return ``True`` when the record is within the freshness window.

        A freshness window of ``0`` disables deduplication entirely.
        """
        if self._freshness <= 0:
            return False
        try:
            import datetime

            completed = datetime.datetime.fromisoformat(record.completed_at)
            now = datetime.datetime.now(datetime.UTC)
            if completed.tzinfo is None:
                completed = completed.replace(tzinfo=datetime.UTC)
            return (now - completed).total_seconds() <= self._freshness
        except ValueError:
            return True
