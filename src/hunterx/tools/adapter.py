# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool adapter SDK.

Defines the contract every tool (scanner, crawler, enumerator, analyzer,
reporter) implements. A tool receives a target and parameters and returns a
normalized :class:`ToolOutput` containing findings, evidence and assets.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.tools import ToolDescriptor
from hunterx.plugins.sdk.results import EvidenceResult, FindingResult
from hunterx.shared.time import monotonic_ms

__all__ = ["ToolOutput", "ToolContext", "BaseTool"]


@dataclass(slots=True)
class ToolOutput:
    """Normalized result of a single tool execution.

    Attributes:
        findings: verified findings produced.
        evidence: supporting evidence attached.
        assets: discovered assets (name, type, properties).
        raw: raw tool output for parsers.
        duration_ms: execution time in milliseconds.
        error: error message when the tool failed.

    """

    findings: list[FindingResult] = field(default_factory=list)
    evidence: list[EvidenceResult] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    raw: Any = None
    duration_ms: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        """Return ``True`` when the tool completed without error."""
        return not self.error


class ToolContext:
    """Runtime context passed to a tool execution.

    Attributes:
        mission_id: owning mission (may be empty for ad-hoc runs).
        secrets_resolver: callable resolving a secret name to its value.

    """

    def __init__(self, mission_id: str = "", *, secrets_resolver: Any = None) -> None:
        self.mission_id = mission_id
        self._secrets_resolver = secrets_resolver

    def secret(self, name: str) -> str:
        """Resolve a secret for the tool's use."""
        if self._secrets_resolver is None:
            raise RuntimeError("Secrets access is not enabled in this tool context.")
        return self._secrets_resolver(name)


class BaseTool(abc.ABC):
    """Abstract base class for all tool adapters.

    Subclasses declare a :class:`~hunterx.domain.tools.ToolDescriptor` and
    implement :meth:`execute`.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    @abc.abstractmethod
    def execute(self, target: str, parameters: dict[str, Any], context: ToolContext) -> ToolOutput:
        """Execute the tool against ``target`` and return its output."""

    def run(self, target: str, parameters: dict[str, Any], context: ToolContext | None = None) -> ToolOutput:
        """Execute the tool, always returning a :class:`ToolOutput`.

        Exceptions raised by :meth:`execute` are captured into ``output.error``
        so callers never have to handle tool crashes separately.
        """
        started = monotonic_ms()
        context = context or ToolContext()
        output = ToolOutput()
        try:
            output = self.execute(target, parameters, context)
        except Exception as exc:  # noqa: BLE001 - tool isolation boundary
            output.error = f"{type(exc).__name__}: {exc}"
        finally:
            output.duration_ms = monotonic_ms() - started
        return output

    def supports(self, target_kind: str) -> bool:
        """Return ``True`` when this tool supports ``target_kind``."""
        return target_kind in self.descriptor.targets
