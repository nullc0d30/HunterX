# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Representative tool adapters for the Tool Intelligence Layer.

These are reference adapters showing how an integrated tool participates in the
Sprint 023 flow: an adapter runs, produces structured records, the declared
parser turns them into records and the declared normalizer turns them into
canonical observations. They are in-process (no binary required) so the layer
can be exercised end-to-end without external tools.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    ToolExecutionResult,
)
from hunterx.tools.intelligence.parsers import NormalizerRegistry, ParserRegistry
from hunterx.tools.intelligence.target import utc_now


class ReferenceToolAdapter:
    """Base for reference adapters producing canonical observations.

    Subclasses declare ``tool_id`` and implement :meth:`_produce_records`,
    which returns a list of raw record mappings. The adapter resolves the
    declared parser/normalizer from the registries and returns a
    :class:`ToolExecutionResult` carrying canonical observations.
    """

    tool_id: str = ""
    parser_id: str = "json"
    normalizer_id: str = "default"

    def __init__(
        self,
        parsers: ParserRegistry | None = None,
        normalizers: NormalizerRegistry | None = None,
    ) -> None:
        self.parsers = parsers or ParserRegistry()
        self.normalizers = normalizers or NormalizerRegistry()
        self.parsers.register_builtin()
        self.normalizers.register_builtin()

    def run(
        self,
        *,
        target: str,
        metadata: dict[str, Any],
        records: list[dict[str, Any]] | None = None,
    ) -> ToolExecutionResult:
        """Run the adapter and produce a structured execution result.

        ``records`` may be supplied directly (for tests) or computed via
        :meth:`_produce_records`.
        """
        if records is None:
            records = self._produce_records(target, metadata)
        parser = self.parsers.require(self.parser_id)
        normalizer = self.normalizers.require(self.normalizer_id)
        ctx = dict(metadata)
        ctx.setdefault("target_id", target)
        ctx.setdefault("tool_id", self.tool_id)
        parsed = parser(records, ctx)
        observations = tuple(normalizer(record, ctx) for record in parsed)
        return ToolExecutionResult(
            execution_id=f"exec-{self.tool_id}-{_nonce()}",
            tool_id=self.tool_id,
            tool_version=str(metadata.get("tool_version", "")),
            target_id=target,
            started_at=utc_now(),
            completed_at=utc_now(),
            exit_status="0",
            structured_output={"records": parsed},
            observations=observations,
        )

    def _produce_records(self, target: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        raise NotImplementedError

    def observations(
        self,
        *,
        target: str,
        metadata: dict[str, Any],
        records: list[dict[str, Any]] | None = None,
    ) -> tuple[CanonicalObservation, ...]:
        """Return only the canonical observations for a run."""
        return self.run(target=target, metadata=metadata, records=records).observations


class PortScannerAdapter(ReferenceToolAdapter):
    """Reference port/service scanner (nmap-like)."""

    tool_id = "portscanner"
    parser_id = "json"
    normalizer_id = "port"

    def _produce_records(self, target: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"port": 22, "service": "ssh", "confidence": 0.99},
            {"port": 80, "service": "http", "confidence": 0.98},
            {"port": 443, "service": "https", "confidence": 0.98},
        ]


class WebProbeAdapter(ReferenceToolAdapter):
    """Reference HTTP prober (httpx-like)."""

    tool_id = "webprobe"
    parser_id = "json"
    normalizer_id = "url"

    def _produce_records(self, target: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"url": f"https://{target}/", "status": 200, "title": "Example", "confidence": 1.0},
            {"url": f"https://{target}/admin", "status": 403, "confidence": 1.0},
        ]


class TechDetectorAdapter(ReferenceToolAdapter):
    """Reference technology detector (wappalyzer-like)."""

    tool_id = "techdetector"
    parser_id = "json"
    normalizer_id = "technology"

    def _produce_records(self, target: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"name": "Nginx", "version": "1.18.0", "confidence": 0.95},
            {"name": "React", "confidence": 0.9},
        ]


def _nonce() -> str:
    return str(abs(hash(utc_now())))[:12]


#: The reference adapter registry keyed by tool_id.
REFERENCE_ADAPTERS: dict[str, type[ReferenceToolAdapter]] = {
    "portscanner": PortScannerAdapter,
    "webprobe": WebProbeAdapter,
    "techdetector": TechDetectorAdapter,
}

__all__ = [
    "ReferenceToolAdapter",
    "PortScannerAdapter",
    "WebProbeAdapter",
    "TechDetectorAdapter",
    "REFERENCE_ADAPTERS",
]
