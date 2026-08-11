# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for vulnerability knowledge providers.

Every external vulnerability-knowledge source (NVD, CISA KEV, MITRE CVE/CWE,
EPSS, vendor advisories, GHSA/OSV) integrates with HunterX through the Tool
Integration SDK :class:`ToolAdapter` lifecycle. This base class defines the
provider contract: each provider adapter receives raw source material through
the execution parameters, normalizes it to the canonical vulnerability models
and serializes the records into the pipeline's JSON payload under the
``vulnerabilities``/``knowledge`` keys.

No provider may bypass the SDK. No provider ever downloads, executes or verifies
exploits — normalization is data-in/data-out.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.vulnerability.enums import KnowledgeSourceKind
from hunterx.domain.vulnerability.models import (
    VULNERABILITY_KEY,
    Vulnerability,
    VulnerabilityKnowledgeBatch,
    vulnerabilities_from_payload,
)
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class VulnerabilityProviderAdapter(ToolAdapter, abc.ABC):
    """Shared base for in-process vulnerability knowledge adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`ingest`, which
    normalizes one raw provider payload and returns the canonical
    :class:`VulnerabilityKnowledgeBatch`. The default :meth:`run` serializes the
    batch into the pipeline JSON payload.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    #: Provider kind reported in the payload for provenance.
    provider_kind: KnowledgeSourceKind = KnowledgeSourceKind.CUSTOM

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required for in-process normalizers; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    @abc.abstractmethod
    def ingest(self, raw: Any, *, source: str = "") -> VulnerabilityKnowledgeBatch:
        """Normalize a raw provider payload into a canonical knowledge batch."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Read the raw payload from parameters, ingest and emit the result."""
        params = context.parameters or {}
        raw = params.get("raw", params.get("payload", params.get("knowledge")))
        source = str(params.get("source") or context.tool_id)
        batch = self.ingest(raw, source=source)
        collector.set_exit_code(0)
        collector.set_json(
            {
                VULNERABILITY_KEY: [vulnerability.to_dict() for vulnerability in batch.vulnerabilities],
                "kev": [record.to_dict() for record in batch.kev_records],
                "epss": [record.to_dict() for record in batch.epss_records],
                "cwes": [cwe.to_dict() for cwe in batch.cwes],
                "advisories": [advisory.to_dict() for advisory in batch.advisories],
                "count": len(batch.vulnerabilities),
                "source": source,
                "provider_kind": self.provider_kind.value,
                "correlation_id": context.correlation_id,
            }
        )

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty knowledge sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project normalized vulnerabilities into the canonical tool output."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get(VULNERABILITY_KEY), list):
            tool_output.assets = [entry for entry in payload[VULNERABILITY_KEY] if isinstance(entry, dict)]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    @staticmethod
    def vulnerabilities_from_payload(payload: Any) -> list[Vulnerability]:
        """Return canonical vulnerabilities from a provider payload mapping."""
        if isinstance(payload, dict):
            return vulnerabilities_from_payload(payload)
        return []


__all__ = ["VulnerabilityProviderAdapter"]
