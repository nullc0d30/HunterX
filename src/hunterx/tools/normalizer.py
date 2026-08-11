# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Normalizer engine.

Normalizers convert structured parser records into canonical domain objects
(findings, evidence, assets). Normalization is where cross-tool naming,
severity and risk conventions are enforced.
"""

from __future__ import annotations

from hunterx.domain.entities import Finding
from hunterx.domain.exceptions import InvalidFindingError
from hunterx.domain.value_objects import Severity
from hunterx.plugins.sdk.results import EvidenceResult, FindingResult
from hunterx.tools.adapter import ToolOutput


class NormalizerEngine:
    """Normalize parsed records into canonical tool output.

    A ``kind`` field in a record selects the target object:
    ``finding`` (default), ``evidence`` or ``asset``.
    """

    def __init__(self, *, default_tool: str = "unknown") -> None:
        self._default_tool = default_tool

    def normalize(self, records: list[dict[str, object]], *, tool: str | None = None) -> ToolOutput:
        """Convert records to a :class:`ToolOutput`."""
        tool = tool or self._default_tool
        output = ToolOutput()
        for record in records:
            kind = str(record.get("kind", "finding")).lower()
            if kind == "evidence":
                output.evidence.append(
                    EvidenceResult(
                        content=str(record.get("content", "")),
                        mime_type=str(record.get("mime_type", "text/plain")),
                    )
                )
            elif kind == "asset":
                output.assets.append(
                    {
                        "name": record.get("name", ""),
                        "asset_type": record.get("asset_type", "unknown"),
                        "properties": record.get("properties", {}),
                    }
                )
            else:
                output.findings.append(
                    FindingResult(
                        title=str(record.get("title", "")),
                        severity=str(record.get("severity", "medium")).lower(),
                        target=str(record.get("target", "")),
                        description=str(record.get("description", "")),
                        risk_score=_as_optional_float(record.get("risk_score")),
                        metadata=record.get("metadata", {}) if isinstance(record.get("metadata"), dict) else {},
                    )
                )
        return output

    @staticmethod
    def to_domain(output: ToolOutput, *, tool: str, mission_id: str | None = None) -> list[Finding]:
        """Project a :class:`ToolOutput` into domain finding entities.

        Findings are built with computed content hashes; risk scores and
        severities are validated here.
        """
        findings: list[Finding] = []
        for result in output.findings:
            try:
                severity = Severity.from_str(result.severity)
            except InvalidFindingError:
                severity = Severity.MEDIUM
            finding = Finding(
                title=result.title,
                severity=severity,
                target=result.target,
                tool=tool,
                mission_id=mission_id,
                description=result.description,
                risk_score=result.risk_score,
                metadata=dict(result.metadata),
            )
            finding.compute_content_hash()
            findings.append(finding)
        return findings


def _as_optional_float(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None
