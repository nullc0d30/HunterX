# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability Proof Strategy report views and builders.

Presentation-facing projection of the Sprint 022 strategy intelligence layer.
The builder aggregates strategies, the evidence matrix, proof validation results
and strategy candidates into a renderer-friendly view that explains WHY a proof
was (or was not) validated: which security property was tested, which strategy
was selected, which evidence was required, which was present/missing, what was
contradictory, what the replay showed and what impact was legitimately claimed.
Reports never expose secrets.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.vulnerability_proof.matrix import EvidenceMatrix, EvidenceMatrixRow
from hunterx.domain.vulnerability_proof.strategy import (
    ProofStrategy,
    ProofValidationResult,
    StrategyCandidate,
)
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class StrategyReportView:
    """The full data surface of a strategy report.

    Attributes:
        report_id: stable report identifier.
        generated_at: UTC ISO-8601.
        registry_version: strategy registry schema version.
        matrix_version: evidence matrix schema version.
        strategies: strategy projections.
        evidence_matrix: matrix projections.
        validation_results: proof validation result projections.
        strategy_candidates: strategy candidate projections.
        metadata: free-form metadata.

    """

    report_id: str = ""
    generated_at: str = ""
    registry_version: str = "1.0.0"
    matrix_version: str = "1.0.0"
    strategies: tuple[dict[str, Any], ...] = ()
    evidence_matrix: tuple[dict[str, Any], ...] = ()
    validation_results: tuple[dict[str, Any], ...] = ()
    strategy_candidates: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "registry_version": self.registry_version,
            "matrix_version": self.matrix_version,
            "strategies": list(self.strategies),
            "evidence_matrix": list(self.evidence_matrix),
            "validation_results": list(self.validation_results),
            "strategy_candidates": list(self.strategy_candidates),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> StrategyReportView:
        """Rebuild a view from JSON-safe report data."""

        def _dicts(key: str) -> tuple[dict[str, Any], ...]:
            return tuple(dict(item) for item in data.get(key) or () if isinstance(item, dict))

        matrix = data.get("evidence_matrix") or {}
        rows = tuple(dict(item) for item in (matrix.get("rows") or []) if isinstance(item, dict))
        return cls(
            report_id=str(data.get("report_id") or ""),
            generated_at=str(data.get("generated_at") or ""),
            registry_version=str(data.get("registry_version") or "1.0.0"),
            matrix_version=str(matrix.get("version") or data.get("matrix_version") or "1.0.0"),
            strategies=_dicts("strategies"),
            evidence_matrix=rows,
            validation_results=_dicts("validation_results"),
            strategy_candidates=_dicts("strategy_candidates"),
            metadata=dict(data.get("metadata") or {}),
        )


class StrategyReportBuilder:
    """Aggregate strategy intelligence records into a :class:`StrategyReportView`.

    Example::

        builder = StrategyReportBuilder()
        view = builder.build(
            strategies=[...], matrix=matrix,
            validation_results=[...], candidates=[...],
        )
    """

    def build(
        self,
        *,
        strategies: Sequence[ProofStrategy] = (),
        matrix: EvidenceMatrix | None = None,
        validation_results: Sequence[ProofValidationResult] = (),
        candidates: Sequence[StrategyCandidate] = (),
        registry_version: str = "1.0.0",
        report_id: str = "",
    ) -> StrategyReportView:
        """Aggregate the strategy records into a report view."""
        from hunterx.shared.ids import generate_id

        matrix_rows = (
            tuple(_matrix_row(item) for item in matrix.rows) if matrix is not None else ()
        )
        return StrategyReportView(
            report_id=report_id or generate_id(),
            generated_at=utcnow_iso(),
            registry_version=registry_version,
            matrix_version=matrix.version() if matrix is not None else "1.0.0",
            strategies=tuple(strategy.to_dict() for strategy in strategies),
            evidence_matrix=matrix_rows,
            validation_results=tuple(result.to_dict() for result in validation_results),
            strategy_candidates=tuple(candidate.to_dict() for candidate in candidates),
        )


def _matrix_row(row: EvidenceMatrixRow) -> dict[str, Any]:
    return row.to_dict()


__all__ = ["StrategyReportBuilder", "StrategyReportView"]
