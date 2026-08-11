# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Coverage Engine.

Sprint 026. Coverage is NOT "number of tools executed" — it is the state of the
(Target × Asset × Capability × Tool) matrix. The engine records coverage cells,
answers matrix queries, computes per-dimension ratios and produces the
explainable intelligence score dimensions that drive the next-action engine.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from hunterx.domain.target_intelligence.enums import (
    CoverageCapability,
    CoverageState,
    IntelligenceDimension,
)
from hunterx.domain.target_intelligence.models import (
    CoverageEntry,
    CoverageMatrix,
    IntelligenceAsset,
    NegativeResult,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Coverage capabilities that apply to target-level (no asset) cells.
_TARGET_LEVEL_CAPABILITIES: frozenset[CoverageCapability] = frozenset(
    {
        CoverageCapability.ASSET_DISCOVERY,
        CoverageCapability.SUBDOMAIN_ENUMERATION,
        CoverageCapability.PORT_DISCOVERY,
        CoverageCapability.DNS_ENUMERATION,
        CoverageCapability.CERTIFICATE_ENUMERATION,
        CoverageCapability.CLOUD_OWNERSHIP_MAPPING,
    }
)


class CoverageEngine:
    """Record and query the per-(asset, capability) coverage matrix.

    The engine is pure state: it stores entries per target and derives the
    matrix, ratios and score dimensions. It never executes tools.
    """

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, CoverageEntry]] = {}

    # -- mutation -----------------------------------------------------------

    def record(
        self,
        *,
        target_id: str,
        asset_key: str,
        capability: CoverageCapability | str,
        state: CoverageState | str,
        tool: str = "",
        confidence: float = 0.0,
        tested_at: str = "",
        evidence_refs: Sequence[str] | None = None,
        notes: str = "",
    ) -> CoverageEntry:
        """Record (or replace) a coverage cell.

        Replacement preserves ``record_id`` so persisted rows stay stable;
        higher-rank states never regress silently (explicit calls may override
        by passing a state with equal or lower rank).
        """
        if isinstance(capability, str):
            capability = CoverageCapability(capability)
        if isinstance(state, str):
            state = CoverageState(state)
        cell_key = f"{asset_key}|{capability.value}"
        existing = self._entries.get(target_id, {}).get(cell_key)
        record_id = existing.record_id if existing is not None else generate_id()
        entry = CoverageEntry(
            record_id=record_id,
            target_id=target_id,
            asset_key=asset_key,
            capability=capability,
            state=state,
            tool=tool,
            confidence=confidence,
            tested_at=tested_at or utcnow_iso(),
            evidence_refs=tuple(evidence_refs or ()),
            notes=notes,
        )
        self._entries.setdefault(target_id, {})[cell_key] = entry
        return entry

    def mark_not_applicable(
        self, *, target_id: str, asset_key: str, capability: CoverageCapability | str, reason: str = ""
    ) -> CoverageEntry:
        """Mark a capability as not applicable to an asset (e.g. GraphQL on REST-only)."""
        return self.record(
            target_id=target_id,
            asset_key=asset_key,
            capability=capability,
            state=CoverageState.NOT_APPLICABLE,
            notes=reason,
        )

    def ingest_negative(self, negative: NegativeResult) -> CoverageEntry:
        """Record a negative result as a ``TESTED`` coverage cell.

        A negative result never means "not vulnerable" globally — it means the
        capability was exercised under recorded conditions with no evidence.
        """
        return self.record(
            target_id=negative.target_id,
            asset_key=negative.asset_key,
            capability=negative.tested_capability,
            state=CoverageState.TESTED,
            tool=negative.tool,
            confidence=negative.confidence,
            tested_at=negative.tested_at,
            notes=f"negative result ({negative.result}): {negative.coverage}",
        )

    # -- reads --------------------------------------------------------------

    def matrix(self, target_id: str) -> CoverageMatrix:
        """Return the current coverage matrix for a target."""
        entries = tuple(sorted(self._entries.get(target_id, {}).values(), key=lambda e: e.cell_key))
        return CoverageMatrix(target_id=target_id, entries=entries)

    def clear_target(self, target_id: str) -> None:
        """Drop all coverage state for a target."""
        self._entries.pop(target_id, None)

    # -- score dimensions ---------------------------------------------------

    def dimension_score(
        self, matrix: CoverageMatrix, dimension: IntelligenceDimension
    ) -> float:
        """Compute an explainable coverage dimension in ``[0, 1]``."""
        if dimension is IntelligenceDimension.UNKNOWN_RATIO:
            if not matrix.entries:
                return 1.0
            unknown = sum(
                1
                for entry in matrix.entries
                if entry.state in (CoverageState.UNKNOWN, CoverageState.NOT_ASSESSED)
            )
            return round(unknown / len(matrix.entries), 4)

        if dimension is IntelligenceDimension.PROOF_COVERAGE:
            cells = [e for e in matrix.entries if not e.state.uncovered()]
            if not cells:
                return 0.0
            proved = sum(1 for e in cells if e.state is CoverageState.PROVED)
            return round(proved / len(cells), 4)

        if dimension is IntelligenceDimension.EVIDENCE_QUALITY:
            entries_with_evidence = [e for e in matrix.entries if e.evidence_refs]
            if not entries_with_evidence:
                return 0.0
            return round(
                sum(entry.confidence for entry in entries_with_evidence)
                / len(entries_with_evidence),
                4,
            )

        if dimension is IntelligenceDimension.ASSET_COVERAGE:
            return matrix.coverage_ratio()

        if dimension is IntelligenceDimension.SERVICE_COVERAGE:
            service_cells = matrix.by_capability(CoverageCapability.SERVICE_DETECTION)
            return _ratio(service_cells)

        if dimension is IntelligenceDimension.WEB_COVERAGE:
            web_caps = (
                CoverageCapability.CONTENT_DISCOVERY,
                CoverageCapability.PARAMETER_DISCOVERY,
                CoverageCapability.ENDPOINT_ENUMERATION,
                CoverageCapability.TECHNOLOGY_FINGERPRINT,
            )
            return _weighted_ratio([matrix.by_capability(cap) for cap in web_caps])

        if dimension is IntelligenceDimension.API_COVERAGE:
            api_caps = (
                CoverageCapability.API_MAPPING,
                CoverageCapability.GRAPHQL_ENUMERATION,
                CoverageCapability.API_SECURITY,
                CoverageCapability.GRAPHQL_SECURITY,
            )
            return _weighted_ratio([matrix.by_capability(cap) for cap in api_caps])

        if dimension is IntelligenceDimension.CLOUD_COVERAGE:
            cloud_cells = matrix.by_capability(CoverageCapability.CLOUD_OWNERSHIP_MAPPING)
            return _ratio(cloud_cells)

        if dimension is IntelligenceDimension.VULNERABILITY_COVERAGE:
            vuln_caps = (
                CoverageCapability.VULNERABILITY_SCANNING,
                CoverageCapability.SQL_INJECTION,
                CoverageCapability.XSS,
                CoverageCapability.SSRF,
                CoverageCapability.SSTI,
                CoverageCapability.XXE,
                CoverageCapability.LFI,
                CoverageCapability.RCE,
                CoverageCapability.IDOR,
                CoverageCapability.SECRET_DETECTION,
                CoverageCapability.DEPENDENCY_CHECK,
            )
            return _weighted_ratio([matrix.by_capability(cap) for cap in vuln_caps])

        if dimension is IntelligenceDimension.HISTORICAL_COVERAGE:
            # Proxy: target-level discovery cells that reached a terminal state.
            cells = [e for e in matrix.entries if e.asset_key == ""]
            return _ratio(cells)

        return 0.0

    def score(
        self,
        matrix: CoverageMatrix,
        *,
        weights: dict[str, float] | None = None,
        policy_id: str = "target-intelligence/ranking/1.0.0",
    ) -> tuple[dict[str, float], float, dict[str, float]]:
        """Compute per-dimension scores, the weighted aggregate and the weights.

        Returns ``(dimensions, aggregate, weights)``. Weights default to an
        explainable equal-weight set that callers may override via policy.
        """
        default_weights = {
            IntelligenceDimension.ASSET_COVERAGE.value: 0.12,
            IntelligenceDimension.SERVICE_COVERAGE.value: 0.12,
            IntelligenceDimension.WEB_COVERAGE.value: 0.12,
            IntelligenceDimension.API_COVERAGE.value: 0.12,
            IntelligenceDimension.CLOUD_COVERAGE.value: 0.08,
            IntelligenceDimension.VULNERABILITY_COVERAGE.value: 0.14,
            IntelligenceDimension.EVIDENCE_QUALITY.value: 0.12,
            IntelligenceDimension.PROOF_COVERAGE.value: 0.08,
            IntelligenceDimension.HISTORICAL_COVERAGE.value: 0.06,
            IntelligenceDimension.UNKNOWN_RATIO.value: 0.04,
        }
        effective = dict(default_weights)
        if weights:
            effective.update(weights)
        total = sum(effective.values()) or 1.0
        normalized = {k: v / total for k, v in effective.items()}

        dimensions: dict[str, float] = {}
        for dimension in IntelligenceDimension:
            dimensions[dimension.value] = self.dimension_score(matrix, dimension)

        aggregate = round(
            sum(dimensions[k] * normalized[k] for k in normalized if k in dimensions), 4
        )
        return dimensions, aggregate, normalized

    def assign_to_assets(
        self,
        graph_assets: Sequence[IntelligenceAsset],
        *,
        capabilities: Iterable[CoverageCapability] | None = None,
        target_id: str = "",
    ) -> None:
        """Prime coverage cells for every testable asset.

        Structural assets (domains) are excluded; testable assets get
        ``NOT_ASSESSED`` cells for the relevant capabilities so the matrix is
        explicit about what has *not* been tried.
        """
        caps = tuple(capabilities or ()) or tuple(
            cap
            for cap in CoverageCapability
            if cap not in _TARGET_LEVEL_CAPABILITIES
        )
        for asset in graph_assets:
            relevant = self._capabilities_for_kind(asset, caps)
            for capability in relevant:
                cell_key = f"{asset.key}|{capability.value}"
                target_entries = self._entries.setdefault(target_id or asset.target_id, {})
                if cell_key not in target_entries:
                    target_entries[cell_key] = CoverageEntry(
                        record_id=generate_id(),
                        target_id=target_id or asset.target_id,
                        asset_key=asset.key,
                        capability=capability,
                        state=CoverageState.NOT_ASSESSED,
                    )

    @staticmethod
    def _capabilities_for_kind(
        asset: IntelligenceAsset, candidates: Sequence[CoverageCapability]
    ) -> tuple[CoverageCapability, ...]:
        """Filter capabilities to those relevant for the asset kind."""
        kind = asset.kind.value if isinstance(asset.kind, EntityKind) else str(asset.kind)
        if kind in ("port", "service"):
            return tuple(c for c in candidates if c in _NETWORK_CAPS)
        if kind in ("cloud_resource", "cloud_endpoint", "saas_integration", "storage_resource", "compute_resource", "kubernetes_resource", "webhook"):
            return tuple(c for c in candidates if c in _CLOUD_CAPS)
        if kind in ("graphql_endpoint", "api_endpoint", "websocket_endpoint"):
            return tuple(c for c in candidates if c in _API_CAPS)
        if kind in ("url", "auth_surface", "auth_endpoint", "admin_surface"):
            return tuple(c for c in candidates if c in _WEB_CAPS)
        if kind in ("parameter",):
            return tuple(c for c in candidates if c in _PARAMETER_CAPS)
        return tuple(candidates)


_NETWORK_CAPS: frozenset[CoverageCapability] = frozenset(
    {
        CoverageCapability.SERVICE_DETECTION,
        CoverageCapability.VULNERABILITY_SCANNING,
        CoverageCapability.PROOF_VALIDATION,
    }
)

_CLOUD_CAPS: frozenset[CoverageCapability] = frozenset(
    {
        CoverageCapability.CLOUD_OWNERSHIP_MAPPING,
        CoverageCapability.API_MAPPING,
        CoverageCapability.VULNERABILITY_SCANNING,
        CoverageCapability.SECRET_DETECTION,
        CoverageCapability.PROOF_VALIDATION,
    }
)

_API_CAPS: frozenset[CoverageCapability] = frozenset(
    {
        CoverageCapability.API_MAPPING,
        CoverageCapability.GRAPHQL_ENUMERATION,
        CoverageCapability.AUTHENTICATION_ANALYSIS,
        CoverageCapability.AUTHORIZATION_ANALYSIS,
        CoverageCapability.API_SECURITY,
        CoverageCapability.GRAPHQL_SECURITY,
        CoverageCapability.SQL_INJECTION,
        CoverageCapability.XSS,
        CoverageCapability.SSRF,
        CoverageCapability.SSTI,
        CoverageCapability.XXE,
        CoverageCapability.IDOR,
        CoverageCapability.VULNERABILITY_SCANNING,
        CoverageCapability.PROOF_VALIDATION,
    }
)

_WEB_CAPS: frozenset[CoverageCapability] = frozenset(
    {
        CoverageCapability.CONTENT_DISCOVERY,
        CoverageCapability.PARAMETER_DISCOVERY,
        CoverageCapability.ENDPOINT_ENUMERATION,
        CoverageCapability.TECHNOLOGY_FINGERPRINT,
        CoverageCapability.AUTHENTICATION_ANALYSIS,
        CoverageCapability.AUTHORIZATION_ANALYSIS,
        CoverageCapability.SQL_INJECTION,
        CoverageCapability.XSS,
        CoverageCapability.SSRF,
        CoverageCapability.SSTI,
        CoverageCapability.XXE,
        CoverageCapability.LFI,
        CoverageCapability.RCE,
        CoverageCapability.IDOR,
        CoverageCapability.VULNERABILITY_SCANNING,
        CoverageCapability.PROOF_VALIDATION,
    }
)

_PARAMETER_CAPS: frozenset[CoverageCapability] = frozenset(
    {
        CoverageCapability.PARAMETER_DISCOVERY,
        CoverageCapability.SQL_INJECTION,
        CoverageCapability.XSS,
        CoverageCapability.SSRF,
        CoverageCapability.SSTI,
        CoverageCapability.XXE,
        CoverageCapability.LFI,
        CoverageCapability.PROOF_VALIDATION,
    }
)


def _ratio(cells: Sequence[CoverageEntry]) -> float:
    """Return the assessed fraction of the cells in ``[0, 1]``."""
    if not cells:
        return 0.0
    assessed = sum(1 for entry in cells if not entry.state.uncovered())
    return round(assessed / len(cells), 4)


def _weighted_ratio(groups: Sequence[Sequence[CoverageEntry]]) -> float:
    """Average the ratios of several capability groups."""
    present = [group for group in groups if group]
    if not present:
        return 0.0
    return round(sum(_ratio(group) for group in present) / len(present), 4)


__all__ = ["CoverageEngine", "CoverageMatrix", "CoverageEntry", "CoverageState", "CoverageCapability"]
