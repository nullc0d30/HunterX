# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery domain models.

Pure data contracts for the universal discovery pipeline: a discovered asset
with full provenance (source provider, evidence, timestamp, confidence), the
outcome of one provider run, the aggregate of one stage, and the complete run.

No I/O and no execution here — the application layer drives the engine and
builds these structures; the attack-surface service consumes the derived
observations.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.discovery.enums import DiscoveryLayer, DiscoveryStage, DiscoveryState
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class DiscoveryEvidence:
    """One piece of provenance for a discovered asset.

    Attributes:
        provider: provider id that produced the asset.
        tool_id: tool id that produced the asset.
        source: upstream source (e.g. a crawler page, a JS bundle, a spec URL).
        evidence: short evidence fragment (header, URL, JS location, ...).
        timestamp: UTC ISO-8601 discovery timestamp.
        confidence: confidence in ``[0, 1]``.

    """

    provider: str
    tool_id: str = ""
    source: str = ""
    evidence: str = ""
    timestamp: str = field(default_factory=utcnow_iso)
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "provider": self.provider,
            "tool_id": self.tool_id,
            "source": self.source,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class DiscoveredAsset:
    """A canonical discovered asset with deduplication-friendly identity.

    Attributes:
        kind: generic asset kind (``host``, ``subdomain``, ``ip``, ``port``,
            ``service``, ``technology``, ``url``, ``endpoint``, ``api_endpoint``,
            ``graphql_operation``, ``websocket``, ``javascript_endpoint``,
            ``parameter``, ``object``, ``workflow``, ...).
        name: canonical identity of the asset (host, URL, port, ...).
        canonical_key: stable deduplication key (kind + canonical name).
        layer: :class:`DiscoveryLayer` the asset belongs to.
        attributes: extra typed attributes (port number, method, tech version...).
        evidence: provenance records from every provider that observed it.
        first_seen: UTC ISO-8601 first-observation timestamp.
        confidence: maximum confidence across evidence.

    """

    kind: str
    name: str
    canonical_key: str = ""
    layer: DiscoveryLayer | str = DiscoveryLayer.SURFACE
    attributes: Mapping[str, Any] = field(default_factory=dict)
    evidence: list[DiscoveryEvidence] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow_iso)
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if not self.canonical_key:
            object.__setattr__(self, "canonical_key", f"{self.kind}:{self.name}".lower())
        layer = self.layer
        if isinstance(layer, str):
            layer = _parse_layer(layer)
        if layer is DiscoveryLayer.SURFACE:
            layer = _layer_for_kind(self.kind)
        object.__setattr__(self, "layer", layer)
        evidence = list(self.evidence)
        object.__setattr__(self, "evidence", evidence)
        confidence = max((item.confidence for item in evidence), default=0.0)
        object.__setattr__(self, "confidence", max(self.confidence, confidence))

    def add_evidence(self, evidence: DiscoveryEvidence) -> None:
        """Append provenance and recompute the confidence (best-evidence)."""
        self.evidence.append(evidence)
        confidence = max((item.confidence for item in self.evidence), default=0.0)
        object.__setattr__(self, "confidence", max(self.confidence, confidence))

    def merge(self, other: DiscoveredAsset) -> None:
        """Merge another asset with the same canonical identity.

        Provenance is appended (deduplicated by provider + evidence), the
        first-seen timestamp is kept, and confidence rises to the best evidence.
        """
        for item in other.evidence:
            if any(existing.provider == item.provider and existing.evidence == item.evidence for existing in self.evidence):
                continue
            self.evidence.append(item)
        if other.first_seen and other.first_seen < self.first_seen:
            object.__setattr__(self, "first_seen", other.first_seen)
        confidence = max((item.confidence for item in self.evidence), default=0.0)
        object.__setattr__(self, "confidence", max(self.confidence, confidence))
        if other.attributes:
            merged = dict(self.attributes)
            merged.update(dict(other.attributes))
            object.__setattr__(self, "attributes", merged)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "kind": self.kind,
            "name": self.name,
            "canonical_key": self.canonical_key,
            "layer": self.layer.value if isinstance(self.layer, DiscoveryLayer) else str(self.layer),
            "attributes": dict(self.attributes),
            "evidence": [item.to_dict() for item in self.evidence],
            "first_seen": self.first_seen,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryProviderResult:
    """Outcome of running one discovery provider through the execution engine.

    Attributes:
        provider_id: provider identifier (tool id or derived stage).
        tool_id: actual tool id executed.
        state: :class:`DiscoveryState` outcome.
        error: error message when the provider failed (else ``""``).
        records: raw canonical records produced by the provider.
        assets: :class:`DiscoveredAsset` objects produced by the provider.
        duration_ms: execution duration in milliseconds.
        details: extra structured detail (payload summary, warnings).

    """

    provider_id: str
    tool_id: str = ""
    state: DiscoveryState | str = DiscoveryState.COMPLETED
    error: str = ""
    records: tuple[Any, ...] = ()
    assets: tuple[DiscoveredAsset, ...] = ()
    duration_ms: int = 0
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", _parse_state(self.state))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "provider_id": self.provider_id,
            "tool_id": self.tool_id,
            "state": self.state.value,
            "error": self.error,
            "records": len(self.records),
            "assets": len(self.assets),
            "duration_ms": self.duration_ms,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class DiscoveryStageResult:
    """Aggregate of one discovery stage.

    Attributes:
        stage: the :class:`DiscoveryStage`.
        state: aggregate state (``COMPLETED`` when every provider succeeded,
            ``PARTIAL`` when some failed, ``FAILED`` when all failed,
            ``UNAVAILABLE`` when no provider was available, ``NOT_APPLICABLE``
            when the stage does not apply).
        providers: per-provider results.
        assets: assets discovered by this stage.
        started_at / completed_at: UTC ISO-8601 boundaries.

    """

    stage: DiscoveryStage | str
    state: DiscoveryState | str = DiscoveryState.COMPLETED
    providers: list[DiscoveryProviderResult] = field(default_factory=list)
    assets: list[DiscoveredAsset] = field(default_factory=list)
    started_at: str = field(default_factory=utcnow_iso)
    completed_at: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage", _parse_stage(self.stage))
        object.__setattr__(self, "state", _parse_state(self.state))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "stage": self.stage.value if isinstance(self.stage, DiscoveryStage) else str(self.stage),
            "state": self.state.value,
            "providers": [provider.to_dict() for provider in self.providers],
            "assets": [asset.to_dict() for asset in self.assets],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass(slots=True)
class DiscoveryRun:
    """The complete result of one universal discovery run.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        target: the root target being discovered.
        mode: execution posture (``passive``/``active``/``hybrid``).
        stages: ordered stage results.
        assets: deduplicated assets across every stage.
        dedup: deduplication statistics (raw vs merged assets).
        summary: aggregated state summary.
        created_at: UTC ISO-8601 run timestamp.
        run_id: stable identifier for this run.

    """

    mission_id: str = ""
    target: str = ""
    mode: str = "hybrid"
    stages: list[DiscoveryStageResult] = field(default_factory=list)
    assets: list[DiscoveredAsset] = field(default_factory=list)
    dedup: Mapping[str, Any] = field(default_factory=dict)
    summary: Mapping[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)
    run_id: str = field(default_factory=lambda: f"discovery-{generate_id()[:12]}", kw_only=True)

    def add_stage(self, result: DiscoveryStageResult) -> None:
        """Append a stage result."""
        self.stages.append(result)

    def asset_count(self) -> int:
        """Return the number of deduplicated assets."""
        return len(self.assets)

    def stage_state(self, stage: DiscoveryStage) -> str:
        """Return the state of a stage (``unavailable`` when absent)."""
        for result in self.stages:
            if result.stage is stage:
                return result.state.value
        return DiscoveryState.UNAVAILABLE.value

    def provider_states(self) -> dict[str, str]:
        """Return ``{provider_id: state}`` across every stage."""
        states: dict[str, str] = {}
        for stage in self.stages:
            for provider in stage.providers:
                states[provider.provider_id] = provider.state.value
        return states

    def by_kind(self, kind: str) -> list[DiscoveredAsset]:
        """Return every deduplicated asset of ``kind``."""
        return [asset for asset in self.assets if asset.kind == kind]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "mode": self.mode,
            "stages": [stage.to_dict() for stage in self.stages],
            "assets": [asset.to_dict() for asset in self.assets],
            "dedup": dict(self.dedup),
            "summary": dict(self.summary),
            "created_at": self.created_at,
            "run_id": self.run_id,
        }


def _parse_state(value: DiscoveryState | str) -> DiscoveryState:
    if isinstance(value, DiscoveryState):
        return value
    return DiscoveryState(str(value).lower())


def _parse_layer(value: DiscoveryLayer | str) -> DiscoveryLayer:
    if isinstance(value, DiscoveryLayer):
        return value
    return DiscoveryLayer(str(value).lower())


def _parse_stage(value: DiscoveryStage | str) -> DiscoveryStage:
    if isinstance(value, DiscoveryStage):
        return value
    return DiscoveryStage(str(value).lower())


def _layer_for_kind(kind: str) -> DiscoveryLayer:
    """Map a generic asset kind to its discovery layer (surface fallback)."""
    if kind in ("host", "subdomain", "domain", "ip", "cidr"):
        return DiscoveryLayer.ASSET
    if kind in ("port", "service"):
        return DiscoveryLayer.SERVICE
    if kind == "technology":
        return DiscoveryLayer.APPLICATION
    if kind in ("parameter", "path_variable", "json_field", "form_field", "header", "cookie", "file", "upload", "download"):
        return DiscoveryLayer.INPUT
    if kind in ("object", "object_identifier", "sink", "source"):
        return DiscoveryLayer.OBJECT
    if kind in ("auth_surface", "auth_state", "authorization_context"):
        return DiscoveryLayer.STATE
    if kind in ("workflow", "state_transition"):
        return DiscoveryLayer.WORKFLOW
    return DiscoveryLayer.SURFACE


__all__ = [
    "DiscoveredAsset",
    "DiscoveryEvidence",
    "DiscoveryProviderResult",
    "DiscoveryRun",
    "DiscoveryStageResult",
]
