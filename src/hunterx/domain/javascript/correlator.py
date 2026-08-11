# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Correlation of JavaScript intelligence findings across assets.

Aggregates per-asset analyses into a run-level view: deduplicates by canonical
key, merges evidence and provenance, re-scores confidence from multiplicity, and
produces the correlated collections stored on a :class:`JavaScriptBatch`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace

from hunterx.domain.javascript.confidence import JSConfidenceEngine
from hunterx.domain.javascript.models import (
    JSAcquisition,
    JSAssetAnalysis,
    JSAuthenticationReference,
    JSConfigurationIndicator,
    JSDependency,
    JSDynamicImport,
    JSEndpoint,
    JSEvidence,
    JSExternalDomain,
    JSRoute,
    JSSecurityIndicator,
    JSStorageIndicator,
    JSThirdPartyService,
    JSWasmReference,
    JSWorker,
)

#: Finding types that carry an ``evidence`` tuple and a ``confidence`` field.
_FINDING_KINDS = (
    "endpoints",
    "routes",
    "auth",
    "domains",
    "services",
    "storage",
    "technology",
    "dependencies",
    "configuration",
    "workers",
    "wasm",
    "security",
    "dynamic_imports",
)

#: Attribute name on each finding that holds the evidence sequence.
_EVIDENCE_ATTRS = {
    "endpoints": "evidence",
    "routes": "evidence",
    "auth": "evidence",
    "domains": "evidence",
    "services": "evidence",
    "storage": "evidence",
    "technology": "evidence",
    "dependencies": "evidence",
    "configuration": "evidence",
    "workers": "evidence",
    "wasm": "evidence",
    "security": "evidence",
    "dynamic_imports": "evidence",
}


@dataclass(frozen=True, slots=True)
class JSCorrelationResult:
    """The correlated outcome of a JavaScript run.

    Attributes:
        assets: correlated asset acquisitions (one per content hash).
        endpoints / routes / auth / domains / services / storage / secrets /
        technology / dependencies / configuration / source_maps / workers /
        wasm / security / dynamic_imports: correlated findings.
        evidence: merged evidence fragments.
        total_findings: count of correlated findings.

    """

    assets: list[JSAcquisition] = ()
    endpoints: list[JSEndpoint] = ()
    routes: list[JSRoute] = ()
    auth: list[JSAuthenticationReference] = ()
    domains: list[JSExternalDomain] = ()
    services: list[JSThirdPartyService] = ()
    storage: list[JSStorageIndicator] = ()
    secrets: list[object] = ()
    technology: list[object] = ()
    dependencies: list[JSDependency] = ()
    configuration: list[JSConfigurationIndicator] = ()
    source_maps: list[object] = ()
    workers: list[JSWorker] = ()
    wasm: list[JSWasmReference] = ()
    security: list[JSSecurityIndicator] = ()
    dynamic_imports: list[JSDynamicImport] = ()
    evidence: list[JSEvidence] = ()

    @property
    def total_findings(self) -> int:
        """Return the number of correlated findings."""
        return sum(
            len(items)
            for items in (
                self.endpoints,
                self.routes,
                self.auth,
                self.domains,
                self.services,
                self.storage,
                self.secrets,
                self.technology,
                self.dependencies,
                self.configuration,
                self.source_maps,
                self.workers,
                self.wasm,
                self.security,
                self.dynamic_imports,
            )
        )

    def as_batch_lists(self) -> dict[str, list[object]]:
        """Return the correlated lists keyed by their batch attribute name."""
        return {
            "assets": list(self.assets),
            "endpoints": list(self.endpoints),
            "routes": list(self.routes),
            "auth": list(self.auth),
            "domains": list(self.domains),
            "services": list(self.services),
            "storage": list(self.storage),
            "secrets": list(self.secrets),
            "technology": list(self.technology),
            "dependencies": list(self.dependencies),
            "configuration": list(self.configuration),
            "source_maps": list(self.source_maps),
            "workers": list(self.workers),
            "wasm": list(self.wasm),
            "security": list(self.security),
            "dynamic_imports": list(self.dynamic_imports),
        }


class JSCorrelator:
    """Correlate per-asset analyses into a run-level result."""

    def __init__(
        self,
        *,
        confidence: JSConfidenceEngine | None = None,
    ) -> None:
        self._confidence = confidence or JSConfidenceEngine()

    def correlate(self, analyses: Iterable[JSAssetAnalysis]) -> JSCorrelationResult:
        """Correlate a set of per-asset analyses."""
        analysis_list = list(analyses)
        result_kwargs: dict[str, list[object]] = {"assets": _correlate_assets(analysis_list)}
        for kind in _FINDING_KINDS:
            result_kwargs[kind] = _correlate_findings(
                analysis_list,
                kind,
                self._confidence,
            )
        return JSCorrelationResult(**result_kwargs)  # type: ignore[arg-type]


def _correlate_assets(analyses: list[JSAssetAnalysis]) -> list[JSAcquisition]:
    """Return one acquisition per content hash (deterministic order)."""
    seen: dict[str, JSAcquisition] = {}
    for analysis in analyses:
        asset = analysis.asset
        key = asset.content_hash or asset.key()
        if key not in seen or asset.acquired_at < seen[key].acquired_at:
            seen[key] = asset
    return list(seen.values())


def _correlate_findings(
    analyses: list[JSAssetAnalysis],
    kind: str,
    confidence: JSConfidenceEngine,
) -> list[object]:
    """Deduplicate findings of ``kind`` by their ``key()`` and merge evidence."""
    buckets: dict[str, list[object]] = {}
    for analysis in analyses:
        for finding in getattr(analysis, kind) or ():
            key = _finding_key(finding)
            buckets.setdefault(key, []).append(finding)

    merged: list[object] = []
    for _key, findings in buckets.items():
        first = findings[0]
        evidence_attr = _EVIDENCE_ATTRS.get(kind)
        if evidence_attr is None or not hasattr(first, evidence_attr):
            merged.append(first)
            continue
        evidence = _merge_evidence(findings, evidence_attr)
        score = confidence.adjust(
            float(getattr(first, "confidence", 1.0)),
            evidence_count=len(evidence),
            source_count=len(findings),
        )
        merged.append(
            replace(
                first,
                **{evidence_attr: tuple(evidence), "confidence": score},
            )
        )
    merged.sort(key=lambda finding: _finding_key(finding))
    return merged


def _merge_evidence(findings: list[object], attr: str) -> list[JSEvidence]:
    """Merge the evidence sequences of ``findings`` without duplicates."""
    merged: list[JSEvidence] = []
    seen: set[str] = set()
    for finding in findings:
        for item in getattr(finding, attr) or ():
            digest = item.integrity or f"{item.location}:{item.value}"
            if digest in seen:
                continue
            seen.add(digest)
            merged.append(item)
    return merged


def _finding_key(finding: object) -> str:
    """Return the canonical deduplication key of a finding."""
    key_fn = getattr(finding, "dedup_key", None)
    if key_fn is None:
        key_fn = getattr(finding, "key", None)
    if callable(key_fn):
        return str(key_fn())
    return str(finding)
