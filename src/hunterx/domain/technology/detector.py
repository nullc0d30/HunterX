# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process signature detector.

The fallback (and in-process) technology detection path. Given an HTTP
evidence bundle — status, headers, HTML, meta tags, cookies, TLS certificate
fields and script references — it matches the curated signature database and
produces canonical :class:`TechnologyObservation` records with evidence
fragments and best-effort versions.

The detector is pure and deterministic: the same evidence always yields the
same observations. It never trusts a single weak indicator over stronger
evidence — confidence is a function of the evidence actually matched.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from hunterx.domain.technology.models import (
    EvidenceStrength,
    EvidenceType,
    TechnologyCategory,
    TechnologyEvidence,
    TechnologyFamily,
    TechnologyObservation,
    VersionConfidence,
    VersionSpec,
)
from hunterx.domain.technology.signatures import SignatureMatchMode, TechSignature
from hunterx.domain.technology.taxonomy import TechDefinition, catalog_by_name
from hunterx.shared.time import utcnow_iso

#: Evidence-type to strength weight used for the deterministic evidence score.
_STRENGTH_WEIGHTS: Mapping[EvidenceStrength, float] = {
    EvidenceStrength.STRONG: 1.0,
    EvidenceStrength.MODERATE: 0.6,
    EvidenceStrength.WEAK: 0.3,
}


@dataclass(frozen=True, slots=True)
class HttpEvidence:
    """An HTTP(S) evidence bundle collected for one asset.

    Attributes:
        url: the URL that was fetched.
        status_code: HTTP status code (``None`` when not observable).
        headers: response headers (lowercased names, original values).
        html: response body.
        cookies: cookie names/values returned by the server.
        title: document title when present.
        meta: meta tags (name -> content).
        scripts: script ``src`` references observed in the body.
        tls_subject: TLS certificate subject CN when observable.
        tls_issuer: TLS certificate issuer CN when observable.
        redirect_target: ``Location`` header value (empty when none).
        fetched_at: UTC ISO-8601 fetch timestamp.

    """

    url: str = ""
    status_code: int | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    html: str = ""
    cookies: Mapping[str, str] = field(default_factory=dict)
    title: str = ""
    meta: Mapping[str, str] = field(default_factory=dict)
    scripts: tuple[str, ...] = ()
    tls_subject: str = ""
    tls_issuer: str = ""
    redirect_target: str = ""
    fetched_at: str = field(default_factory=utcnow_iso)

    @property
    def has_signal(self) -> bool:
        """Return whether the bundle carries any observable signal.

        A bundle with no status, no headers and no body carries no signal, so
        the signature adapter can fall back to an alternate scheme.
        """
        return self.status_code is not None or bool(self.headers) or bool(self.html)


class SignatureDetector:
    """Match an evidence bundle against the signature database.

    Usage::

        detector = SignatureDetector()
        observations = detector.detect(
            evidence,
            asset="example.com",
            asset_type="hostname",
            tool_id="signature",
        )
    """

    def __init__(self, catalog: Mapping[str, TechDefinition] | None = None) -> None:
        self._catalog = dict(catalog) if catalog is not None else catalog_by_name()

    def detect(
        self,
        evidence: HttpEvidence,
        *,
        asset: str,
        asset_type: str = "hostname",
        tool_id: str = "signature",
        source: str = "",
        target_id: str | None = None,
        execution_id: str = "",
        correlation_id: str = "",
    ) -> list[TechnologyObservation]:
        """Detect technologies from ``evidence`` and return observations."""
        bundle = _build_evidence_map(evidence)
        detections: dict[str, list[TechSignature]] = {}
        versions: dict[str, tuple[str, EvidenceStrength]] = {}
        for technology in self._known_technologies():
            matched: list[TechSignature] = []
            best_version: tuple[str, EvidenceStrength] | None = None
            for signature in signatures_for_technology(technology):
                if _signature_matches(signature, bundle):
                    matched.append(signature)
                    version = _extract_version(signature, bundle)
                    if version and (
                        best_version is None
                        or _STRENGTH_WEIGHTS.get(signature.version_strength, 0.0)
                        > _STRENGTH_WEIGHTS.get(best_version[1], 0.0)
                    ):
                        best_version = (version, signature.version_strength)
            if matched:
                detections[technology] = matched
                if best_version is not None:
                    versions[technology] = best_version

        observations: list[TechnologyObservation] = []
        for technology, signatures in detections.items():
            definition = self._catalog.get(technology)
            evidence_fragments = tuple(
                TechnologyEvidence(
                    evidence_type=signature.evidence_type,
                    value=signature.pattern,
                    source=source or tool_id,
                    strength=signature.strength,
                    tool_id=tool_id,
                    detail=_matched_evidence(signature, bundle),
                )
                for signature in signatures
            )
            version, version_confidence = _resolve_version(versions.get(technology))
            version_spec = VersionSpec(
                value=version,
                confidence=version_confidence,
                evidence=tuple(
                    str(item.detail)
                    for item in evidence_fragments
                    if version and version in (item.detail or "")
                ),
            )
            observations.append(
                TechnologyObservation(
                    asset=asset,
                    asset_type=asset_type,
                    raw_name=technology,
                    canonical_name=technology,
                    vendor=definition.vendor if definition is not None else "",
                    product=definition.product if definition is not None else "",
                    version=version,
                    version_spec=version_spec if version else None,
                    category=definition.category if definition is not None else TechnologyCategory.OTHER,
                    family=definition.family if definition is not None else TechnologyFamily.OTHER,
                    confidence=_detection_confidence(signatures, definition),
                    evidence=evidence_fragments,
                    source=source or tool_id,
                    tool_id=tool_id,
                    target_id=target_id,
                    execution_id=execution_id,
                    correlation_id=correlation_id,
                )
            )
        observations.sort(key=lambda obs: (obs.asset, obs.canonical_name))
        return observations

    def _known_technologies(self) -> tuple[str, ...]:
        """Return every technology with signatures, in catalogue order."""
        from hunterx.domain.technology.signatures import SIGNATURES

        return tuple(name for name in self._catalog if name in SIGNATURES)


def signatures_for_technology(technology: str) -> tuple[TechSignature, ...]:
    """Return the signatures registered for a canonical technology."""
    from hunterx.domain.technology.signatures import signatures_for

    return signatures_for(technology)


def _build_evidence_map(evidence: HttpEvidence) -> dict[EvidenceType, list[str]]:
    """Render the evidence bundle into per-type evidence strings."""
    bundle: dict[EvidenceType, list[str]] = {
        EvidenceType.RESPONSE_HEADER: [],
        EvidenceType.COOKIE: [],
        EvidenceType.HTML: [],
        EvidenceType.META: [],
        EvidenceType.TLS_CERTIFICATE: [],
        EvidenceType.HTTP_STATUS: [],
        EvidenceType.URL_PATTERN: [],
        EvidenceType.JAVASCRIPT: [],
    }
    for name, value in evidence.headers.items():
        bundle[EvidenceType.RESPONSE_HEADER].append(f"{name.lower()}: {value}")
    bundle[EvidenceType.COOKIE].extend(str(name).lower() for name in evidence.cookies)
    body = evidence.html or ""
    bundle[EvidenceType.HTML].append(body)
    if evidence.title:
        bundle[EvidenceType.HTML].append(f"<title>{evidence.title}</title>")
    for name, value in evidence.meta.items():
        bundle[EvidenceType.META].append(f'name="{name}" content="{value}"')
    if evidence.tls_subject:
        bundle[EvidenceType.TLS_CERTIFICATE].append(evidence.tls_subject)
    if evidence.tls_issuer:
        bundle[EvidenceType.TLS_CERTIFICATE].append(evidence.tls_issuer)
    if evidence.status_code is not None:
        bundle[EvidenceType.HTTP_STATUS].append(str(evidence.status_code))
    path = _url_path(evidence.url)
    if path:
        bundle[EvidenceType.URL_PATTERN].append(path)
    bundle[EvidenceType.JAVASCRIPT].extend(evidence.scripts)
    return bundle


def _signature_matches(signature: TechSignature, bundle: Mapping[EvidenceType, list[str]]) -> bool:
    """Return whether a signature matches any evidence string of its type."""
    values = bundle.get(signature.evidence_type)
    if not values:
        return False
    if signature.mode is SignatureMatchMode.REGEX:
        try:
            compiled = re.compile(signature.pattern, re.IGNORECASE)
        except re.error:
            return False
        return any(compiled.search(value) for value in values)
    return any(signature.pattern.lower() in value.lower() for value in values)


def _extract_version(signature: TechSignature, bundle: Mapping[EvidenceType, list[str]]) -> str:
    """Extract a version from matched evidence using the signature's pattern."""
    if not signature.version_pattern:
        return ""
    values = bundle.get(signature.evidence_type) or ()
    if signature.mode is SignatureMatchMode.REGEX:
        try:
            compiled = re.compile(signature.pattern, re.IGNORECASE)
        except re.error:
            return ""
        for value in values:
            match = compiled.search(value)
            if match is None:
                continue
            version = _extract_version_from_match(match.string[match.start() :], signature.version_pattern)
            if version:
                return version
        return ""
    try:
        version_regex = re.compile(signature.version_pattern, re.IGNORECASE)
    except re.error:
        return ""
    for value in values:
        match = version_regex.search(value)
        if match is not None:
            return _extract_version_from_match(value, signature.version_pattern)
    return ""


def _extract_version_from_match(sample: str, version_pattern: str) -> str:
    """Extract the version capture group from a sample using ``version_pattern``."""
    group = 1
    pattern = version_pattern
    marker = "group:"
    if version_pattern.startswith(marker):
        try:
            group = int(version_pattern[len(marker) :])
        except ValueError:
            group = 1
        pattern = ""
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return ""
    match = compiled.search(sample)
    if match is None or group >= len(match.groups()) + 1:
        return ""
    return (match.group(group) or "").strip()


def _matched_evidence(signature: TechSignature, bundle: Mapping[EvidenceType, list[str]]) -> str:
    """Return the first evidence string a signature matched (for detail)."""
    values = bundle.get(signature.evidence_type) or ()
    for value in values:
        if _signature_matches(signature, {signature.evidence_type: [value]}):
            return value[:256]
    return ""


def _resolve_version(candidate: tuple[str, EvidenceStrength] | None) -> tuple[str, VersionConfidence]:
    """Map an extracted version + its evidence strength to a version spec."""
    if candidate is None:
        return "", VersionConfidence.UNKNOWN
    version, strength = candidate
    if not version:
        return "", VersionConfidence.UNKNOWN
    confidence = {
        EvidenceStrength.STRONG: VersionConfidence.CONFIRMED,
        EvidenceStrength.MODERATE: VersionConfidence.PROBABLE,
        EvidenceStrength.WEAK: VersionConfidence.UNKNOWN,
    }.get(strength, VersionConfidence.UNKNOWN)
    return version, confidence


def _detection_confidence(signatures: Sequence[TechSignature], definition: TechDefinition | None) -> float:
    """Compute a deterministic detection confidence from matched evidence."""
    weights = [_STRENGTH_WEIGHTS.get(signature.strength, 0.0) for signature in signatures]
    score = min(1.0, sum(weights) / 2.0)
    base = definition.base_confidence if definition is not None else 0.6
    return max(0.1, min(1.0, base * score))


def _url_path(url: str) -> str:
    """Return the path component of ``url`` (empty when unparseable)."""
    if not url:
        return ""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.path or ""
    except ValueError:  # pragma: no cover - defensive
        return ""
