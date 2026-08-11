# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding-layer Target Intelligence Database entities.

History, evidence, risk and reference entities that attach to the canonical
``Finding``/``Evidence`` aggregates defined in ``hunterx.domain.entities``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class FindingHistory(TidbEntity):
    """An immutable snapshot of a finding at a point in time.

    Attributes:
        finding_id: owning finding.
        finding_version: finding version this snapshot represents.
        finding_revision: finding revision this snapshot represents.
        severity: severity at snapshot time.
        status: finding status at snapshot time.
        title: title at snapshot time.
        description: description at snapshot time.
        delta: JSON map of fields changed since the previous revision.
        changed_by: actor that made the change.

    """

    finding_id: str
    finding_version: int = 1
    finding_revision: int = 1
    severity: str = "info"
    status: str = "new"
    title: str = ""
    description: str = ""
    delta: dict[str, object] = field(default_factory=dict)
    changed_by: str | None = None


@dataclass(slots=True)
class EvidenceAttachment(TidbEntity):
    """A file or blob attached to an evidence record.

    Attributes:
        evidence_id: owning evidence.
        object_key: object-store key.
        file_path: local/relative path.
        size: size in bytes.
        sha256: content hash.
        mime_type: content MIME type.

    """

    evidence_id: str
    object_key: str | None = None
    file_path: str | None = None
    size: int | None = None
    sha256: str | None = None
    mime_type: str | None = None


@dataclass(slots=True)
class RiskRating(TidbEntity):
    """A computed or overridden risk rating for a finding.

    Attributes:
        finding_id: owning finding.
        score: composite score in ``[0, 10]``.
        vector: map of rating components
            (``{exploitability, impact, exposure, likelihood, detectability}``).
        formula_version: risk model version.
        overrides: ``{reason, by}`` map for human overrides.
        calculated_at: calculation timestamp (ISO).

    """

    finding_id: str
    score: float = 0.0
    vector: dict[str, object] = field(default_factory=dict)
    formula_version: str = "1.0.0"
    overrides: dict[str, object] = field(default_factory=dict)
    calculated_at: str | None = None


@dataclass(slots=True)
class SeverityBand(TidbEntity):
    """Reference definition of a severity band.

    Attributes:
        name: severity name (info|low|medium|high|critical).
        score_min: inclusive lower bound.
        score_max: inclusive upper bound.
        description: band description.

    """

    name: str
    score_min: float = 0.0
    score_max: float = 10.0
    description: str = ""


@dataclass(slots=True)
class ConfidenceLevel(TidbEntity):
    """Reference definition of a confidence band.

    Attributes:
        name: band name.
        min_value: inclusive lower bound.
        max_value: inclusive upper bound.
        description: band description.

    """

    name: str
    min_value: float = 0.0
    max_value: float = 1.0
    description: str = ""


@dataclass(slots=True)
class Recommendation(TidbEntity):
    """Mitigation guidance attached to a finding.

    Attributes:
        finding_id: owning finding.
        text: recommendation text.
        category: fix|workaround|hardening|process|... .
        priority: priority within the finding.

    """

    finding_id: str
    text: str
    category: str = "fix"
    priority: int = 0


@dataclass(slots=True)
class Reference(TidbEntity):
    """An external reference attached to a finding.

    Attributes:
        finding_id: owning finding.
        kind: cve|cwe|capec|url|article|advisory|... .
        url: reference URL.
        title: reference title.
        source: reference source name.

    """

    finding_id: str
    kind: str = "url"
    url: str | None = None
    title: str | None = None
    source: str | None = None


@dataclass(slots=True)
class Validation(TidbEntity):
    """A validation attempt for a finding.

    Attributes:
        finding_id: owning finding.
        method: active|manual|correlation|tool-verification.
        result: success|failure|inconclusive.
        validator: validator/step identifier.
        payload_ref: payload used for validation.
        detail: free-form result detail map.
        validated_at: validation timestamp (ISO).

    """

    finding_id: str
    method: str = "manual"
    result: str = "inconclusive"
    validator: str | None = None
    payload_ref: str | None = None
    detail: dict[str, object] = field(default_factory=dict)
    validated_at: str | None = None


@dataclass(slots=True)
class Verification(TidbEntity):
    """A verification verdict for a finding.

    Attributes:
        finding_id: owning finding.
        verdict: confirmed|refuted|inconclusive|accepted|reported.
        verifier: verifier identifier.
        evidence_ids: identifiers of supporting evidence.
        notes: free-form notes.
        verified_at: verification timestamp (ISO).

    """

    finding_id: str
    verdict: str = "inconclusive"
    verifier: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    notes: str = ""
    verified_at: str | None = None
