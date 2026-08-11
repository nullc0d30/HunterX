# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology intelligence TIDB entities.

System-of-record entities for the Sprint 011 technology fingerprinting
capability: the canonical technology catalogue (categories, families,
definitions), the per-asset technology observations with their evidence and
version specifications, and the derived intelligence (conflicts, changes and
fingerprint run records). All technology intelligence that matters is persisted
here — never only in memory, logs or reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class TechnologyCategory(TidbEntity):
    """A canonical taxonomy category (e.g. ``web-server``).

    Attributes:
        name: canonical category key (one of the technology taxonomy values).
        family: default technology family for the category.
        description: human description.

    """

    name: str
    family: str = "other"
    description: str = ""


@dataclass(slots=True)
class TechnologyFamily(TidbEntity):
    """A canonical technology family (e.g. ``web-server``, ``cdn``).

    Attributes:
        name: canonical family key.
        description: human description.

    """

    name: str
    description: str = ""


@dataclass(slots=True)
class TechnologyDefinition(TidbEntity):
    """A canonical technology catalogue entry.

    Attributes:
        canonical_name: canonical display name (e.g. ``Nginx``).
        aliases: alternative spellings that resolve to this technology.
        vendor: technology vendor.
        product: canonical product name.
        category: canonical taxonomy category.
        family: canonical technology family.
        description: short human description.
        base_confidence: confidence of a weak-signature-only detection.

    """

    canonical_name: str
    aliases: list[str] = field(default_factory=list)
    vendor: str = ""
    product: str = ""
    category: str = "other"
    family: str = "other"
    description: str = ""
    base_confidence: float = 0.9


@dataclass(slots=True)
class TechnologyObservation(TidbEntity):
    """A persisted technology detection on one asset.

    Attributes:
        asset: canonical asset identifier (hostname, domain, IP or URL).
        asset_type: canonical asset kind.
        raw_name: technology name exactly as observed.
        canonical_name: resolved canonical technology name.
        vendor: technology vendor when known.
        product: canonical product name when known.
        software_version: resolved version value.
        version_confidence: version confidence state
            (``confirmed``/``probable``/``range``/``unknown``).
        category: canonical taxonomy category.
        family: canonical technology family.
        confidence: detection confidence in ``[0, 1]``.
        evidence_count: number of evidence fragments supporting the detection.
        source: upstream source of the observation.
        tool_id: the tool that produced the observation.
        validation_status: ``valid``/``unknown``/``invalid``.
        target_id: owning target record id when in-scope.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.
        mission_id: owning mission id (empty for ad-hoc runs).

    """

    asset: str
    asset_type: str = "hostname"
    raw_name: str = ""
    canonical_name: str = ""
    vendor: str = ""
    product: str = ""
    software_version: str = ""
    version_confidence: str = "unknown"
    category: str = "other"
    family: str = "other"
    confidence: float = 1.0
    evidence_count: int = 0
    source: str = ""
    tool_id: str = ""
    validation_status: str = "valid"
    target_id: str | None = None
    execution_id: str = ""
    correlation_id: str = ""
    mission_id: str = ""


@dataclass(slots=True)
class TechnologyVersion(TidbEntity):
    """An evidence-backed version specification for a technology.

    Attributes:
        observation_id: owning technology observation.
        asset: canonical asset identifier.
        canonical_name: canonical technology name.
        value: the version value (``""`` when unknown).
        confidence: version confidence state.
        lower: inclusive lower bound when only a range is known.
        upper: inclusive upper bound when only a range is known.
        evidence: evidence fragments that support the version.
        tool_id: the tool that produced the version.

    """

    observation_id: str
    asset: str
    canonical_name: str
    value: str = ""
    confidence: str = "unknown"
    lower: str = ""
    upper: str = ""
    evidence: list[str] = field(default_factory=list)
    tool_id: str = ""


@dataclass(slots=True)
class TechnologyEvidence(TidbEntity):
    """A persisted detection evidence fragment.

    Attributes:
        observation_id: owning technology observation.
        asset: canonical asset identifier.
        canonical_name: canonical technology name.
        evidence_type: kind of source (header, cookie, html, ...).
        value: the raw indicator observed.
        source: upstream source of the evidence.
        strength: relative strength (strong/moderate/weak).
        tool_id: tool that produced the evidence.
        detail: contextual detail (e.g. the header line matched).

    """

    observation_id: str
    asset: str
    canonical_name: str
    evidence_type: str = "other"
    value: str = ""
    source: str = ""
    strength: str = "moderate"
    tool_id: str = ""
    detail: str = ""


@dataclass(slots=True)
class TechnologyConflict(TidbEntity):
    """A preserved contradiction about one technology on one asset.

    Attributes:
        asset: the affected asset.
        technology: the canonical technology name.
        observations: the disagreeing observations with provenance.
        conflict_type: ``version``, ``identity`` or ``presence``.
        selected_value: the canonical value selected.
        selected_source: provenance of the selected value.
        reason: human-readable explanation of the selection.
        confidence: confidence in the selected value in ``[0, 1]``.
        mission_id: owning mission.
        correlation_id: correlation id of the detecting run.

    """

    asset: str
    technology: str
    observations: list[dict[str, object]] = field(default_factory=list)
    conflict_type: str = "version"
    selected_value: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class TechnologyChange(TidbEntity):
    """A temporal change in the technology state of an asset.

    Attributes:
        asset: the affected asset.
        technology: the canonical technology name.
        change_type: ``added``, ``removed`` or ``changed``.
        old_value: previous value (empty for added technologies).
        new_value: current value (empty for removed technologies).
        tool_id: tool that produced the current observation.
        confidence: confidence of the new value.
        mission_id: owning mission.
        correlation_id: correlation id of the detecting run.

    """

    asset: str
    technology: str
    change_type: str = "added"
    old_value: str = ""
    new_value: str = ""
    tool_id: str = ""
    confidence: float = 1.0
    mission_id: str = ""
    correlation_id: str = ""


@dataclass(slots=True)
class TechnologyRun(TidbEntity):
    """Observability record for a fingerprinting run.

    Attributes:
        mission_id: owning mission.
        target_key: canonical key of the target the run covered.
        status: run status (running/completed/failed/partial).
        observations: raw technology observations collected.
        technologies: distinct canonical technologies retained.
        versions: technologies with an evidence-backed version.
        conflicts: conflicts detected and preserved.
        changes: historical changes detected.
        started_at: run start stamp.
        completed_at: run completion stamp (``None`` while running).
        duration_ms: wall-clock duration in milliseconds.
        summary: free-form summary of the run.
        correlation_id: correlation id of the run.

    """

    mission_id: str = ""
    target_key: str = ""
    status: str = "running"
    observations: int = 0
    technologies: int = 0
    versions: int = 0
    conflicts: int = 0
    changes: int = 0
    started_at: str = ""
    completed_at: str | None = None
    duration_ms: int = 0
    summary: dict[str, object] = field(default_factory=dict)
    correlation_id: str = ""
