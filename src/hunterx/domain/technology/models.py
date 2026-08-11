# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology fingerprinting canonical domain models.

Pure data contracts for the technology intelligence capability: the canonical
technology observation, version specification, evidence fragments, conflicts,
historical changes, execution summaries, the collection strategy and the batch
that carries everything back to the application layer. No I/O and no execution
here.

The TIDB ``technology`` entities
(:mod:`hunterx.domain.entities.tidb.technology`) are the persistence projection
of these models; this module is the runtime surface the fingerprinting pipeline
is built on.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class TechnologyCategory(StrEnum):
    """Canonical technology taxonomy categories.

    These are the normalized buckets every detected technology is mapped into.
    Tools may report free-form categories; the taxonomy resolver collapses them
    onto this canonical set.
    """

    WEB_SERVER = "web-server"
    APPLICATION_SERVER = "application-server"
    CMS = "cms"
    FRAMEWORK = "framework"
    JAVASCRIPT = "javascript"
    FRONTEND = "frontend"
    BACKEND = "backend"
    DATABASE = "database"
    CDN = "cdn"
    WAF = "waf"
    PROXY = "proxy"
    LOAD_BALANCER = "load-balancer"
    CLOUD = "cloud"
    HOSTING = "hosting"
    ANALYTICS = "analytics"
    AUTHENTICATION = "authentication"
    SECURITY = "security"
    MONITORING = "monitoring"
    PROGRAMMING_LANGUAGE = "programming-language"
    RUNTIME = "runtime"
    PROTOCOL = "protocol"
    INFRASTRUCTURE = "infrastructure"
    OPERATING_SYSTEM = "operating-system"
    OTHER = "other"


class TechnologyFamily(StrEnum):
    """Canonical technology family.

    A family groups technologies by their role in a stack (e.g. every web
    server belongs to the ``web-server`` family) and is broader than a single
    product yet narrower than a category.
    """

    WEB_SERVER = "web-server"
    APPLICATION_SERVER = "application-server"
    WEB_FRAMEWORK = "web-framework"
    FRONTEND_FRAMEWORK = "frontend-framework"
    BACKEND_FRAMEWORK = "backend-framework"
    JAVASCRIPT = "javascript"
    PROGRAMMING_LANGUAGE = "programming-language"
    DATABASE = "database"
    CDN = "cdn"
    WAF = "waf"
    REVERSE_PROXY = "reverse-proxy"
    LOAD_BALANCER = "load-balancer"
    HOSTING_PROVIDER = "hosting-provider"
    CLOUD_PLATFORM = "cloud-platform"
    EDGE_NETWORK = "edge-network"
    SECURITY = "security"
    AUTHENTICATION = "authentication"
    ANALYTICS = "analytics"
    MONITORING = "monitoring"
    RUNTIME = "runtime"
    PROTOCOL = "protocol"
    OPERATING_SYSTEM = "operating-system"
    INFRASTRUCTURE = "infrastructure"
    OTHER = "other"


class VersionConfidence(StrEnum):
    """How strongly a detected version is supported by evidence.

    A weak fingerprint is never promoted to a confirmed version: evidence that
    only suggests a product family produces an ``unknown`` or ``range`` version
    state, never a ``confirmed`` one.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    RANGE = "range"
    UNKNOWN = "unknown"


class EvidenceStrength(StrEnum):
    """Relative strength of a single detection indicator."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class EvidenceType(StrEnum):
    """The kind of source an evidence fragment came from.

    Multiple evidence types for the same technology are correlated rather than
    trusting a single weak indicator.
    """

    HTTP_HEADER = "http-header"
    RESPONSE_HEADER = "response-header"
    COOKIE = "cookie"
    HTML = "html"
    META = "meta"
    DOM = "dom"
    TLS_CERTIFICATE = "tls-certificate"
    SERVICE_BANNER = "service-banner"
    HTTP_STATUS = "http-status"
    URL_PATTERN = "url-pattern"
    JAVASCRIPT = "javascript"
    KNOWN_SIGNATURE = "known-signature"
    TOOL_OUTPUT = "tool-output"
    TIDB_INTELLIGENCE = "tidb-intelligence"
    CPE = "cpe"
    OTHER = "other"


#: Observation payload discriminator keys used inside the pipeline JSON payload.
OBSERVATION_TECHNOLOGY = "technology"
OBSERVATION_EVIDENCE = "evidence"

#: Canonical asset kinds a technology can be observed on.
ASSET_HOSTNAME = "hostname"
ASSET_DOMAIN = "domain"
ASSET_IP = "ip"
ASSET_URL = "url"
ASSET_SERVICE = "service"


@dataclass(frozen=True, slots=True)
class TechTarget:
    """A single technology fingerprinting target.

    Attributes:
        value: canonical target identifier (a hostname, domain, IP or URL).
        target_type: canonical target kind (``url``, ``hostname``, ``domain``,
            ``ip``).
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "hostname"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class VersionSpec:
    """A version value with its evidence-backed confidence state.

    Attributes:
        value: the version string (``""`` when unknown).
        confidence: how strongly the value is supported.
        lower: inclusive lower bound when only a range is known.
        upper: inclusive upper bound when only a range is known.
        evidence: evidence fragments that support the version.

    """

    value: str = ""
    confidence: VersionConfidence = VersionConfidence.UNKNOWN
    lower: str = ""
    upper: str = ""
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", _parse_version_confidence(self.confidence))
        if not self.value:
            object.__setattr__(self, "value", _range_value(self.lower, self.upper))
        object.__setattr__(self, "value", str(self.value).strip())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "value": self.value,
            "confidence": self.confidence.value,
            "lower": self.lower,
            "upper": self.upper,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> VersionSpec:
        """Rebuild a version spec from a :meth:`to_dict` payload."""
        return cls(
            value=str(payload.get("value") or ""),
            confidence=_parse_version_confidence(payload.get("confidence")),
            lower=str(payload.get("lower") or ""),
            upper=str(payload.get("upper") or ""),
            evidence=tuple(str(item) for item in payload.get("evidence") or ()),
        )


@dataclass(frozen=True, slots=True)
class TechnologyEvidence:
    """A single detection evidence fragment.

    Attributes:
        evidence_type: the kind of source (header, cookie, html, ...).
        value: the raw indicator value observed.
        source: upstream source of the evidence.
        strength: relative strength of the indicator.
        tool_id: tool that produced the evidence.
        detail: optional contextual detail (e.g. the header name).

    """

    evidence_type: EvidenceType = EvidenceType.OTHER
    value: str = ""
    source: str = ""
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    tool_id: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_type", _parse_evidence_type(self.evidence_type))
        object.__setattr__(self, "strength", _parse_evidence_strength(self.strength))
        object.__setattr__(self, "value", str(self.value).strip())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return {
            "evidence_type": self.evidence_type.value,
            "value": self.value,
            "source": self.source,
            "strength": self.strength.value,
            "tool_id": self.tool_id,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TechnologyEvidence:
        """Rebuild an evidence fragment from a :meth:`to_dict` payload."""
        return cls(
            evidence_type=_parse_evidence_type(payload.get("evidence_type")),
            value=str(payload.get("value") or ""),
            source=str(payload.get("source") or ""),
            strength=_parse_evidence_strength(payload.get("strength")),
            tool_id=str(payload.get("tool_id") or ""),
            detail=str(payload.get("detail") or ""),
        )


@dataclass(frozen=True, slots=True)
class TechnologyObservation:
    """A canonical technology detection on one asset.

    Attributes:
        asset: canonical asset identifier (hostname, domain, IP or URL).
        asset_type: canonical asset kind.
        raw_name: the technology name exactly as observed (e.g. ``nginx/1.24.0``).
        canonical_name: the resolved canonical technology name (e.g. ``Nginx``).
        vendor: technology vendor when known.
        product: canonical product name when known.
        version: resolved version value.
        version_spec: evidence-backed version specification.
        category: canonical taxonomy category.
        family: canonical technology family.
        confidence: detection confidence in ``[0, 1]``.
        evidence: evidence fragments supporting the detection.
        source: upstream source of the observation.
        tool_id: the tool that produced the observation.
        validation_status: ``valid``/``unknown``/``invalid``.
        target_id: owning target record id when in-scope.
        observed_at: UTC ISO-8601 observation timestamp.
        execution_id: owning execution id.
        correlation_id: correlation id shared by the run.
        record_id: stable identifier for this observation.

    """

    asset: str
    asset_type: str = ASSET_HOSTNAME
    raw_name: str = ""
    canonical_name: str = ""
    vendor: str = ""
    product: str = ""
    version: str = ""
    version_spec: VersionSpec | None = None
    category: TechnologyCategory = TechnologyCategory.OTHER
    family: TechnologyFamily = TechnologyFamily.OTHER
    confidence: float = 1.0
    evidence: tuple[TechnologyEvidence, ...] = ()
    source: str = ""
    tool_id: str = ""
    validation_status: str = "valid"
    target_id: str | None = None
    observed_at: str = field(default_factory=utcnow_iso)
    execution_id: str = ""
    correlation_id: str = ""
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "asset", str(self.asset).strip().lower().rstrip("."))
        object.__setattr__(self, "category", _parse_category(self.category))
        object.__setattr__(self, "family", _parse_family(self.family))
        version_spec = self.version_spec
        if version_spec is not None and isinstance(version_spec, dict):
            version_spec = VersionSpec.from_dict(version_spec)
            object.__setattr__(self, "version_spec", version_spec)
        version = self.version or (version_spec.value if version_spec is not None else "")
        if version:
            object.__setattr__(self, "version", str(version).strip())
        if not self.canonical_name and self.raw_name:
            object.__setattr__(self, "canonical_name", str(self.raw_name).strip())

    def key(self) -> str:
        """Return the canonical deduplication key for this observation."""
        name = self.canonical_name or self.raw_name
        return f"tech:{self.asset}|{name}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "type": OBSERVATION_TECHNOLOGY,
            "record_id": self.record_id,
            "asset": self.asset,
            "asset_type": self.asset_type,
            "raw_name": self.raw_name,
            "canonical_name": self.canonical_name,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "version_spec": self.version_spec.to_dict() if self.version_spec is not None else None,
            "category": self.category.value,
            "family": self.family.value,
            "confidence": self.confidence,
            "evidence": [evidence.to_dict() for evidence in self.evidence],
            "source": self.source,
            "tool_id": self.tool_id,
            "validation_status": self.validation_status,
            "target_id": self.target_id,
            "observed_at": self.observed_at,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TechnologyObservation:
        """Rebuild an observation from a :meth:`to_dict` payload."""
        raw_spec = payload.get("version_spec")
        return cls(
            asset=str(payload.get("asset") or ""),
            asset_type=str(payload.get("asset_type") or ASSET_HOSTNAME),
            raw_name=str(payload.get("raw_name") or ""),
            canonical_name=str(payload.get("canonical_name") or ""),
            vendor=str(payload.get("vendor") or ""),
            product=str(payload.get("product") or ""),
            version=str(payload.get("version") or ""),
            version_spec=VersionSpec.from_dict(raw_spec) if isinstance(raw_spec, dict) else None,
            category=_parse_category(payload.get("category")),
            family=_parse_family(payload.get("family")),
            confidence=float(payload.get("confidence") or 1.0),
            evidence=tuple(
                TechnologyEvidence.from_dict(item) for item in payload.get("evidence") or () if isinstance(item, dict)
            ),
            source=str(payload.get("source") or ""),
            tool_id=str(payload.get("tool_id") or ""),
            validation_status=str(payload.get("validation_status") or "valid"),
            target_id=payload.get("target_id"),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            execution_id=str(payload.get("execution_id") or ""),
            correlation_id=str(payload.get("correlation_id") or ""),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class TechConflict:
    """A disagreement between sources about one technology on one asset.

    Conflicts are never silently overwritten: every observation, its source,
    tool, timestamp and evidence are preserved alongside the canonical choice
    and the reason it was selected.

    Attributes:
        asset: the affected asset.
        technology: the canonical technology name.
        observations: the disagreeing observations with provenance.
        conflict_type: ``version``, ``identity`` or ``presence``.
        selected: the canonical value selected.
        selected_source: provenance of the selected value.
        reason: human-readable explanation of the selection.
        confidence: confidence in the selected value in ``[0, 1]``.
        detected_at: UTC ISO-8601 detection timestamp.

    """

    asset: str
    technology: str
    observations: tuple[dict[str, Any], ...] = ()
    conflict_type: str = "version"
    selected: str = ""
    selected_source: str = ""
    reason: str = ""
    confidence: float = 0.0
    detected_at: str = field(default_factory=utcnow_iso)

    def key(self) -> str:
        """Return the canonical key of this conflict."""
        return f"tech:{self.asset}|{self.technology}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for reporting."""
        return {
            "asset": self.asset,
            "technology": self.technology,
            "observations": [dict(item) for item in self.observations],
            "conflict_type": self.conflict_type,
            "selected": self.selected,
            "selected_source": self.selected_source,
            "reason": self.reason,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
        }


@dataclass(frozen=True, slots=True)
class TechChange:
    """A detected difference between historical and current technology state.

    Attributes:
        asset: the affected asset.
        technology: the canonical technology name.
        change_type: ``added``, ``removed`` or ``changed``.
        previous: previous value (empty for added technologies).
        current: current value (empty for removed technologies).
        detected_at: UTC ISO-8601 detection timestamp.
        source: tool that produced the current observation.
        details: extra change context (e.g. old/new version).

    """

    asset: str
    technology: str
    change_type: str
    previous: str = ""
    current: str = ""
    detected_at: str = field(default_factory=utcnow_iso)
    source: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        """Return the canonical key of the changed observation."""
        return f"tech:{self.asset}|{self.technology}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for reporting."""
        return {
            "asset": self.asset,
            "technology": self.technology,
            "change_type": self.change_type,
            "previous": self.previous,
            "current": self.current,
            "detected_at": self.detected_at,
            "source": self.source,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class TechExecutionSummary:
    """Outcome of running one fingerprinting tool through the execution engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value.
        observations: number of technology observations produced.
        technologies: number of distinct canonical technologies produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    observations: int = 0
    technologies: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class TechnologyBatch:
    """The result of one fingerprinting run.

    Aggregates the raw observations, the correlated canonical technologies,
    evidence, conflicts, changes and the run's identity.

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target analysed.
        mode: the execution posture used.
        raw: raw observations collected from every source.
        technologies: correlated canonical technology observations.
        evidence: collected evidence fragments.
        conflicts: conflicting observations recorded.
        changes: historical changes detected.
        executions: per-tool execution summaries.
        created_at: UTC ISO-8601 run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: TechTarget
    mode: ReconMode = ReconMode.HYBRID
    raw: list[TechnologyObservation] = field(default_factory=list)
    technologies: list[TechnologyObservation] = field(default_factory=list)
    evidence: list[TechnologyEvidence] = field(default_factory=list)
    conflicts: list[TechConflict] = field(default_factory=list)
    changes: list[TechChange] = field(default_factory=list)
    executions: list[TechExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_observation(self, observation: TechnologyObservation) -> None:
        """Append a raw technology observation to the batch."""
        self.raw.append(observation)

    def add_technology(self, observation: TechnologyObservation) -> None:
        """Append a correlated canonical technology to the batch."""
        self.technologies.append(observation)

    def add_evidence(self, evidence: TechnologyEvidence) -> None:
        """Append an evidence fragment to the batch."""
        self.evidence.append(evidence)

    def add_conflict(self, conflict: TechConflict) -> None:
        """Append a conflict to the batch."""
        self.conflicts.append(conflict)

    def add_change(self, change: TechChange) -> None:
        """Append a historical change to the batch."""
        self.changes.append(change)

    def add_execution(self, summary: TechExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)

    def technology_count(self) -> int:
        """Return the number of correlated canonical technologies."""
        return len(self.technologies)

    def distinct_technologies(self) -> int:
        """Return the number of distinct canonical technology names."""
        return len({obs.canonical_name for obs in self.technologies if obs.canonical_name})

    def version_count(self) -> int:
        """Return the number of correlated technologies with a version."""
        return sum(1 for obs in self.technologies if obs.version)

    def conflict_count(self) -> int:
        """Return the number of recorded conflicts."""
        return len(self.conflicts)

    def total_observations(self) -> int:
        """Return the total number of raw observations in the batch."""
        return len(self.raw)


# -- observation factories --------------------------------------------------


def make_observation(
    asset: str,
    raw_name: str,
    *,
    asset_type: str = ASSET_HOSTNAME,
    canonical_name: str = "",
    vendor: str = "",
    product: str = "",
    version: str = "",
    version_spec: VersionSpec | None = None,
    category: TechnologyCategory | str = TechnologyCategory.OTHER,
    family: TechnologyFamily | str = TechnologyFamily.OTHER,
    confidence: float = 1.0,
    evidence: tuple[TechnologyEvidence | dict[str, Any], ...] = (),
    source: str = "",
    tool_id: str = "",
    validation_status: str = "valid",
    target_id: str | None = None,
    execution_id: str = "",
    correlation_id: str = "",
    observed_at: str | None = None,
) -> TechnologyObservation:
    """Build a :class:`TechnologyObservation` with the given asset and name."""
    return TechnologyObservation(
        asset=asset,
        asset_type=asset_type,
        raw_name=str(raw_name).strip(),
        canonical_name=canonical_name,
        vendor=vendor,
        product=product,
        version=version,
        version_spec=version_spec,
        category=_parse_category(category) if isinstance(category, str) else category,
        family=_parse_family(family) if isinstance(family, str) else family,
        confidence=confidence,
        evidence=tuple(
            evidence_item if isinstance(evidence_item, TechnologyEvidence) else TechnologyEvidence.from_dict(evidence_item)
            for evidence_item in evidence
        ),
        source=source,
        tool_id=tool_id,
        validation_status=validation_status,
        target_id=target_id,
        observed_at=observed_at or utcnow_iso(),
        execution_id=execution_id,
        correlation_id=correlation_id,
    )


def observations_from_payload(payload: Mapping[str, Any] | None) -> list[TechnologyObservation]:
    """Extract canonical observations from a pipeline JSON payload.

    Technology adapters serialise their detections under the ``technologies``
    key of the JSON payload they attach to the execution output. Each entry
    carries a ``type`` discriminator (``technology``). This helper rebuilds the
    typed records so downstream services never touch raw dictionaries.
    """
    if not payload:
        return []
    entries = payload.get("technologies")
    if not isinstance(entries, list):
        return []
    observations: list[TechnologyObservation] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") not in (OBSERVATION_TECHNOLOGY, None):
            continue
        observations.append(TechnologyObservation.from_dict(entry))
    return observations


# -- parsing helpers --------------------------------------------------------


def infer_asset_type(value: str) -> str:
    """Infer a canonical asset kind from a target value."""
    candidate = str(value).strip()
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return ASSET_URL
    try:
        import ipaddress

        ipaddress.ip_address(candidate)
        return ASSET_IP
    except ValueError:
        pass
    if "." in candidate:
        return ASSET_DOMAIN if candidate.count(".") == 1 else ASSET_HOSTNAME
    return ASSET_HOSTNAME


def _parse_category(value: object) -> TechnologyCategory:
    try:
        return TechnologyCategory(str(value).lower())
    except ValueError:
        return TechnologyCategory.OTHER


def _parse_family(value: object) -> TechnologyFamily:
    try:
        return TechnologyFamily(str(value).lower())
    except ValueError:
        return TechnologyFamily.OTHER


def _parse_version_confidence(value: object) -> VersionConfidence:
    try:
        return VersionConfidence(str(value).lower())
    except ValueError:
        return VersionConfidence.UNKNOWN


def _parse_evidence_type(value: object) -> EvidenceType:
    try:
        return EvidenceType(str(value).lower())
    except ValueError:
        return EvidenceType.OTHER


def _parse_evidence_strength(value: object) -> EvidenceStrength:
    try:
        return EvidenceStrength(str(value).lower())
    except ValueError:
        return EvidenceStrength.MODERATE


def _range_value(lower: str, upper: str) -> str:
    """Render a range as a human value (``>= x <= y``)."""
    if lower and upper:
        return f"{lower}..{upper}"
    if lower:
        return f">={lower}"
    if upper:
        return f"<={upper}"
    return ""
