# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Professional finding intelligence & reporting models.

Pure, immutable value objects for the Sprint 029 professional reporting
capability: the canonical finding-intelligence aggregate, classification
(CWE / OWASP / ATT&CK / CAPEC / CVE / CVSS), severity and priority
assessments, finding quality, reportability verdicts, evidence bundles and
artifacts with integrity hashes, timeline entries, tool provenance, source
reliability, report claims, remediation and retest plans, reproduction and
PoC presentation sections, report versions and snapshots, QA results, cross
-finding correlations, security-testing matrices and the consolidated report
document.

These objects are storage-agnostic; the TIDB entities
(:mod:`hunterx.domain.entities.tidb.reporting_intelligence`) are their
persistence projection and the application service maps between them. No I/O
and no rendering happens here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.reporting.enums import (
    BusinessImpactType,
    ClaimState,
    ClaimType,
    OwaspFramework,
    PriorityLevel,
    QaVerdict,
    QualityGrade,
    ReliabilityRank,
    ReportabilityStatus,
    ReportState,
    RetestState,
    SecurityTestingState,
    SourceReliabilityKind,
    TemplateKind,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class CvssAssessment:
    """A CVSS assessment bound to a finding.

    Environmental/context values are only present when actually provided;
    HunterX never fabricates them.

    Attributes:
        version: CVSS release version (``3.1`` / ``4.0``).
        vector: raw vector string.
        base_score: base score in ``[0, 10]``.
        severity: CVSS severity band.
        environmental_score: environmental/context score (``None`` unless provided).
        source: where the vector came from.
        explanation: explainable rationale for the metrics.
        analyzed_at: UTC ISO-8601 analysis timestamp.

    """

    version: str = "3.1"
    vector: str = ""
    base_score: float | None = None
    severity: str | None = None
    environmental_score: float | None = None
    source: str = "hunterx.severity"
    explanation: str = ""
    analyzed_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "version": self.version,
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
            "environmental_score": self.environmental_score,
            "source": self.source,
            "explanation": self.explanation,
            "analyzed_at": self.analyzed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CvssAssessment:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            version=str(payload.get("version") or "3.1"),
            vector=str(payload.get("vector") or ""),
            base_score=_opt_float(payload.get("base_score")),
            severity=_opt_str(payload.get("severity")),
            environmental_score=_opt_float(payload.get("environmental_score")),
            source=str(payload.get("source") or "hunterx.severity"),
            explanation=str(payload.get("explanation") or ""),
            analyzed_at=str(payload.get("analyzed_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class CweMapping:
    """One CWE mapping for a finding.

    Attributes:
        cwe_id: canonical CWE identifier (``CWE-79``).
        category: CWE category when known.
        title: CWE title/name.
        confidence: mapping confidence in ``[0, 1]``.
        rationale: evidence-backed mapping rationale.
        source: mapping source.

    """

    cwe_id: str
    category: str = ""
    title: str = ""
    confidence: float = 1.0
    rationale: str = ""
    source: str = "hunterx.classification"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "cwe_id": self.cwe_id,
            "category": self.category,
            "title": self.title,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CweMapping:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            cwe_id=str(payload.get("cwe_id") or ""),
            category=str(payload.get("category") or ""),
            title=str(payload.get("title") or ""),
            confidence=float(payload.get("confidence") or 0.0),
            rationale=str(payload.get("rationale") or ""),
            source=str(payload.get("source") or "hunterx.classification"),
        )


@dataclass(frozen=True, slots=True)
class OwaspMapping:
    """One OWASP mapping for a finding.

    Attributes:
        framework: OWASP framework referenced.
        item_id: item identifier (``A01``, ``2021-A01``, ASVS ref, WSTG ref).
        title: item title.
        confidence: mapping confidence in ``[0, 1]``.
        rationale: evidence-backed mapping rationale.

    """

    framework: OwaspFramework
    item_id: str
    title: str = ""
    confidence: float = 1.0
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "framework": self.framework.value,
            "item_id": self.item_id,
            "title": self.title,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> OwaspMapping:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            framework=_enum(OwaspFramework, payload.get("framework"), OwaspFramework.TOP_10),
            item_id=str(payload.get("item_id") or ""),
            title=str(payload.get("title") or ""),
            confidence=float(payload.get("confidence") or 0.0),
            rationale=str(payload.get("rationale") or ""),
        )


@dataclass(frozen=True, slots=True)
class AttackMapping:
    """One MITRE ATT&CK mapping for a finding.

    Mappings are only produced where the technique genuinely applies; they are
    never forced onto a finding.

    Attributes:
        technique_id: ATT&CK technique identifier (``T1190``).
        sub_technique_id: sub-technique identifier (``T1190.001``) when known.
        tactic: ATT&CK tactic name.
        technique_name: technique name.
        confidence: mapping confidence in ``[0, 1]``.
        rationale: evidence-backed mapping rationale.

    """

    technique_id: str
    sub_technique_id: str = ""
    tactic: str = ""
    technique_name: str = ""
    confidence: float = 0.5
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "technique_id": self.technique_id,
            "sub_technique_id": self.sub_technique_id,
            "tactic": self.tactic,
            "technique_name": self.technique_name,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AttackMapping:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            technique_id=str(payload.get("technique_id") or ""),
            sub_technique_id=str(payload.get("sub_technique_id") or ""),
            tactic=str(payload.get("tactic") or ""),
            technique_name=str(payload.get("technique_name") or ""),
            confidence=float(payload.get("confidence") or 0.0),
            rationale=str(payload.get("rationale") or ""),
        )


@dataclass(frozen=True, slots=True)
class Classification:
    """The complete classification of a finding across canonical vocabularies.

    Attributes:
        vulnerability_class: HunterX canonical vulnerability class.
        cwes: CWE mappings (multiple supported where justified).
        owasp: OWASP mappings.
        attack: MITRE ATT&CK mappings.
        capecs: CAPEC identifiers.
        cve_ids: referenced CVE identifiers.
        cvss: CVSS assessment when applicable.
        classified_at: UTC ISO-8601 classification timestamp.

    """

    vulnerability_class: str = "unknown_behavior"
    cwes: tuple[CweMapping, ...] = ()
    owasp: tuple[OwaspMapping, ...] = ()
    attack: tuple[AttackMapping, ...] = ()
    capecs: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    cvss: CvssAssessment | None = None
    classified_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "vulnerability_class": self.vulnerability_class,
            "cwes": [item.to_dict() for item in self.cwes],
            "owasp": [item.to_dict() for item in self.owasp],
            "attack": [item.to_dict() for item in self.attack],
            "capecs": list(self.capecs),
            "cve_ids": list(self.cve_ids),
            "cvss": self.cvss.to_dict() if self.cvss else None,
            "classified_at": self.classified_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Classification:
        """Rebuild from a :meth:`to_dict` payload."""
        cvss = payload.get("cvss")
        return cls(
            vulnerability_class=str(payload.get("vulnerability_class") or "unknown_behavior"),
            cwes=tuple(
                CweMapping.from_dict(item)
                for item in payload.get("cwes") or ()
                if isinstance(item, dict)
            ),
            owasp=tuple(
                OwaspMapping.from_dict(item)
                for item in payload.get("owasp") or ()
                if isinstance(item, dict)
            ),
            attack=tuple(
                AttackMapping.from_dict(item)
                for item in payload.get("attack") or ()
                if isinstance(item, dict)
            ),
            capecs=tuple(str(item) for item in payload.get("capecs") or ()),
            cve_ids=tuple(str(item) for item in payload.get("cve_ids") or ()),
            cvss=CvssAssessment.from_dict(cvss) if isinstance(cvss, dict) else None,
            classified_at=str(payload.get("classified_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class BusinessImpact:
    """Evidence-backed business impact of a finding.

    Every claimed impact carries either supporting evidence references or an
    explicit analyst-reasoning marker.

    Attributes:
        dimensions: per-impact-type level (``none``/``low``/``medium``/``high``).
        evidence_refs: evidence references per impact type.
        reasoning: analyst reasoning applied.
        analyst_reasoned: whether any claim relies on explicit analyst reasoning.
        assessed_at: UTC ISO-8601 assessment timestamp.

    """

    dimensions: Mapping[BusinessImpactType, str] = field(default_factory=dict)
    evidence_refs: Mapping[BusinessImpactType, tuple[str, ...]] = field(default_factory=dict)
    reasoning: tuple[str, ...] = ()
    analyst_reasoned: bool = False
    assessed_at: str = field(default_factory=utcnow_iso)

    def level(self, impact_type: BusinessImpactType) -> str:
        """Return the assessed level for ``impact_type``."""
        return self.dimensions.get(impact_type, "none")

    def any_impact(self) -> bool:
        """Return ``True`` when at least one impact type is above ``none``."""
        return any(level not in ("", "none") for level in self.dimensions.values())

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "dimensions": {key.value: value for key, value in self.dimensions.items()},
            "evidence_refs": {key.value: list(value) for key, value in self.evidence_refs.items()},
            "reasoning": list(self.reasoning),
            "analyst_reasoned": self.analyst_reasoned,
            "assessed_at": self.assessed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> BusinessImpact:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            dimensions={
                _enum(BusinessImpactType, key, BusinessImpactType.DATA_EXPOSURE): str(value)
                for key, value in dict(payload.get("dimensions") or {}).items()
            },
            evidence_refs={
                _enum(BusinessImpactType, key, BusinessImpactType.DATA_EXPOSURE): tuple(
                    str(item) for item in values or ()
                )
                for key, values in dict(payload.get("evidence_refs") or {}).items()
            },
            reasoning=tuple(str(item) for item in payload.get("reasoning") or ()),
            analyst_reasoned=bool(payload.get("analyst_reasoned", False)),
            assessed_at=str(payload.get("assessed_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class AssetCriticality:
    """Asset criticality context integrated from target intelligence.

    Attributes:
        asset: canonical asset identifier.
        importance: asset importance (``low``/``medium``/``high``/``critical``).
        internet_exposure: whether the asset is internet-facing.
        production: whether the asset is production.
        authentication_required: whether the surface requires authentication.
        data_sensitivity: data sensitivity level.
        cloud_role: cloud role when applicable.
        business_function: business function when known.
        known_criticality: known criticality classification.
        evidence_refs: supporting evidence references.

    """

    asset: str = ""
    importance: str = "medium"
    internet_exposure: bool = False
    production: bool = False
    authentication_required: bool = False
    data_sensitivity: str = "unknown"
    cloud_role: str = ""
    business_function: str = ""
    known_criticality: str = ""
    evidence_refs: tuple[str, ...] = ()

    def criticality_level(self) -> int:
        """Return a numeric criticality level ``0..3``."""
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(self.importance, 1)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "asset": self.asset,
            "importance": self.importance,
            "internet_exposure": self.internet_exposure,
            "production": self.production,
            "authentication_required": self.authentication_required,
            "data_sensitivity": self.data_sensitivity,
            "cloud_role": self.cloud_role,
            "business_function": self.business_function,
            "known_criticality": self.known_criticality,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AssetCriticality:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            asset=str(payload.get("asset") or ""),
            importance=str(payload.get("importance") or "medium"),
            internet_exposure=bool(payload.get("internet_exposure", False)),
            production=bool(payload.get("production", False)),
            authentication_required=bool(payload.get("authentication_required", False)),
            data_sensitivity=str(payload.get("data_sensitivity") or "unknown"),
            cloud_role=str(payload.get("cloud_role") or ""),
            business_function=str(payload.get("business_function") or ""),
            known_criticality=str(payload.get("known_criticality") or ""),
            evidence_refs=tuple(str(item) for item in payload.get("evidence_refs") or ()),
        )


@dataclass(frozen=True, slots=True)
class FindingQuality:
    """Finding quality assessment.

    Confidence answers "how likely is this finding correct?" while quality
    answers "how strong and defensible is this report?".

    Attributes:
        finding_id: owning finding.
        quality_score: composite score in ``[0, 1]``.
        quality_grade: grade band.
        quality_explanation: explainable explanation.
        factors: per-factor scores.
        assessed_at: UTC ISO-8601 assessment timestamp.

    """

    finding_id: str = ""
    quality_score: float = 0.0
    quality_grade: QualityGrade = QualityGrade.F
    quality_explanation: str = ""
    factors: tuple[QualityFactorScore, ...] = ()
    assessed_at: str = field(default_factory=utcnow_iso)

    def factor(self, name: str) -> QualityFactorScore | None:
        """Return the factor named ``name`` or ``None``."""
        for item in self.factors:
            if item.name == name:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "finding_id": self.finding_id,
            "quality_score": self.quality_score,
            "quality_grade": self.quality_grade.value,
            "quality_explanation": self.quality_explanation,
            "factors": [item.to_dict() for item in self.factors],
            "assessed_at": self.assessed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FindingQuality:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            finding_id=str(payload.get("finding_id") or ""),
            quality_score=float(payload.get("quality_score") or 0.0),
            quality_grade=_enum(QualityGrade, payload.get("quality_grade"), QualityGrade.F),
            quality_explanation=str(payload.get("quality_explanation") or ""),
            factors=tuple(
                QualityFactorScore.from_dict(item)
                for item in payload.get("factors") or ()
                if isinstance(item, dict)
            ),
            assessed_at=str(payload.get("assessed_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class QualityFactorScore:
    """One explainable factor inside a finding quality assessment."""

    name: str
    score: float
    weight: float
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {"name": self.name, "score": self.score, "weight": self.weight, "reason": self.reason}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> QualityFactorScore:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            name=str(payload.get("name") or ""),
            score=float(payload.get("score") or 0.0),
            weight=float(payload.get("weight") or 0.0),
            reason=str(payload.get("reason") or ""),
        )


@dataclass(frozen=True, slots=True)
class SeverityAssessment:
    """Evidence-backed severity assessment.

    Severity is never derived from the vulnerability class alone; it is
    derived from evidence-backed impact dimensions, exploitability and
    business context.

    Attributes:
        finding_id: owning finding.
        severity: final severity (informational/low/medium/high/critical).
        risk_score: numeric risk score in ``[0, 10]``.
        reasoning: explainable reasoning.
        evidence_refs: supporting evidence references.
        evidence_backed: whether every driver is evidence-backed.
        assessed_at: UTC ISO-8601 assessment timestamp.

    """

    finding_id: str = ""
    severity: str = "informational"
    risk_score: float = 0.0
    reasoning: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    evidence_backed: bool = True
    assessed_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "reasoning": list(self.reasoning),
            "evidence_refs": list(self.evidence_refs),
            "evidence_backed": self.evidence_backed,
            "assessed_at": self.assessed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SeverityAssessment:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            finding_id=str(payload.get("finding_id") or ""),
            severity=str(payload.get("severity") or "informational"),
            risk_score=float(payload.get("risk_score") or 0.0),
            reasoning=tuple(str(item) for item in payload.get("reasoning") or ()),
            evidence_refs=tuple(str(item) for item in payload.get("evidence_refs") or ()),
            evidence_backed=bool(payload.get("evidence_backed", True)),
            assessed_at=str(payload.get("assessed_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class PriorityAssessment:
    """Remediation priority of a finding (distinct from severity)."""

    finding_id: str = ""
    priority: PriorityLevel = PriorityLevel.P4
    score: float = 0.0
    factors: tuple[PriorityFactor, ...] = ()
    rationale: str = ""
    assessed_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "finding_id": self.finding_id,
            "priority": self.priority.value,
            "score": self.score,
            "factors": [item.to_dict() for item in self.factors],
            "rationale": self.rationale,
            "assessed_at": self.assessed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> PriorityAssessment:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            finding_id=str(payload.get("finding_id") or ""),
            priority=_enum(PriorityLevel, payload.get("priority"), PriorityLevel.P4),
            score=float(payload.get("score") or 0.0),
            factors=tuple(
                PriorityFactor.from_dict(item)
                for item in payload.get("factors") or ()
                if isinstance(item, dict)
            ),
            rationale=str(payload.get("rationale") or ""),
            assessed_at=str(payload.get("assessed_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class PriorityFactor:
    """One explainable factor of a priority assessment."""

    name: str
    score: float
    weight: float
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {"name": self.name, "score": self.score, "weight": self.weight, "reason": self.reason}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> PriorityFactor:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            name=str(payload.get("name") or ""),
            score=float(payload.get("score") or 0.0),
            weight=float(payload.get("weight") or 0.0),
            reason=str(payload.get("reason") or ""),
        )


@dataclass(frozen=True, slots=True)
class ReportabilityCheck:
    """One reportability check result."""

    name: str
    passed: bool
    detail: str = ""
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {"name": self.name, "passed": self.passed, "detail": self.detail, "required": self.required}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportabilityCheck:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            name=str(payload.get("name") or ""),
            passed=bool(payload.get("passed", False)),
            detail=str(payload.get("detail") or ""),
            required=bool(payload.get("required", True)),
        )


@dataclass(frozen=True, slots=True)
class Reportability:
    """Reportability verdict for a finding.

    Attributes:
        finding_id: owning finding.
        status: reportability verdict.
        checks: per-criteria checks.
        reasons: explainable reasons.
        assessed_at: UTC ISO-8601 assessment timestamp.

    """

    finding_id: str = ""
    status: ReportabilityStatus = ReportabilityStatus.NOT_ACTIONABLE
    checks: tuple[ReportabilityCheck, ...] = ()
    reasons: tuple[str, ...] = ()
    assessed_at: str = field(default_factory=utcnow_iso)

    def check(self, name: str) -> ReportabilityCheck | None:
        """Return the check named ``name`` or ``None``."""
        for item in self.checks:
            if item.name == name:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "checks": [item.to_dict() for item in self.checks],
            "reasons": list(self.reasons),
            "assessed_at": self.assessed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Reportability:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            finding_id=str(payload.get("finding_id") or ""),
            status=_enum(ReportabilityStatus, payload.get("status"), ReportabilityStatus.NOT_ACTIONABLE),
            checks=tuple(
                ReportabilityCheck.from_dict(item)
                for item in payload.get("checks") or ()
                if isinstance(item, dict)
            ),
            reasons=tuple(str(item) for item in payload.get("reasons") or ()),
            assessed_at=str(payload.get("assessed_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    """Evidence-based remediation plan for a finding.

    Remediation is technically relevant to the actual root cause and avoids
    generic advice when the evidence indicates a specific problem.

    Attributes:
        plan_id: stable identifier.
        finding_id: owning finding.
        root_cause_id: linked root cause when known.
        immediate_mitigations: immediate actions to reduce exposure.
        short_term_fixes: short-term fixes.
        long_term_fixes: long-term architectural fixes.
        configuration_changes: configuration changes.
        code_remediation: code-level remediation guidance.
        monitoring_recommendations: monitoring recommendations.
        validation_recommendations: how to validate the fix.
        evidence_refs: supporting evidence references.
        created_at: UTC ISO-8601 creation timestamp.

    """

    plan_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    root_cause_id: str = ""
    immediate_mitigations: tuple[str, ...] = ()
    short_term_fixes: tuple[str, ...] = ()
    long_term_fixes: tuple[str, ...] = ()
    configuration_changes: tuple[str, ...] = ()
    code_remediation: tuple[str, ...] = ()
    monitoring_recommendations: tuple[str, ...] = ()
    validation_recommendations: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "root_cause_id": self.root_cause_id,
            "immediate_mitigations": list(self.immediate_mitigations),
            "short_term_fixes": list(self.short_term_fixes),
            "long_term_fixes": list(self.long_term_fixes),
            "configuration_changes": list(self.configuration_changes),
            "code_remediation": list(self.code_remediation),
            "monitoring_recommendations": list(self.monitoring_recommendations),
            "validation_recommendations": list(self.validation_recommendations),
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RemediationPlan:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            plan_id=str(payload.get("plan_id") or generate_id()),
            finding_id=str(payload.get("finding_id") or ""),
            root_cause_id=str(payload.get("root_cause_id") or ""),
            immediate_mitigations=tuple(str(item) for item in payload.get("immediate_mitigations") or ()),
            short_term_fixes=tuple(str(item) for item in payload.get("short_term_fixes") or ()),
            long_term_fixes=tuple(str(item) for item in payload.get("long_term_fixes") or ()),
            configuration_changes=tuple(str(item) for item in payload.get("configuration_changes") or ()),
            code_remediation=tuple(str(item) for item in payload.get("code_remediation") or ()),
            monitoring_recommendations=tuple(str(item) for item in payload.get("monitoring_recommendations") or ()),
            validation_recommendations=tuple(str(item) for item in payload.get("validation_recommendations") or ()),
            evidence_refs=tuple(str(item) for item in payload.get("evidence_refs") or ()),
            created_at=str(payload.get("created_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class RetestPlan:
    """Retest plan for an actionable finding.

    Attributes:
        plan_id: stable identifier.
        finding_id: owning finding.
        state: retest lifecycle state.
        what_must_change: what must change for the fix to hold.
        endpoints: endpoint/resource to test.
        behaviors_to_disappear: behaviors that must disappear.
        proofs_to_fail: proof/PoC replays that should fail.
        evidence_to_collect: evidence to collect during retest.
        acceptance_criteria: acceptance criteria for fix verification.
        created_at: UTC ISO-8601 creation timestamp.

    """

    plan_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    state: RetestState = RetestState.PLANNED
    what_must_change: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    behaviors_to_disappear: tuple[str, ...] = ()
    proofs_to_fail: tuple[str, ...] = ()
    evidence_to_collect: tuple[str, ...] = ()
    acceptance_criteria: tuple[str, ...] = ()
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "state": self.state.value,
            "what_must_change": list(self.what_must_change),
            "endpoints": list(self.endpoints),
            "behaviors_to_disappear": list(self.behaviors_to_disappear),
            "proofs_to_fail": list(self.proofs_to_fail),
            "evidence_to_collect": list(self.evidence_to_collect),
            "acceptance_criteria": list(self.acceptance_criteria),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RetestPlan:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            plan_id=str(payload.get("plan_id") or generate_id()),
            finding_id=str(payload.get("finding_id") or ""),
            state=_enum(RetestState, payload.get("state"), RetestState.PLANNED),
            what_must_change=tuple(str(item) for item in payload.get("what_must_change") or ()),
            endpoints=tuple(str(item) for item in payload.get("endpoints") or ()),
            behaviors_to_disappear=tuple(str(item) for item in payload.get("behaviors_to_disappear") or ()),
            proofs_to_fail=tuple(str(item) for item in payload.get("proofs_to_fail") or ()),
            evidence_to_collect=tuple(str(item) for item in payload.get("evidence_to_collect") or ()),
            acceptance_criteria=tuple(str(item) for item in payload.get("acceptance_criteria") or ()),
            created_at=str(payload.get("created_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class ReproductionSection:
    """Professional reproduction section for a report.

    Sensitive values must be redacted while preserving reproduction utility.

    Attributes:
        target: target identifier.
        endpoint: affected endpoint.
        method: HTTP method.
        parameter: affected parameter name.
        preconditions: reproduction preconditions.
        authentication_context: authentication context required.
        request: request description.
        payload_reference: reference to the payload used (redacted).
        expected_behavior: expected behavior.
        observed_behavior: observed behavior.
        verification: verification evidence reference.
        proof_refs: proof references.
        impact: stated impact.
        redacted: whether sensitive values were redacted.

    """

    target: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    preconditions: tuple[str, ...] = ()
    authentication_context: str = ""
    request: str = ""
    payload_reference: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    verification: str = ""
    proof_refs: tuple[str, ...] = ()
    impact: str = ""
    redacted: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "preconditions": list(self.preconditions),
            "authentication_context": self.authentication_context,
            "request": self.request,
            "payload_reference": self.payload_reference,
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "verification": self.verification,
            "proof_refs": list(self.proof_refs),
            "impact": self.impact,
            "redacted": self.redacted,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReproductionSection:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            target=str(payload.get("target") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or "GET"),
            parameter=str(payload.get("parameter") or ""),
            preconditions=tuple(str(item) for item in payload.get("preconditions") or ()),
            authentication_context=str(payload.get("authentication_context") or ""),
            request=str(payload.get("request") or ""),
            payload_reference=str(payload.get("payload_reference") or ""),
            expected_behavior=str(payload.get("expected_behavior") or ""),
            observed_behavior=str(payload.get("observed_behavior") or ""),
            verification=str(payload.get("verification") or ""),
            proof_refs=tuple(str(item) for item in payload.get("proof_refs") or ()),
            impact=str(payload.get("impact") or ""),
            redacted=bool(payload.get("redacted", True)),
        )


@dataclass(frozen=True, slots=True)
class PoCPresentation:
    """PoC presentation integrated from the Sprint 028 proof engine."""

    poc_id: str = ""
    finding_id: str = ""
    poc_type: str = ""
    purpose: str = ""
    preconditions: tuple[str, ...] = ()
    minimal_reproduction: str = ""
    expected_result: str = ""
    actual_result: str = ""
    validation_status: str = "generated"
    replay_status: str = "not_run"
    evidence_refs: tuple[str, ...] = ()
    safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "poc_id": self.poc_id,
            "finding_id": self.finding_id,
            "poc_type": self.poc_type,
            "purpose": self.purpose,
            "preconditions": list(self.preconditions),
            "minimal_reproduction": self.minimal_reproduction,
            "expected_result": self.expected_result,
            "actual_result": self.actual_result,
            "validation_status": self.validation_status,
            "replay_status": self.replay_status,
            "evidence_refs": list(self.evidence_refs),
            "safe": self.safe,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> PoCPresentation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            poc_id=str(payload.get("poc_id") or ""),
            finding_id=str(payload.get("finding_id") or ""),
            poc_type=str(payload.get("poc_type") or ""),
            purpose=str(payload.get("purpose") or ""),
            preconditions=tuple(str(item) for item in payload.get("preconditions") or ()),
            minimal_reproduction=str(payload.get("minimal_reproduction") or ""),
            expected_result=str(payload.get("expected_result") or ""),
            actual_result=str(payload.get("actual_result") or ""),
            validation_status=str(payload.get("validation_status") or "generated"),
            replay_status=str(payload.get("replay_status") or "not_run"),
            evidence_refs=tuple(str(item) for item in payload.get("evidence_refs") or ()),
            safe=bool(payload.get("safe", True)),
        )


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    """One evidence artifact with integrity metadata.

    Attributes:
        artifact_id: stable identifier.
        kind: artifact kind (observation/request/response/tool_output/...).
        content_hash: SHA-256 content hash.
        source: producing source.
        timestamp: UTC ISO-8601 capture timestamp.
        collector: collecting component.
        tool: producing tool when applicable.
        mission_id / target_id / finding_id: ownership identifiers.
        provenance: free-form provenance map.
        redaction_state: redaction state applied.

    """

    artifact_id: str = field(default_factory=generate_id)
    kind: str = "observation"
    content_hash: str = ""
    source: str = ""
    timestamp: str = field(default_factory=utcnow_iso)
    collector: str = ""
    tool: str = ""
    mission_id: str = ""
    target_id: str = ""
    finding_id: str = ""
    provenance: Mapping[str, Any] = field(default_factory=dict)
    redaction_state: str = "redacted"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "content_hash": self.content_hash,
            "source": self.source,
            "timestamp": self.timestamp,
            "collector": self.collector,
            "tool": self.tool,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "finding_id": self.finding_id,
            "provenance": dict(self.provenance),
            "redaction_state": self.redaction_state,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EvidenceArtifact:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            artifact_id=str(payload.get("artifact_id") or generate_id()),
            kind=str(payload.get("kind") or "observation"),
            content_hash=str(payload.get("content_hash") or ""),
            source=str(payload.get("source") or ""),
            timestamp=str(payload.get("timestamp") or utcnow_iso()),
            collector=str(payload.get("collector") or ""),
            tool=str(payload.get("tool") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            target_id=str(payload.get("target_id") or ""),
            finding_id=str(payload.get("finding_id") or ""),
            provenance=dict(payload.get("provenance") or {}),
            redaction_state=str(payload.get("redaction_state") or "redacted"),
        )


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Immutable evidence bundle for a finding.

    Contains references and integrity hashes; the full raw evidence stays in
    the evidence store and is referenced, never duplicated.

    Attributes:
        bundle_id: stable identifier.
        finding_id: owning finding.
        artifacts: evidence artifacts included.
        normalized_observations: normalized observation references.
        requests: request references.
        response_metadata: response metadata references.
        headers: safe headers map.
        callback_evidence: controlled callback evidence references.
        tool_outputs: tool output references.
        validation_results: validation result references.
        proof_references: proof/PoC references.
        replay_results: replay result references.
        timestamps: captured timestamps.
        bundle_hash: SHA-256 over the artifact hashes.
        immutable: whether the bundle is immutable once created.
        created_at: UTC ISO-8601 creation timestamp.

    """

    bundle_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    artifacts: tuple[EvidenceArtifact, ...] = ()
    normalized_observations: tuple[str, ...] = ()
    requests: tuple[str, ...] = ()
    response_metadata: tuple[str, ...] = ()
    headers: Mapping[str, str] = field(default_factory=dict)
    callback_evidence: tuple[str, ...] = ()
    tool_outputs: tuple[str, ...] = ()
    validation_results: tuple[str, ...] = ()
    proof_references: tuple[str, ...] = ()
    replay_results: tuple[str, ...] = ()
    timestamps: tuple[str, ...] = ()
    bundle_hash: str = ""
    immutable: bool = True
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "bundle_id": self.bundle_id,
            "finding_id": self.finding_id,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "normalized_observations": list(self.normalized_observations),
            "requests": list(self.requests),
            "response_metadata": list(self.response_metadata),
            "headers": dict(self.headers),
            "callback_evidence": list(self.callback_evidence),
            "tool_outputs": list(self.tool_outputs),
            "validation_results": list(self.validation_results),
            "proof_references": list(self.proof_references),
            "replay_results": list(self.replay_results),
            "timestamps": list(self.timestamps),
            "bundle_hash": self.bundle_hash,
            "immutable": self.immutable,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EvidenceBundle:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            bundle_id=str(payload.get("bundle_id") or generate_id()),
            finding_id=str(payload.get("finding_id") or ""),
            artifacts=tuple(
                EvidenceArtifact.from_dict(item)
                for item in payload.get("artifacts") or ()
                if isinstance(item, dict)
            ),
            normalized_observations=tuple(str(item) for item in payload.get("normalized_observations") or ()),
            requests=tuple(str(item) for item in payload.get("requests") or ()),
            response_metadata=tuple(str(item) for item in payload.get("response_metadata") or ()),
            headers={str(key): str(value) for key, value in dict(payload.get("headers") or {}).items()},
            callback_evidence=tuple(str(item) for item in payload.get("callback_evidence") or ()),
            tool_outputs=tuple(str(item) for item in payload.get("tool_outputs") or ()),
            validation_results=tuple(str(item) for item in payload.get("validation_results") or ()),
            proof_references=tuple(str(item) for item in payload.get("proof_references") or ()),
            replay_results=tuple(str(item) for item in payload.get("replay_results") or ()),
            timestamps=tuple(str(item) for item in payload.get("timestamps") or ()),
            bundle_hash=str(payload.get("bundle_hash") or ""),
            immutable=bool(payload.get("immutable", True)),
            created_at=str(payload.get("created_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    """One finding-timeline entry.

    Timestamps come from actual events; HunterX never invents timestamps.

    Attributes:
        event: canonical event name.
        detail: explainable detail.
        occurred_at: UTC ISO-8601 event timestamp.
        provenance: producing source.

    """

    event: str
    detail: str = ""
    occurred_at: str = field(default_factory=utcnow_iso)
    provenance: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "event": self.event,
            "detail": self.detail,
            "occurred_at": self.occurred_at,
            "provenance": self.provenance,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TimelineEntry:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            event=str(payload.get("event") or ""),
            detail=str(payload.get("detail") or ""),
            occurred_at=str(payload.get("occurred_at") or utcnow_iso()),
            provenance=str(payload.get("provenance") or ""),
        )


@dataclass(frozen=True, slots=True)
class FindingTimeline:
    """Ordered finding timeline derived from actual persisted events."""

    timeline_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    entries: tuple[TimelineEntry, ...] = ()
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "timeline_id": self.timeline_id,
            "finding_id": self.finding_id,
            "entries": [entry.to_dict() for entry in self.entries],
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FindingTimeline:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            timeline_id=str(payload.get("timeline_id") or generate_id()),
            finding_id=str(payload.get("finding_id") or ""),
            entries=tuple(
                TimelineEntry.from_dict(item)
                for item in payload.get("entries") or ()
                if isinstance(item, dict)
            ),
            created_at=str(payload.get("created_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class ToolProvenance:
    """Provenance of a tool-derived fact.

    Attributes:
        tool: tool name.
        version: tool version.
        command_reference: command/configuration reference.
        execution_id: tool execution identifier.
        timestamp: UTC ISO-8601 execution timestamp.
        target: target the tool ran against.
        scope: scope context.
        result_reference: reference to the tool result.
        normalization_version: normalizer version applied.
        reliability: source reliability classification.

    """

    tool: str
    version: str = ""
    command_reference: str = ""
    execution_id: str = ""
    timestamp: str = ""
    target: str = ""
    scope: str = ""
    result_reference: str = ""
    normalization_version: str = "1.0.0"
    reliability: SourceReliabilityKind = SourceReliabilityKind.TOOL_SIGNATURE

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "tool": self.tool,
            "version": self.version,
            "command_reference": self.command_reference,
            "execution_id": self.execution_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "scope": self.scope,
            "result_reference": self.result_reference,
            "normalization_version": self.normalization_version,
            "reliability": self.reliability.value,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ToolProvenance:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            tool=str(payload.get("tool") or ""),
            version=str(payload.get("version") or ""),
            command_reference=str(payload.get("command_reference") or ""),
            execution_id=str(payload.get("execution_id") or ""),
            timestamp=str(payload.get("timestamp") or ""),
            target=str(payload.get("target") or ""),
            scope=str(payload.get("scope") or ""),
            result_reference=str(payload.get("result_reference") or ""),
            normalization_version=str(payload.get("normalization_version") or "1.0.0"),
            reliability=_enum(
                SourceReliabilityKind,
                payload.get("reliability"),
                SourceReliabilityKind.TOOL_SIGNATURE,
            ),
        )


@dataclass(frozen=True, slots=True)
class SourceReliabilityModel:
    """Source reliability classification for one evidence source.

    Direct validated evidence must outrank AI inference.

    Attributes:
        source: source name.
        kind: source reliability classification.
        rank: ordered reliability rank.
        notes: explainable notes.
        effective_weight: weight applied to evidence from this source.

    """

    source: str
    kind: SourceReliabilityKind = SourceReliabilityKind.DIRECT_OBSERVATION
    rank: ReliabilityRank = ReliabilityRank.DIRECT
    notes: str = ""
    effective_weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "source": self.source,
            "kind": self.kind.value,
            "rank": self.rank.value,
            "notes": self.notes,
            "effective_weight": self.effective_weight,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SourceReliabilityModel:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            source=str(payload.get("source") or ""),
            kind=_enum(SourceReliabilityKind, payload.get("kind"), SourceReliabilityKind.DIRECT_OBSERVATION),
            rank=_enum(ReliabilityRank, payload.get("rank"), ReliabilityRank.DIRECT),
            notes=str(payload.get("notes") or ""),
            effective_weight=float(payload.get("effective_weight") or 1.0),
        )


@dataclass(frozen=True, slots=True)
class ReportClaim:
    """A material report claim with provenance.

    Attributes:
        claim_id: stable identifier.
        claim_text: the claim text.
        source_refs: evidence/observation references supporting the claim.
        claim_type: claim type.
        confidence: claim confidence in ``[0, 1]``.
        generated_by: producer (engine/manual/ai).
        verification_state: claim verification state.
        verification_detail: explainable verification detail.

    """

    claim_id: str = field(default_factory=generate_id)
    claim_text: str = ""
    source_refs: tuple[str, ...] = ()
    claim_type: ClaimType = ClaimType.VULNERABILITY
    confidence: float = 0.0
    generated_by: str = "hunterx.reporting"
    verification_state: ClaimState = ClaimState.UNSUPPORTED
    verification_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "claim_id": self.claim_id,
            "claim_text": self.claim_text,
            "source_refs": list(self.source_refs),
            "claim_type": self.claim_type.value,
            "confidence": self.confidence,
            "generated_by": self.generated_by,
            "verification_state": self.verification_state.value,
            "verification_detail": self.verification_detail,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportClaim:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            claim_id=str(payload.get("claim_id") or generate_id()),
            claim_text=str(payload.get("claim_text") or ""),
            source_refs=tuple(str(item) for item in payload.get("source_refs") or ()),
            claim_type=_enum(ClaimType, payload.get("claim_type"), ClaimType.VULNERABILITY),
            confidence=float(payload.get("confidence") or 0.0),
            generated_by=str(payload.get("generated_by") or "hunterx.reporting"),
            verification_state=_enum(ClaimState, payload.get("verification_state"), ClaimState.UNSUPPORTED),
            verification_detail=str(payload.get("verification_detail") or ""),
        )


@dataclass(frozen=True, slots=True)
class QaCheckResult:
    """One report QA check result."""

    name: str
    verdict: QaVerdict = QaVerdict.WARN
    detail: str = ""
    blocking: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "name": self.name,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "blocking": self.blocking,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> QaCheckResult:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            name=str(payload.get("name") or ""),
            verdict=_enum(QaVerdict, payload.get("verdict"), QaVerdict.WARN),
            detail=str(payload.get("detail") or ""),
            blocking=bool(payload.get("blocking", False)),
        )


@dataclass(frozen=True, slots=True)
class ReportQaResult:
    """Aggregated report QA result.

    Attributes:
        report_id: report being checked.
        verdict: overall verdict (pass/fail/warn).
        checks: individual check results.
        blocked: whether the report is blocked from submission.
        reasons: explainable reasons.
        checked_at: UTC ISO-8601 check timestamp.

    """

    report_id: str = ""
    verdict: QaVerdict = QaVerdict.WARN
    checks: tuple[QaCheckResult, ...] = ()
    blocked: bool = True
    reasons: tuple[str, ...] = ()
    checked_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "report_id": self.report_id,
            "verdict": self.verdict.value,
            "checks": [item.to_dict() for item in self.checks],
            "blocked": self.blocked,
            "reasons": list(self.reasons),
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportQaResult:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            report_id=str(payload.get("report_id") or ""),
            verdict=_enum(QaVerdict, payload.get("verdict"), QaVerdict.WARN),
            checks=tuple(
                QaCheckResult.from_dict(item)
                for item in payload.get("checks") or ()
                if isinstance(item, dict)
            ),
            blocked=bool(payload.get("blocked", True)),
            reasons=tuple(str(item) for item in payload.get("reasons") or ()),
            checked_at=str(payload.get("checked_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class RedactionRecord:
    """One redaction applied to a report output."""

    field_name: str
    pattern: str = ""
    secret_type: str = ""
    masked_value: str = ""
    preserved_for_reproduction: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "field_name": self.field_name,
            "pattern": self.pattern,
            "secret_type": self.secret_type,
            "masked_value": self.masked_value,
            "preserved_for_reproduction": self.preserved_for_reproduction,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RedactionRecord:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            field_name=str(payload.get("field_name") or ""),
            pattern=str(payload.get("pattern") or ""),
            secret_type=str(payload.get("secret_type") or ""),
            masked_value=str(payload.get("masked_value") or ""),
            preserved_for_reproduction=bool(payload.get("preserved_for_reproduction", False)),
        )


@dataclass(frozen=True, slots=True)
class ReportRedaction:
    """Redaction metadata attached to a report output."""

    applied: bool = False
    records: tuple[RedactionRecord, ...] = ()
    policy_version: str = "1.0.0"
    applied_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "applied": self.applied,
            "records": [item.to_dict() for item in self.records],
            "policy_version": self.policy_version,
            "applied_at": self.applied_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportRedaction:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            applied=bool(payload.get("applied", False)),
            records=tuple(
                RedactionRecord.from_dict(item)
                for item in payload.get("records") or ()
                if isinstance(item, dict)
            ),
            policy_version=str(payload.get("policy_version") or "1.0.0"),
            applied_at=str(payload.get("applied_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class CrossFindingRelation:
    """One relationship in a cross-finding correlation report.

    Attributes:
        source_finding_id: source finding.
        target_finding_id: target finding / asset / credential / identity / resource.
        relation: relation kind.
        rationale: explainable rationale.
        evidence_refs: supporting evidence references.

    """

    source_finding_id: str
    target_finding_id: str
    relation: str
    rationale: str = ""
    evidence_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "source_finding_id": self.source_finding_id,
            "target_finding_id": self.target_finding_id,
            "relation": self.relation,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CrossFindingRelation:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            source_finding_id=str(payload.get("source_finding_id") or ""),
            target_finding_id=str(payload.get("target_finding_id") or ""),
            relation=str(payload.get("relation") or ""),
            rationale=str(payload.get("rationale") or ""),
            evidence_refs=tuple(str(item) for item in payload.get("evidence_refs") or ()),
        )


@dataclass(frozen=True, slots=True)
class FindingCorrelationReport:
    """Cross-finding correlation analysis for a report package."""

    report_id: str = ""
    relations: tuple[CrossFindingRelation, ...] = ()
    root_cause_groups: tuple[str, ...] = ()
    generated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "report_id": self.report_id,
            "relations": [item.to_dict() for item in self.relations],
            "root_cause_groups": list(self.root_cause_groups),
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FindingCorrelationReport:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            report_id=str(payload.get("report_id") or ""),
            relations=tuple(
                CrossFindingRelation.from_dict(item)
                for item in payload.get("relations") or ()
                if isinstance(item, dict)
            ),
            root_cause_groups=tuple(str(item) for item in payload.get("root_cause_groups") or ()),
            generated_at=str(payload.get("generated_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class SecurityTestingStateEntry:
    """One finding row in the security testing matrix."""

    finding_id: str
    state: SecurityTestingState = SecurityTestingState.UNVERIFIED
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {"finding_id": self.finding_id, "state": self.state.value, "detail": self.detail}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SecurityTestingStateEntry:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            finding_id=str(payload.get("finding_id") or ""),
            state=_enum(SecurityTestingState, payload.get("state"), SecurityTestingState.UNVERIFIED),
            detail=str(payload.get("detail") or ""),
        )


@dataclass(frozen=True, slots=True)
class SecurityTestingMatrix:
    """Per-finding verification-state matrix.

    States (confirmed/validated/observed/suspected/theoretical/unverified) are
    never mixed inside a report.

    """

    entries: tuple[SecurityTestingStateEntry, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {"entries": [entry.to_dict() for entry in self.entries]}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SecurityTestingMatrix:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            entries=tuple(
                SecurityTestingStateEntry.from_dict(item)
                for item in payload.get("entries") or ()
                if isinstance(item, dict)
            )
        )


@dataclass(frozen=True, slots=True)
class ReportTemplate:
    """A data-driven report template.

    Templates describe sections in data, never in business logic.

    Attributes:
        template_id: stable identifier.
        kind: template kind.
        version: template version.
        title: template title.
        sections: ordered section definitions.
        schema_version: template schema version.
        locale: template locale (i18n aware).
        created_at: UTC ISO-8601 creation timestamp.

    """

    template_id: str
    kind: TemplateKind
    version: str = "1.0.0"
    title: str = ""
    sections: tuple[TemplateSection, ...] = ()
    schema_version: str = "1.0.0"
    locale: str = "en"
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "template_id": self.template_id,
            "kind": self.kind.value,
            "version": self.version,
            "title": self.title,
            "sections": [section.to_dict() for section in self.sections],
            "schema_version": self.schema_version,
            "locale": self.locale,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportTemplate:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            template_id=str(payload.get("template_id") or generate_id()),
            kind=_enum(TemplateKind, payload.get("kind"), TemplateKind.PENTEST),
            version=str(payload.get("version") or "1.0.0"),
            title=str(payload.get("title") or ""),
            sections=tuple(
                TemplateSection.from_dict(item)
                for item in payload.get("sections") or ()
                if isinstance(item, dict)
            ),
            schema_version=str(payload.get("schema_version") or "1.0.0"),
            locale=str(payload.get("locale") or "en"),
            created_at=str(payload.get("created_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class TemplateSection:
    """One data-driven template section.

    Attributes:
        key: section key.
        title: section title.
        order: display order.
        required: whether the section is mandatory.
        description: section description.

    """

    key: str
    title: str
    order: int = 0
    required: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "key": self.key,
            "title": self.title,
            "order": self.order,
            "required": self.required,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TemplateSection:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            key=str(payload.get("key") or ""),
            title=str(payload.get("title") or ""),
            order=int(payload.get("order") or 0),
            required=bool(payload.get("required", False)),
            description=str(payload.get("description") or ""),
        )


@dataclass(frozen=True, slots=True)
class ReportVersion:
    """An immutable report version.

    A new generation never overwrites a historical report.

    Attributes:
        report_id: report identity.
        version: version number.
        finding_id: owning finding.
        template_version: template version used.
        schema_version: report schema version.
        generated_at: UTC ISO-8601 generation timestamp.
        generator_version: generator version.
        source_snapshot: evidence snapshot hash.
        content_hash: SHA-256 of the generated structured content.
        status: report state at generation.

    """

    report_id: str = ""
    version: int = 1
    finding_id: str = ""
    template_version: str = "1.0.0"
    schema_version: str = "1.0.0"
    generated_at: str = field(default_factory=utcnow_iso)
    generator_version: str = "1.0.0"
    source_snapshot: str = ""
    content_hash: str = ""
    status: str = ReportState.DRAFT.value

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "report_id": self.report_id,
            "version": self.version,
            "finding_id": self.finding_id,
            "template_version": self.template_version,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "generator_version": self.generator_version,
            "source_snapshot": self.source_snapshot,
            "content_hash": self.content_hash,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportVersion:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            report_id=str(payload.get("report_id") or ""),
            version=int(payload.get("version") or 1),
            finding_id=str(payload.get("finding_id") or ""),
            template_version=str(payload.get("template_version") or "1.0.0"),
            schema_version=str(payload.get("schema_version") or "1.0.0"),
            generated_at=str(payload.get("generated_at") or utcnow_iso()),
            generator_version=str(payload.get("generator_version") or "1.0.0"),
            source_snapshot=str(payload.get("source_snapshot") or ""),
            content_hash=str(payload.get("content_hash") or ""),
            status=str(payload.get("status") or ReportState.DRAFT.value),
        )


@dataclass(frozen=True, slots=True)
class ReportSnapshot:
    """A consistent evidence snapshot referenced by report generation.

    Report generation always references a consistent snapshot so a report is
    never generated from partially updated data.

    Attributes:
        snapshot_id: stable identifier.
        finding_id: owning finding.
        finding_hash: SHA-256 of the finding snapshot.
        evidence_hash: SHA-256 over the evidence artifact hashes.
        captured_at: UTC ISO-8601 capture timestamp.

    """

    snapshot_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    finding_hash: str = ""
    evidence_hash: str = ""
    captured_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "snapshot_id": self.snapshot_id,
            "finding_id": self.finding_id,
            "finding_hash": self.finding_hash,
            "evidence_hash": self.evidence_hash,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportSnapshot:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            snapshot_id=str(payload.get("snapshot_id") or generate_id()),
            finding_id=str(payload.get("finding_id") or ""),
            finding_hash=str(payload.get("finding_hash") or ""),
            evidence_hash=str(payload.get("evidence_hash") or ""),
            captured_at=str(payload.get("captured_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class FindingIntelligence:
    """The canonical finding-intelligence aggregate.

    Aggregates the finding, evidence, validation, proof, reproduction, impact,
    severity, confidence, quality, target intelligence, asset intelligence,
    technology intelligence, attack-path relationships, root cause, historical
    observations, tool provenance, timestamps, scope, deduplication state and
    report state. It extends (never duplicates) the finding entity.

    Attributes:
        intelligence_id: stable identifier.
        finding_id: owning finding.
        mission_id / target_id / asset_id: scoping identifiers.
        title / description / vulnerability_class: finding summary.
        finding_state: canonical finding lifecycle state.
        severity: evidence-backed severity assessment.
        classification: canonical classification.
        confidence: confidence score in ``[0, 1]``.
        quality: finding quality assessment.
        priority: remediation priority.
        reportability: reportability verdict.
        impact: business impact.
        asset_criticality: asset criticality context.
        attack_path_relationships: attack-path references.
        root_cause: root-cause references.
        historical_observations: historical observation references.
        tool_provenance: tool provenance records.
        timeline: finding timeline.
        evidence_bundle: evidence bundle reference.
        report_state: current report lifecycle state.
        created_at: UTC ISO-8601 creation timestamp.

    """

    intelligence_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    asset_id: str = ""
    title: str = ""
    description: str = ""
    vulnerability_class: str = "unknown_behavior"
    finding_state: str = "candidate"
    severity: SeverityAssessment = field(default_factory=SeverityAssessment)
    classification: Classification = field(default_factory=Classification)
    confidence: float = 0.0
    quality: FindingQuality = field(default_factory=FindingQuality)
    priority: PriorityAssessment = field(default_factory=PriorityAssessment)
    reportability: Reportability = field(default_factory=Reportability)
    impact: BusinessImpact = field(default_factory=BusinessImpact)
    asset_criticality: AssetCriticality = field(default_factory=AssetCriticality)
    attack_path_relationships: tuple[str, ...] = ()
    root_cause: tuple[str, ...] = ()
    historical_observations: tuple[str, ...] = ()
    tool_provenance: tuple[ToolProvenance, ...] = ()
    timeline: FindingTimeline = field(default_factory=FindingTimeline)
    evidence_bundle: EvidenceBundle = field(default_factory=EvidenceBundle)
    report_state: str = ReportState.DRAFT.value
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "intelligence_id": self.intelligence_id,
            "finding_id": self.finding_id,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "asset_id": self.asset_id,
            "title": self.title,
            "description": self.description,
            "vulnerability_class": self.vulnerability_class,
            "finding_state": self.finding_state,
            "severity": self.severity.to_dict(),
            "classification": self.classification.to_dict(),
            "confidence": self.confidence,
            "quality": self.quality.to_dict(),
            "priority": self.priority.to_dict(),
            "reportability": self.reportability.to_dict(),
            "impact": self.impact.to_dict(),
            "asset_criticality": self.asset_criticality.to_dict(),
            "attack_path_relationships": list(self.attack_path_relationships),
            "root_cause": list(self.root_cause),
            "historical_observations": list(self.historical_observations),
            "tool_provenance": [item.to_dict() for item in self.tool_provenance],
            "timeline": self.timeline.to_dict(),
            "evidence_bundle": self.evidence_bundle.to_dict(),
            "report_state": self.report_state,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FindingIntelligence:
        """Rebuild from a :meth:`to_dict` payload."""
        severity = payload.get("severity")
        classification = payload.get("classification")
        quality = payload.get("quality")
        priority = payload.get("priority")
        reportability = payload.get("reportability")
        impact = payload.get("impact")
        criticality = payload.get("asset_criticality")
        timeline = payload.get("timeline")
        bundle = payload.get("evidence_bundle")
        return cls(
            intelligence_id=str(payload.get("intelligence_id") or generate_id()),
            finding_id=str(payload.get("finding_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            target_id=str(payload.get("target_id") or ""),
            asset_id=str(payload.get("asset_id") or ""),
            title=str(payload.get("title") or ""),
            description=str(payload.get("description") or ""),
            vulnerability_class=str(payload.get("vulnerability_class") or "unknown_behavior"),
            finding_state=str(payload.get("finding_state") or "candidate"),
            severity=SeverityAssessment.from_dict(severity) if isinstance(severity, dict) else SeverityAssessment(),
            classification=Classification.from_dict(classification) if isinstance(classification, dict) else Classification(),
            confidence=float(payload.get("confidence") or 0.0),
            quality=FindingQuality.from_dict(quality) if isinstance(quality, dict) else FindingQuality(),
            priority=PriorityAssessment.from_dict(priority) if isinstance(priority, dict) else PriorityAssessment(),
            reportability=Reportability.from_dict(reportability) if isinstance(reportability, dict) else Reportability(),
            impact=BusinessImpact.from_dict(impact) if isinstance(impact, dict) else BusinessImpact(),
            asset_criticality=(
                AssetCriticality.from_dict(criticality) if isinstance(criticality, dict) else AssetCriticality()
            ),
            attack_path_relationships=tuple(str(item) for item in payload.get("attack_path_relationships") or ()),
            root_cause=tuple(str(item) for item in payload.get("root_cause") or ()),
            historical_observations=tuple(str(item) for item in payload.get("historical_observations") or ()),
            tool_provenance=tuple(
                ToolProvenance.from_dict(item)
                for item in payload.get("tool_provenance") or ()
                if isinstance(item, dict)
            ),
            timeline=FindingTimeline.from_dict(timeline) if isinstance(timeline, dict) else FindingTimeline(),
            evidence_bundle=EvidenceBundle.from_dict(bundle) if isinstance(bundle, dict) else EvidenceBundle(),
            report_state=str(payload.get("report_state") or ReportState.DRAFT.value),
            created_at=str(payload.get("created_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class ExecutiveSummary:
    """Executive-level summary aggregates for a report.

    Avoids technical jargon where unnecessary.

    Attributes:
        report_id: report identity.
        finding_count: number of findings.
        severity_distribution: severity counts.
        critical_assets: critical assets referenced.
        major_attack_paths: major attack paths.
        root_causes: root-cause identifiers.
        risk_concentration: risk concentration notes.
        remediation_priorities: remediation priority notes.
        validated_impact: validated impact notes.
        generated_at: UTC ISO-8601 generation timestamp.

    """

    report_id: str = ""
    finding_count: int = 0
    severity_distribution: Mapping[str, int] = field(default_factory=dict)
    critical_assets: tuple[str, ...] = ()
    major_attack_paths: tuple[str, ...] = ()
    root_causes: tuple[str, ...] = ()
    risk_concentration: tuple[str, ...] = ()
    remediation_priorities: tuple[str, ...] = ()
    validated_impact: tuple[str, ...] = ()
    generated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "report_id": self.report_id,
            "finding_count": self.finding_count,
            "severity_distribution": dict(self.severity_distribution),
            "critical_assets": list(self.critical_assets),
            "major_attack_paths": list(self.major_attack_paths),
            "root_causes": list(self.root_causes),
            "risk_concentration": list(self.risk_concentration),
            "remediation_priorities": list(self.remediation_priorities),
            "validated_impact": list(self.validated_impact),
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ExecutiveSummary:
        """Rebuild from a :meth:`to_dict` payload."""
        return cls(
            report_id=str(payload.get("report_id") or ""),
            finding_count=int(payload.get("finding_count") or 0),
            severity_distribution={
                str(key): int(value) for key, value in dict(payload.get("severity_distribution") or {}).items()
            },
            critical_assets=tuple(str(item) for item in payload.get("critical_assets") or ()),
            major_attack_paths=tuple(str(item) for item in payload.get("major_attack_paths") or ()),
            root_causes=tuple(str(item) for item in payload.get("root_causes") or ()),
            risk_concentration=tuple(str(item) for item in payload.get("risk_concentration") or ()),
            remediation_priorities=tuple(str(item) for item in payload.get("remediation_priorities") or ()),
            validated_impact=tuple(str(item) for item in payload.get("validated_impact") or ()),
            generated_at=str(payload.get("generated_at") or utcnow_iso()),
        )


@dataclass(frozen=True, slots=True)
class ReportDocument:
    """The consolidated, versioned report document.

    Attributes:
        report_id: stable report identity.
        finding_id: owning finding.
        mission_id / target_id: scoping identifiers.
        title: report title.
        template: template kind.
        template_version: template version.
        schema_version: report schema version.
        status: report lifecycle state.
        version: report version number.
        intelligence: finding-intelligence aggregates.
        classification: canonical classification.
        severity: severity assessment.
        priority: priority assessment.
        quality: quality assessment.
        reportability: reportability verdict.
        impact: business impact.
        asset_criticality: asset criticality.
        remediation: remediation plan.
        retest: retest plan.
        reproduction: reproduction section.
        poc: PoC presentation.
        evidence_bundle: evidence bundle.
        timeline: finding timeline.
        tool_provenance: tool provenance records.
        claims: report claims.
        qa: QA result.
        redaction: redaction metadata.
        executive_summary: executive summary.
        correlation: cross-finding correlation report.
        testing_matrix: security testing matrix.
        attack_paths: attack-path references.
        root_causes: root-cause references.
        references: knowledge references.
        generated_at: UTC ISO-8601 generation timestamp.

    """

    report_id: str = field(default_factory=generate_id)
    finding_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    title: str = ""
    template: TemplateKind = TemplateKind.PENTEST
    template_version: str = "1.0.0"
    schema_version: str = "1.0.0"
    status: str = ReportState.DRAFT.value
    version: int = 1
    intelligence: FindingIntelligence | None = None
    classification: Classification = field(default_factory=Classification)
    severity: SeverityAssessment = field(default_factory=SeverityAssessment)
    priority: PriorityAssessment = field(default_factory=PriorityAssessment)
    quality: FindingQuality = field(default_factory=FindingQuality)
    reportability: Reportability = field(default_factory=Reportability)
    impact: BusinessImpact = field(default_factory=BusinessImpact)
    asset_criticality: AssetCriticality = field(default_factory=AssetCriticality)
    remediation: RemediationPlan | None = None
    retest: RetestPlan | None = None
    reproduction: ReproductionSection | None = None
    poc: PoCPresentation | None = None
    evidence_bundle: EvidenceBundle = field(default_factory=EvidenceBundle)
    timeline: FindingTimeline = field(default_factory=FindingTimeline)
    tool_provenance: tuple[ToolProvenance, ...] = ()
    claims: tuple[ReportClaim, ...] = ()
    qa: ReportQaResult = field(default_factory=ReportQaResult)
    redaction: ReportRedaction = field(default_factory=ReportRedaction)
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    correlation: FindingCorrelationReport = field(default_factory=FindingCorrelationReport)
    testing_matrix: SecurityTestingMatrix = field(default_factory=SecurityTestingMatrix)
    attack_paths: tuple[str, ...] = ()
    root_causes: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    generated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "mission_id": self.mission_id,
            "target_id": self.target_id,
            "title": self.title,
            "template": self.template.value,
            "template_version": self.template_version,
            "schema_version": self.schema_version,
            "status": self.status,
            "version": self.version,
            "intelligence": self.intelligence.to_dict() if self.intelligence else None,
            "classification": self.classification.to_dict(),
            "severity": self.severity.to_dict(),
            "priority": self.priority.to_dict(),
            "quality": self.quality.to_dict(),
            "reportability": self.reportability.to_dict(),
            "impact": self.impact.to_dict(),
            "asset_criticality": self.asset_criticality.to_dict(),
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "retest": self.retest.to_dict() if self.retest else None,
            "reproduction": self.reproduction.to_dict() if self.reproduction else None,
            "poc": self.poc.to_dict() if self.poc else None,
            "evidence_bundle": self.evidence_bundle.to_dict(),
            "timeline": self.timeline.to_dict(),
            "tool_provenance": [item.to_dict() for item in self.tool_provenance],
            "claims": [claim.to_dict() for claim in self.claims],
            "qa": self.qa.to_dict(),
            "redaction": self.redaction.to_dict(),
            "executive_summary": self.executive_summary.to_dict(),
            "correlation": self.correlation.to_dict(),
            "testing_matrix": self.testing_matrix.to_dict(),
            "attack_paths": list(self.attack_paths),
            "root_causes": list(self.root_causes),
            "references": list(self.references),
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ReportDocument:
        """Rebuild from a :meth:`to_dict` payload."""
        intelligence = payload.get("intelligence")
        remediation = payload.get("remediation")
        retest = payload.get("retest")
        reproduction = payload.get("reproduction")
        poc = payload.get("poc")
        return cls(
            report_id=str(payload.get("report_id") or generate_id()),
            finding_id=str(payload.get("finding_id") or ""),
            mission_id=str(payload.get("mission_id") or ""),
            target_id=str(payload.get("target_id") or ""),
            title=str(payload.get("title") or ""),
            template=_enum(TemplateKind, payload.get("template"), TemplateKind.PENTEST),
            template_version=str(payload.get("template_version") or "1.0.0"),
            schema_version=str(payload.get("schema_version") or "1.0.0"),
            status=str(payload.get("status") or ReportState.DRAFT.value),
            version=int(payload.get("version") or 1),
            intelligence=FindingIntelligence.from_dict(intelligence) if isinstance(intelligence, dict) else None,
            classification=(
                Classification.from_dict(payload["classification"]) if isinstance(payload.get("classification"), dict) else Classification()
            ),
            severity=(
                SeverityAssessment.from_dict(payload["severity"]) if isinstance(payload.get("severity"), dict) else SeverityAssessment()
            ),
            priority=(
                PriorityAssessment.from_dict(payload["priority"]) if isinstance(payload.get("priority"), dict) else PriorityAssessment()
            ),
            quality=(
                FindingQuality.from_dict(payload["quality"]) if isinstance(payload.get("quality"), dict) else FindingQuality()
            ),
            reportability=(
                Reportability.from_dict(payload["reportability"])
                if isinstance(payload.get("reportability"), dict)
                else Reportability()
            ),
            impact=(
                BusinessImpact.from_dict(payload["impact"]) if isinstance(payload.get("impact"), dict) else BusinessImpact()
            ),
            asset_criticality=(
                AssetCriticality.from_dict(payload["asset_criticality"])
                if isinstance(payload.get("asset_criticality"), dict)
                else AssetCriticality()
            ),
            remediation=RemediationPlan.from_dict(remediation) if isinstance(remediation, dict) else None,
            retest=RetestPlan.from_dict(retest) if isinstance(retest, dict) else None,
            reproduction=ReproductionSection.from_dict(reproduction) if isinstance(reproduction, dict) else None,
            poc=PoCPresentation.from_dict(poc) if isinstance(poc, dict) else None,
            evidence_bundle=(
                EvidenceBundle.from_dict(payload["evidence_bundle"])
                if isinstance(payload.get("evidence_bundle"), dict)
                else EvidenceBundle()
            ),
            timeline=(
                FindingTimeline.from_dict(payload["timeline"]) if isinstance(payload.get("timeline"), dict) else FindingTimeline()
            ),
            tool_provenance=tuple(
                ToolProvenance.from_dict(item)
                for item in payload.get("tool_provenance") or ()
                if isinstance(item, dict)
            ),
            claims=tuple(
                ReportClaim.from_dict(item)
                for item in payload.get("claims") or ()
                if isinstance(item, dict)
            ),
            qa=ReportQaResult.from_dict(payload["qa"]) if isinstance(payload.get("qa"), dict) else ReportQaResult(),
            redaction=(
                ReportRedaction.from_dict(payload["redaction"])
                if isinstance(payload.get("redaction"), dict)
                else ReportRedaction()
            ),
            executive_summary=(
                ExecutiveSummary.from_dict(payload["executive_summary"])
                if isinstance(payload.get("executive_summary"), dict)
                else ExecutiveSummary()
            ),
            correlation=(
                FindingCorrelationReport.from_dict(payload["correlation"])
                if isinstance(payload.get("correlation"), dict)
                else FindingCorrelationReport()
            ),
            testing_matrix=(
                SecurityTestingMatrix.from_dict(payload["testing_matrix"])
                if isinstance(payload.get("testing_matrix"), dict)
                else SecurityTestingMatrix()
            ),
            attack_paths=tuple(str(item) for item in payload.get("attack_paths") or ()),
            root_causes=tuple(str(item) for item in payload.get("root_causes") or ()),
            references=tuple(str(item) for item in payload.get("references") or ()),
            generated_at=str(payload.get("generated_at") or utcnow_iso()),
        )


# -- parsing helpers --------------------------------------------------------


def _enum(enum_cls: type[Any], value: object, default: Any) -> Any:
    """Coerce ``value`` into ``enum_cls`` falling back to ``default``."""
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value).lower())
    except (TypeError, ValueError):
        return default


def _opt_str(value: object) -> str | None:
    """Return ``None`` for empty strings."""
    if value is None or value == "":
        return None
    return str(value)


def _opt_float(value: object) -> float | None:
    """Return ``None`` when the value cannot be parsed as a float."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (str, bytes, bytearray)):
            return float(value)
        return float(str(value))
    except (TypeError, ValueError):
        return None


__all__ = [
    "AssetCriticality",
    "AttackMapping",
    "BusinessImpact",
    "Classification",
    "CrossFindingRelation",
    "CvssAssessment",
    "CweMapping",
    "EvidenceArtifact",
    "EvidenceBundle",
    "ExecutiveSummary",
    "FindingCorrelationReport",
    "FindingIntelligence",
    "FindingQuality",
    "FindingTimeline",
    "OwaspMapping",
    "PoCPresentation",
    "PriorityAssessment",
    "PriorityFactor",
    "QaCheckResult",
    "QualityFactorScore",
    "RedactionRecord",
    "RemediationPlan",
    "ReportClaim",
    "ReportDocument",
    "ReportQaResult",
    "ReportRedaction",
    "ReportSnapshot",
    "ReportTemplate",
    "ReportVersion",
    "Reportability",
    "ReportabilityCheck",
    "ReproductionSection",
    "RetestPlan",
    "SecurityTestingMatrix",
    "SecurityTestingStateEntry",
    "SeverityAssessment",
    "SourceReliabilityModel",
    "TemplateSection",
    "TimelineEntry",
    "ToolProvenance",
]
