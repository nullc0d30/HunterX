# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Target Intelligence — canonical enums.

Sprint 026. Pure, storage-agnostic value categories for the target
intelligence layer: target lifecycle, mission phases, observation taxonomy,
coverage states, capability dimensions, unknown categories, information gap
categories, hypothesis taxonomy and lifecycle, action taxonomy and lifecycle,
change kinds and intelligence score dimensions.

The vocabulary keeps observed facts (observations), derived state (coverage),
explicit uncertainty (unknowns/gaps), conjectures (hypotheses) and validated
conclusions (proofs) strictly separated. Missing information is NEVER treated
as negative information: ``NOT_ASSESSED``/``UNKNOWN`` coverage states exist for
exactly that reason.
"""

from __future__ import annotations

from enum import StrEnum


class IntelligenceTargetStatus(StrEnum):
    """Lifecycle state of a canonical intelligence target.

    ``ACTIVE`` means the target is currently being interrogated; ``STALE``
    means no observation refreshed it recently; ``EXPIRED`` means its data
    exceeded the freshness policy; ``COMPLETED`` means the mission reached a
    justified terminal state; ``ARCHIVED`` means it is retained for history
    only.
    """

    ACTIVE = "active"
    STALE = "stale"
    EXPIRED = "expired"
    COMPLETED = "completed"
    ARCHIVED = "archived"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for states that end active intelligence work."""
        return self in (
            IntelligenceTargetStatus.COMPLETED,
            IntelligenceTargetStatus.ARCHIVED,
            IntelligenceTargetStatus.EXPIRED,
        )


class IntelligenceTargetKind(StrEnum):
    """Canonical kinds a top-level target may take.

    A target is never merely a hostname: it is the authorized objective of a
    mission (an organization, a program, a domain tree, an account, ...).
    """

    ORGANIZATION = "organization"
    PROGRAM = "program"
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    HOST = "host"
    URL = "url"
    CLOUD_ACCOUNT = "cloud_account"
    REPOSITORY = "repository"
    SAAS_TENANT = "saas_tenant"


class IntelligencePhase(StrEnum):
    """Mission intelligence state machine.

    Transitions are derived from intelligence state (coverage, unknowns,
    hypotheses, evidence), never from a fixed tool list.
    """

    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    MAPPING = "mapping"
    ANALYSIS = "analysis"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"
    PROOF = "proof"
    REPORTING = "reporting"

    @property
    def rank(self) -> int:
        """Return the escalation rank used for ordering."""
        return {
            IntelligencePhase.DISCOVERY: 0,
            IntelligencePhase.ENUMERATION: 1,
            IntelligencePhase.MAPPING: 2,
            IntelligencePhase.ANALYSIS: 3,
            IntelligencePhase.HYPOTHESIS: 4,
            IntelligencePhase.VALIDATION: 5,
            IntelligencePhase.PROOF: 6,
            IntelligencePhase.REPORTING: 7,
        }[self]


class ObservationType(StrEnum):
    """Canonical taxonomy of intelligence observations.

    Every normalized tool result maps to at least one observation type. The
    taxonomy spans assets, services, technologies, web/API surfaces, cloud
    resources, proofs and the ``NEGATIVE`` marker used for carefully-scoped
    negative results.
    """

    ASSET = "asset"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    API = "api"
    GRAPHQL = "graphql"
    JAVASCRIPT = "javascript"
    CLOUD_RESOURCE = "cloud_resource"
    SAAS = "saas"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    REPOSITORY = "repository"
    SECRET = "secret"
    AUTHENTICATION_SURFACE = "authentication_surface"
    AUTHORIZATION_SURFACE = "authorization_surface"
    VULNERABILITY = "vulnerability"
    FINDING = "finding"
    EVIDENCE = "evidence"
    PROOF = "proof"
    CVE = "cve"
    CWE = "cwe"
    RELATIONSHIP = "relationship"
    NEGATIVE = "negative"
    OTHER = "other"


class CoverageCapability(StrEnum):
    """Canonical coverage dimensions the matrix is measured across.

    Coverage is measured per (asset, capability) — never merely "number of
    tools executed". Each capability can also be re-scoped to a vulnerability
    class for vulnerability coverage.
    """

    ASSET_DISCOVERY = "asset_discovery"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    PORT_DISCOVERY = "port_discovery"
    SERVICE_DETECTION = "service_detection"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    CONTENT_DISCOVERY = "content_discovery"
    PARAMETER_DISCOVERY = "parameter_discovery"
    ENDPOINT_ENUMERATION = "endpoint_enumeration"
    API_MAPPING = "api_mapping"
    GRAPHQL_ENUMERATION = "graphql_enumeration"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    DNS_ENUMERATION = "dns_enumeration"
    CERTIFICATE_ENUMERATION = "certificate_enumeration"
    AUTHENTICATION_ANALYSIS = "authentication_analysis"
    AUTHORIZATION_ANALYSIS = "authorization_analysis"
    CLOUD_OWNERSHIP_MAPPING = "cloud_ownership_mapping"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    LFI = "lfi"
    RCE = "rce"
    IDOR = "idor"
    API_SECURITY = "api_security"
    GRAPHQL_SECURITY = "graphql_security"
    SECRET_DETECTION = "secret_detection"
    DEPENDENCY_CHECK = "dependency_check"
    PROOF_VALIDATION = "proof_validation"
    REPLAY = "replay"

    #: Map a :class:`HypothesisType` to the coverage capability that validates
    #: it, so adaptive validation can find the coverage cell to update.
    @classmethod
    def for_hypothesis(cls, hypothesis_type: str) -> CoverageCapability:
        """Return the coverage capability that validates a hypothesis type."""
        mapping = {
            "injection": CoverageCapability.SQL_INJECTION,
            "xss": CoverageCapability.XSS,
            "ssrf": CoverageCapability.SSRF,
            "ssti": CoverageCapability.SSTI,
            "xxe": CoverageCapability.XXE,
            "lfi": CoverageCapability.LFI,
            "rfi": CoverageCapability.LFI,
            "rce": CoverageCapability.RCE,
            "idor": CoverageCapability.IDOR,
            "api_security": CoverageCapability.API_SECURITY,
            "graphql_security": CoverageCapability.GRAPHQL_SECURITY,
            "cloud_exposure": CoverageCapability.CLOUD_OWNERSHIP_MAPPING,
            "secret_exposure": CoverageCapability.SECRET_DETECTION,
            "dependency_vulnerability": CoverageCapability.DEPENDENCY_CHECK,
        }
        return mapping.get(hypothesis_type, CoverageCapability.VULNERABILITY_SCANNING)


class CoverageState(StrEnum):
    """Canonical coverage state of a (asset, capability) cell.

    ``UNKNOWN`` means no information exists; ``NOT_ASSESSED`` means the
    capability was never exercised; ``CANDIDATE`` means a hypothesis/evidence
    candidate exists; ``TESTED`` means a tool exercised the capability under
    recorded conditions (a negative result is still ``TESTED`` with a recorded
    negative result); ``VALIDATED`` means the result was validated;
    ``PROVED`` means proof exists; ``NOT_APPLICABLE`` means the capability
    does not apply to the asset.
    """

    UNKNOWN = "unknown"
    NOT_ASSESSED = "not_assessed"
    CANDIDATE = "candidate"
    TESTED = "tested"
    VALIDATED = "validated"
    PROVED = "proved"
    NOT_APPLICABLE = "not_applicable"

    @property
    def rank(self) -> int:
        """Return the escalation rank used for progress comparison."""
        return {
            CoverageState.UNKNOWN: 0,
            CoverageState.NOT_ASSESSED: 0,
            CoverageState.NOT_APPLICABLE: 0,
            CoverageState.CANDIDATE: 1,
            CoverageState.TESTED: 2,
            CoverageState.VALIDATED: 3,
            CoverageState.PROVED: 4,
        }[self]

    def uncovered(self) -> bool:
        """Return ``True`` when the cell still needs action."""
        return self in (
            CoverageState.UNKNOWN,
            CoverageState.NOT_ASSESSED,
            CoverageState.CANDIDATE,
        )


class UnknownCategory(StrEnum):
    """Canonical categories of explicit uncertainty.

    Uncertainty is first-class: the platform must say "we do not know X yet"
    instead of pretending a gap is a negative result.
    """

    TECHNOLOGY = "technology"
    BACKEND = "backend"
    API_BEHAVIOR = "api_behavior"
    AUTHENTICATION_BOUNDARY = "authentication_boundary"
    AUTHORIZATION_BOUNDARY = "authorization_boundary"
    PARAMETER_BEHAVIOR = "parameter_behavior"
    CLOUD_OWNERSHIP = "cloud_ownership"
    SERVICE_VERSION = "service_version"
    ENDPOINT_PURPOSE = "endpoint_purpose"
    VULNERABILITY_STATE = "vulnerability_state"
    ASSET_OWNERSHIP = "asset_ownership"


class InformationGapCategory(StrEnum):
    """Canonical categories of :class:`InformationGap`.

    Each gap carries a question, importance, required capability and candidate
    tools so the next-action engine can close it with the smallest justified
    tool set.
    """

    ASSET_DISCOVERY = "asset_discovery"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    PORT_DISCOVERY = "port_discovery"
    SERVICE_DETECTION = "service_detection"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    CONTENT_DISCOVERY = "content_discovery"
    PARAMETER_DISCOVERY = "parameter_discovery"
    ENDPOINT_MAPPING = "endpoint_mapping"
    API_MAPPING = "api_mapping"
    GRAPHQL_SCHEMA = "graphql_schema"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    AUTHENTICATION_MAPPING = "authentication_mapping"
    AUTHORIZATION_MAPPING = "authorization_mapping"
    CLOUD_OWNERSHIP = "cloud_ownership"
    VULNERABILITY_TESTING = "vulnerability_testing"
    PROOF_VALIDATION = "proof_validation"
    REPLAY = "replay"

    @classmethod
    def for_unknown(cls, category: UnknownCategory) -> InformationGapCategory:
        """Map an unknown category to the canonical gap category."""
        mapping = {
            UnknownCategory.TECHNOLOGY: InformationGapCategory.TECHNOLOGY_FINGERPRINT,
            UnknownCategory.BACKEND: InformationGapCategory.TECHNOLOGY_FINGERPRINT,
            UnknownCategory.API_BEHAVIOR: InformationGapCategory.API_MAPPING,
            UnknownCategory.AUTHENTICATION_BOUNDARY: InformationGapCategory.AUTHENTICATION_MAPPING,
            UnknownCategory.AUTHORIZATION_BOUNDARY: InformationGapCategory.AUTHORIZATION_MAPPING,
            UnknownCategory.PARAMETER_BEHAVIOR: InformationGapCategory.PARAMETER_DISCOVERY,
            UnknownCategory.CLOUD_OWNERSHIP: InformationGapCategory.CLOUD_OWNERSHIP,
            UnknownCategory.SERVICE_VERSION: InformationGapCategory.SERVICE_DETECTION,
            UnknownCategory.ENDPOINT_PURPOSE: InformationGapCategory.ENDPOINT_MAPPING,
            UnknownCategory.VULNERABILITY_STATE: InformationGapCategory.VULNERABILITY_TESTING,
            UnknownCategory.ASSET_OWNERSHIP: InformationGapCategory.ASSET_DISCOVERY,
        }
        return mapping.get(category, InformationGapCategory.ASSET_DISCOVERY)


class HypothesisType(StrEnum):
    """Canonical hypothesis taxonomy.

    Hypotheses are conjectures to validate — never conclusions. ``NOVEL_VARIANT``
    covers behavior that matches no known signature, so a finding never requires
    a CVE to exist first.
    """

    KNOWN_VULNERABILITY = "known_vulnerability"
    MISCONFIGURATION = "misconfiguration"
    AUTHENTICATION_ISSUE = "authentication_issue"
    AUTHORIZATION_ISSUE = "authorization_issue"
    INJECTION = "injection"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    IDOR = "idor"
    BUSINESS_LOGIC = "business_logic"
    API_SECURITY = "api_security"
    GRAPHQL_SECURITY = "graphql_security"
    CLOUD_EXPOSURE = "cloud_exposure"
    SECRET_EXPOSURE = "secret_exposure"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    UNKNOWN_BEHAVIOR = "unknown_behavior"
    NOVEL_VARIANT = "novel_variant"


class HypothesisStatus(StrEnum):
    """Lifecycle state of a hypothesis.

    ``PROPOSED`` → ``SUPPORTED``/``CONTRADICTED`` → ``VALIDATED`` → ``PROVEN``,
    with ``INCONCLUSIVE`` keeping the hypothesis open and ``DISMISSED``
    refuting it. A hypothesis is never "confirmed" by scanner output alone.
    """

    PROPOSED = "proposed"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    VALIDATED = "validated"
    PROVEN = "proven"
    INCONCLUSIVE = "inconclusive"
    DISMISSED = "dismissed"


class ActionType(StrEnum):
    """Canonical action taxonomy of the next-action engine.

    The pipeline moves from discovery → enumeration → mapping → analysis →
    hypothesis → validation → proof → reporting; the engine must be able to
    move backwards too (a new asset re-opens discovery).
    """

    DISCOVER = "discover"
    ENUMERATE = "enumerate"
    FINGERPRINT = "fingerprint"
    MAP = "map"
    ANALYZE = "analyze"
    TEST = "test"
    VALIDATE = "validate"
    PROVE = "prove"
    MONITOR = "monitor"
    REASSESS = "reassess"
    STOP = "stop"


class ActionStatus(StrEnum):
    """Lifecycle state of a proposed action."""

    PROPOSED = "proposed"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    SUPERSEDED = "superseded"


class ChangeKind(StrEnum):
    """Canonical target change taxonomy produced by the change detector.

    ``NEW``/``REMOVED``/``CHANGED`` are the base set; ``REAPPEARED`` tracks
    assets that returned after removal; ``EXPIRED`` marks stale intelligence;
    ``RECLASSIFIED`` marks a re-categorised asset; ``CORROBORATED`` records an
    independently confirmed observation; ``CONFLICTED`` records a preserved
    contradiction that requires validation.
    """

    NEW = "new"
    REMOVED = "removed"
    CHANGED = "changed"
    REAPPEARED = "reappeared"
    EXPIRED = "expired"
    RECLASSIFIED = "reclassified"
    CORROBORATED = "corroborated"
    CONFLICTED = "conflicted"


class IntelligenceDimension(StrEnum):
    """Explainable intelligence score dimensions.

    Scores are never collapsed into one opaque number: each dimension is
    reported, and the final aggregate is a weighted explainable combination.
    """

    ASSET_COVERAGE = "asset_coverage"
    SERVICE_COVERAGE = "service_coverage"
    WEB_COVERAGE = "web_coverage"
    API_COVERAGE = "api_coverage"
    CLOUD_COVERAGE = "cloud_coverage"
    VULNERABILITY_COVERAGE = "vulnerability_coverage"
    EVIDENCE_QUALITY = "evidence_quality"
    PROOF_COVERAGE = "proof_coverage"
    HISTORICAL_COVERAGE = "historical_coverage"
    UNKNOWN_RATIO = "unknown_ratio"


class ConflictState(StrEnum):
    """Lifecycle state of a preserved intelligence conflict.

    Conflicting tool results are never averaged; they are preserved and
    escalated for higher-quality evidence collection.
    """

    OPEN = "open"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class StopCondition(StrEnum):
    """Canonical stop conditions for actions.

    Every action carries stop conditions so the mission can terminate on
    justified grounds instead of running forever.
    """

    SUFFICIENT_EVIDENCE = "sufficient_evidence"
    SCOPE_EXHAUSTED = "scope_exhausted"
    PROOF_VALIDATED = "proof_validated"
    RISK_THRESHOLD = "risk_threshold_exceeded"
    RATE_LIMIT = "rate_limit_reached"
    TOOL_FAILURE = "tool_failure"
    DUPLICATE_EVIDENCE = "duplicate_evidence"
    TARGET_REMOVED = "target_removed"
    AUTHORIZATION_UNAVAILABLE = "authorization_unavailable"


__all__ = [
    "ActionStatus",
    "ActionType",
    "ChangeKind",
    "ConflictState",
    "CoverageCapability",
    "CoverageState",
    "HypothesisStatus",
    "HypothesisType",
    "InformationGapCategory",
    "IntelligenceDimension",
    "IntelligencePhase",
    "IntelligenceTargetKind",
    "IntelligenceTargetStatus",
    "ObservationType",
    "StopCondition",
    "UnknownCategory",
]
