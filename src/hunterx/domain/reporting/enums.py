# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Professional finding intelligence & reporting canonical enums.

Pure, storage-agnostic value categories for the Sprint 029 professional
reporting capability. They keep the report lifecycle, reportability,
quality, priority, claim, QA, export, remediation, retest, classification,
source-reliability and security-testing vocabulary strictly separated so a
report is never a text generator output: evidence decides the truth and the
AI only explains it.

The security model of this package is explicit: a report is never
``READY_FOR_SUBMISSION`` while an unsupported claim, an unredacted secret or
a QA failure is open; every material claim must trace back to evidence.
"""

from __future__ import annotations

from enum import StrEnum


class ReportState(StrEnum):
    """Lifecycle states of a professional report.

    Every transition is explicit (see
    :mod:`hunterx.domain.reporting.lifecycle`). ``READY_FOR_SUBMISSION`` is
    only reachable after QA passed and no unsupported high-impact claim is
    open.
    """

    DRAFT = "draft"
    EVIDENCE_REVIEW = "evidence_review"
    ANALYSIS_COMPLETE = "analysis_complete"
    REPORTABLE = "reportable"
    REPORT_GENERATED = "report_generated"
    QA_REQUIRED = "qa_required"
    QA_PASSED = "qa_passed"
    QA_FAILED = "qa_failed"
    READY_FOR_SUBMISSION = "ready_for_submission"
    SUBMITTED = "submitted"
    REOPENED = "reopened"
    REMEDIATED = "remediated"
    RETESTED = "retested"
    CLOSED = "closed"


class ReportabilityStatus(StrEnum):
    """Verdict of the reportability engine for a finding."""

    REPORTABLE = "reportable"
    INCOMPLETE = "incomplete"
    DISPUTED = "disputed"
    DUPLICATE = "duplicate"
    OUT_OF_SCOPE = "out_of_scope"
    NOT_ACTIONABLE = "not_actionable"


class QualityGrade(StrEnum):
    """Band of the report-quality score."""

    A = "a"
    B = "b"
    C = "c"
    D = "d"
    F = "f"


class PriorityLevel(StrEnum):
    """Remediation priority of a finding.

    Priority is not severity: it combines severity, confidence, quality,
    asset criticality, exploitability, proof strength, attack-path position,
    business impact, exposure, remediation difficulty and root-cause
    recurrence.
    """

    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class ClaimState(StrEnum):
    """Verification state of a report claim."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"
    VERIFIED = "verified"
    BLOCKED = "blocked"


class ClaimType(StrEnum):
    """Type of a material report claim."""

    VULNERABILITY = "vulnerability"
    AFFECTED_ASSET = "affected_asset"
    IMPACT = "impact"
    SEVERITY = "severity"
    EXPLOITABILITY = "exploitability"
    REPRODUCTION = "reproduction"
    ROOT_CAUSE = "root_cause"
    REMEDIATION = "remediation"
    CVSS = "cvss"
    CWE = "cwe"
    OWASP = "owasp"
    ATTACK_PATH = "attack_path"
    BUSINESS_IMPACT = "business_impact"


class QaVerdict(StrEnum):
    """Verdict of a single report QA check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class ExportFormat(StrEnum):
    """Supported report export formats."""

    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    SARIF = "sarif"
    PDF = "pdf"
    PACKAGE = "package"


class RemediationState(StrEnum):
    """Lifecycle of remediation validation for a finding.

    Mirrors the sprint contract: original finding, remediation applied,
    retest, proof replay, finding state and closure.
    """

    OPEN = "open"
    REMEDIATION_IN_PROGRESS = "remediation_in_progress"
    RETEST_REQUIRED = "retest_required"
    RETESTING = "retesting"
    FIX_VERIFIED = "fix_verified"
    FIX_FAILED = "fix_failed"
    REOPENED = "reopened"
    CLOSED = "closed"


class RetestState(StrEnum):
    """Lifecycle of a retest plan execution."""

    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"


class TemplateKind(StrEnum):
    """Canonical report template kinds."""

    BUG_BOUNTY = "bug_bounty"
    PENTEST = "pentest"
    EXECUTIVE_PENTEST = "executive_pentest"
    TECHNICAL_PENTEST = "technical_pentest"
    WEB_APP_PENTEST = "web_app_pentest"
    API_PENTEST = "api_pentest"
    CLOUD_ASSESSMENT = "cloud_assessment"
    RED_TEAM = "red_team"
    VULNERABILITY_DISCLOSURE = "vulnerability_disclosure"
    RESEARCH = "research"


class SourceReliabilityKind(StrEnum):
    """Classification of an evidence source.

    Direct validated evidence must always outrank AI inference.
    """

    DIRECT_OBSERVATION = "direct_observation"
    VALIDATED_REPLAY = "validated_replay"
    CONTROLLED_CALLBACK = "controlled_callback"
    TOOL_SIGNATURE = "tool_signature"
    HISTORICAL_ARCHIVE = "historical_archive"
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    AI_INFERENCE = "ai_inference"
    ANALYST_ANNOTATION = "analyst_annotation"


class ReliabilityRank(StrEnum):
    """Ordered reliability rank of an evidence source."""

    DIRECT = "direct"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class SecurityTestingState(StrEnum):
    """Verification strength of a finding inside a report.

    The report must never mix these states.
    """

    CONFIRMED = "confirmed"
    VALIDATED = "validated"
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    THEORETICAL = "theoretical"
    UNVERIFIED = "unverified"


class ClassificationSource(StrEnum):
    """Canonical classification vocabularies a finding maps onto."""

    CWE = "cwe"
    OWASP = "owasp"
    CAPEC = "capec"
    CVE = "cve"
    CVSS = "cvss"
    ATTACK = "attack"
    HUNTERX = "hunterx"


class OwaspFramework(StrEnum):
    """OWASP classification framework referenced by a mapping."""

    TOP_10 = "owasp_top_10"
    API_TOP_10 = "owasp_api_top_10"
    ASVS = "owasp_asvs"
    TESTING_GUIDE = "owasp_wstg"


class BusinessImpactType(StrEnum):
    """Business-impact categories a report may claim.

    Every impact claim must have evidence or explicit analyst reasoning.
    """

    DATA_EXPOSURE = "data_exposure"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    ACCOUNT_TAKEOVER = "account_takeover"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    CLOUD_RESOURCE_ACCESS = "cloud_resource_access"
    FINANCIAL_IMPACT = "financial_impact"
    BUSINESS_PROCESS_MANIPULATION = "business_process_manipulation"
    AVAILABILITY_IMPACT = "availability_impact"
    REPUTATION_SECURITY_BOUNDARY = "reputation_security_boundary"


class FindingTimelineEvent(StrEnum):
    """Canonical finding-timeline event names."""

    TARGET_DISCOVERED = "target_discovered"
    ENDPOINT_IDENTIFIED = "endpoint_identified"
    CANDIDATE_GENERATED = "candidate_generated"
    VALIDATION_STARTED = "validation_started"
    EVIDENCE_CAPTURED = "evidence_captured"
    PROOF_GENERATED = "proof_generated"
    PROOF_REPLAYED = "proof_replayed"
    IMPACT_CONFIRMED = "impact_confirmed"
    FINDING_FINALIZED = "finding_finalized"


__all__ = [
    "BusinessImpactType",
    "ClaimState",
    "ClaimType",
    "ClassificationSource",
    "ExportFormat",
    "FindingTimelineEvent",
    "OwaspFramework",
    "PriorityLevel",
    "QaVerdict",
    "QualityGrade",
    "ReliabilityRank",
    "RemediationState",
    "ReportState",
    "ReportabilityStatus",
    "RetestState",
    "SecurityTestingState",
    "SourceReliabilityKind",
    "TemplateKind",
]
