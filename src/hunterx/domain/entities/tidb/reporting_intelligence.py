# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Professional reporting TIDB entities.

System-of-record entities for the Sprint 029 professional finding intelligence
& reporting capability: report metadata, report versions, templates and
template versions, claim records, QA results, evidence snapshots, report
packages, remediation plans, retest plans and submission state.

Security boundary: these tables store canonical, redacted report data only —
never credentials, never exploit payloads, never out-of-scope request
material. Report exports are immutable/versioned. The TIDB envelope provides
``version`` (the report/template version) and ``created_at``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class ReportRecord(TidbEntity):
    """Canonical professional report metadata projection.

    Attributes:
        report_id: canonical report identifier (envelope ``id`` aliases it).
        finding_id / mission_id / target_id: scoping identifiers.
        title: report title.
        template / template_version: template kind and version.
        report_schema_version: report schema version.
        status: report lifecycle state.
        generator_version: report generator version.
        version: current report version number (envelope ``version``).

    """

    report_id: str
    finding_id: str = ""
    mission_id: str = ""
    target_id: str = ""
    title: str = ""
    template: str = "pentest"
    template_version: str = "1.0.0"
    report_schema_version: str = "1.0.0"
    status: str = "draft"
    generator_version: str = "1.0.0"


@dataclass(slots=True)
class ReportVersionRecord(TidbEntity):
    """An immutable report version.

    Attributes:
        report_id: owning report.
        version: version number (envelope ``version``).
        finding_id: owning finding.
        template_version / report_schema_version: schema versions.
        generated_at: generation timestamp.
        generator_version: generator version.
        source_snapshot: evidence snapshot hash.
        content_hash: SHA-256 of the structured content.
        status: report state at generation.

    """

    report_id: str
    finding_id: str = ""
    template_version: str = "1.0.0"
    report_schema_version: str = "1.0.0"
    generated_at: str = ""
    generator_version: str = "1.0.0"
    source_snapshot: str = ""
    content_hash: str = ""
    status: str = "draft"


@dataclass(slots=True)
class ReportTemplateRecord(TidbEntity):
    """A persisted data-driven report template.

    Attributes:
        template_id: template identifier (envelope ``id`` aliases it).
        kind: template kind.
        template_version: template version.
        title: template title.
        sections: ordered section definitions (JSON-safe).
        template_schema_version: template schema version.
        locale: template locale.

    """

    template_id: str
    kind: str = "pentest"
    template_version: str = "1.0.0"
    title: str = ""
    sections: list[dict[str, object]] = field(default_factory=list)
    template_schema_version: str = "1.0.0"
    locale: str = "en"


@dataclass(slots=True)
class ReportTemplateVersionRecord(TidbEntity):
    """An immutable template version.

    Attributes:
        template_id: owning template.
        version: template version number (envelope ``version``).
        kind: template kind.
        template_json: JSON-safe template definition.
        content_hash: SHA-256 of the template definition.

    """

    template_id: str
    kind: str = "pentest"
    template_json: dict[str, object] = field(default_factory=dict)
    content_hash: str = ""


@dataclass(slots=True)
class ReportClaimRecord(TidbEntity):
    """A persisted report claim.

    Attributes:
        claim_id: claim identifier.
        report_id / finding_id: owning report and finding.
        claim_text: the claim text.
        source_refs: supporting evidence references.
        claim_type: claim type.
        confidence: claim confidence in ``[0, 1]``.
        generated_by: producer.
        verification_state: verification state.
        verification_detail: explainable verification detail.

    """

    claim_id: str
    report_id: str
    finding_id: str = ""
    claim_text: str = ""
    source_refs: list[str] = field(default_factory=list)
    claim_type: str = "vulnerability"
    confidence: float = 0.0
    generated_by: str = "hunterx.reporting"
    verification_state: str = "unsupported"
    verification_detail: str = ""


@dataclass(slots=True)
class ReportQaRecord(TidbEntity):
    """A persisted report QA result.

    Attributes:
        qa_id: QA result identifier.
        report_id: report being checked.
        verdict: overall verdict.
        checks: per-check results (JSON-safe).
        blocked: whether the report is blocked from submission.
        reasons: explainable reasons.
        checked_at: check timestamp.

    """

    qa_id: str
    report_id: str
    verdict: str = "warn"
    checks: list[dict[str, object]] = field(default_factory=list)
    blocked: bool = True
    reasons: list[str] = field(default_factory=list)
    checked_at: str = ""


@dataclass(slots=True)
class ReportEvidenceSnapshotRecord(TidbEntity):
    """A persisted evidence snapshot.

    Attributes:
        snapshot_id: snapshot identifier.
        report_id / finding_id: owning report and finding.
        finding_hash: SHA-256 of the finding snapshot.
        evidence_hash: SHA-256 over the evidence artifact hashes.
        captured_at: capture timestamp.

    """

    snapshot_id: str
    report_id: str = ""
    finding_id: str = ""
    finding_hash: str = ""
    evidence_hash: str = ""
    captured_at: str = ""


@dataclass(slots=True)
class ReportPackageRecord(TidbEntity):
    """A persisted report package.

    Attributes:
        package_id: package identifier.
        report_id / finding_id: owning report and finding.
        version: report version (envelope ``version``).
        document_json: JSON-safe report document (redacted).
        content_hash: SHA-256 of the document JSON.
        status: report state at packaging.
        generated_at: generation timestamp.

    """

    package_id: str
    report_id: str
    finding_id: str = ""
    document_json: dict[str, object] = field(default_factory=dict)
    content_hash: str = ""
    status: str = "draft"
    generated_at: str = ""


@dataclass(slots=True)
class RemediationPlanRecord(TidbEntity):
    """A persisted remediation plan.

    Attributes:
        plan_id: plan identifier.
        finding_id / report_id: owning finding and report.
        root_cause_id: linked root cause.
        plan_json: JSON-safe remediation plan.

    """

    plan_id: str
    finding_id: str = ""
    report_id: str = ""
    root_cause_id: str = ""
    plan_json: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class RetestPlanRecord(TidbEntity):
    """A persisted retest plan.

    Attributes:
        plan_id: plan identifier.
        finding_id / report_id: owning finding and report.
        state: retest lifecycle state.
        plan_json: JSON-safe retest plan.

    """

    plan_id: str
    finding_id: str = ""
    report_id: str = ""
    state: str = "planned"
    plan_json: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ReportSubmissionRecord(TidbEntity):
    """Submission state of a report.

    Attributes:
        submission_id: submission identifier.
        report_id: owning report.
        state: submission state (submitted/reopened/closed/...).
        submitted_at: submission timestamp.
        target: submission target.
        evidence_snapshot_id: evidence snapshot referenced.

    """

    submission_id: str
    report_id: str
    state: str = "submitted"
    submitted_at: str = ""
    target: str = ""
    evidence_snapshot_id: str = ""
