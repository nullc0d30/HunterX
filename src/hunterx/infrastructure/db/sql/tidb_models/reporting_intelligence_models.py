# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB professional reporting entities.

System-of-record tables for the Sprint 029 professional finding intelligence
& reporting capability: report metadata, report versions, templates and
template versions, claim records, QA results, evidence snapshots, report
packages, remediation plans, retest plans and submission state.

Security boundary: every table stores canonical, redacted report data only —
never credentials, never exploit payloads, never out-of-scope request
material. The envelope ``version`` column carries the report/template version
and the envelope ``created_at`` carries creation time.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class ReportRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportRecord`."""

    __tablename__ = "tidb_report_records"

    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    mission_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    target_id: Mapped[str] = mapped_column(String(512), nullable=False, default="", index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    template: Mapped[str] = mapped_column(String(48), nullable=False, default="pentest", index=True)
    template_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    report_schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft", index=True)
    generator_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    __table_args__ = (
        Index("ix_tidb_report_records_finding_status", "finding_id", "status"),
        Index("ix_tidb_report_records_mission_status", "mission_id", "status"),
    )


class ReportVersionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportVersionRecord`."""

    __tablename__ = "tidb_report_versions"

    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    template_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    report_schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    generated_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    generator_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    source_snapshot: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    __table_args__ = (
        Index("ix_tidb_report_versions_report_version", "report_id", "version"),
    )


class ReportTemplateRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportTemplateRecord`."""

    __tablename__ = "tidb_report_templates"

    template_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(48), nullable=False, default="pentest", index=True)
    template_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    sections: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    template_schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    locale: Mapped[str] = mapped_column(String(8), nullable=False, default="en")


class ReportTemplateVersionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportTemplateVersionRecord`."""

    __tablename__ = "tidb_report_template_versions"

    template_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(48), nullable=False, default="pentest", index=True)
    template_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class ReportClaimRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportClaimRecord`."""

    __tablename__ = "tidb_report_claims"

    claim_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    claim_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    claim_type: Mapped[str] = mapped_column(String(48), nullable=False, default="vulnerability", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    generated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="hunterx.reporting")
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unsupported", index=True)
    verification_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    __table_args__ = (
        Index("ix_tidb_report_claims_report_state", "report_id", "verification_state"),
    )


class ReportQaRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportQaRecord`."""

    __tablename__ = "tidb_report_qa_results"

    qa_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False, default="warn", index=True)
    checks: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    checked_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class ReportEvidenceSnapshotRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportEvidenceSnapshotRecord`."""

    __tablename__ = "tidb_report_evidence_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    captured_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class ReportPackageRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportPackageRecord`."""

    __tablename__ = "tidb_report_packages"

    package_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    document_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft", index=True)
    generated_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class RemediationPlanRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.RemediationPlanRecord`."""

    __tablename__ = "tidb_report_remediation_plans"

    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    report_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    root_cause_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
    plan_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class RetestPlanRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.RetestPlanRecord`."""

    __tablename__ = "tidb_report_retest_plans"

    plan_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    report_id: Mapped[str] = mapped_column(String(26), nullable=False, default="", index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="planned", index=True)
    plan_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class ReportSubmissionRecordModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.reporting_intelligence.ReportSubmissionRecord`."""

    __tablename__ = "tidb_report_submissions"

    submission_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="submitted", index=True)
    submitted_at: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    evidence_snapshot_id: Mapped[str] = mapped_column(String(26), nullable=False, default="")
