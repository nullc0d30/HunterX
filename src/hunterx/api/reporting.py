# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Professional reporting API routes.

Exposes the Sprint 029 application services: analyze a finding, classify it,
assess severity/quality/priority/reportability, build evidence bundles and
timelines, produce remediation and retest plans, create and generate
professional reports, run report QA, finalize submission readiness, export
reports (Markdown / HTML / JSON / SARIF / PDF / package), retrieve report
versions and build executive summaries. Handlers resolve services from the
shared dependency container.
"""

from __future__ import annotations

from typing import Any

from hunterx.api.router import ApiRouter
from hunterx.application.professional_reporting import ProfessionalReportingService


def build_reporting_router() -> ApiRouter:
    """Build the ``/reports`` route group."""
    router = ApiRouter(prefix="/reports")

    from hunterx.api.deps import get_container

    def _service() -> ProfessionalReportingService:
        return get_container().resolve(ProfessionalReportingService)

    @router.post("/findings/{finding_id}/analyze", summary="Build the finding-intelligence aggregate")
    def analyze_finding(finding_id: str) -> dict[str, Any]:
        return _service().analyze_finding(finding_id)

    @router.post("/findings/{finding_id}/classify", summary="Classify a finding (CWE/OWASP/ATT&CK/CVSS)")
    def classify_finding(finding_id: str) -> dict[str, Any]:
        return _service().classify_finding(finding_id)

    @router.post("/findings/{finding_id}/severity", summary="Assess the evidence-backed severity")
    def assess_severity(finding_id: str) -> dict[str, Any]:
        return _service().assess_severity(finding_id)

    @router.post("/findings/{finding_id}/quality", summary="Assess the finding report quality")
    def assess_quality(finding_id: str) -> dict[str, Any]:
        return _service().assess_quality(finding_id)

    @router.post("/findings/{finding_id}/priority", summary="Assess the remediation priority")
    def assess_priority(finding_id: str) -> dict[str, Any]:
        return _service().assess_priority(finding_id)

    @router.post("/findings/{finding_id}/reportability", summary="Assess whether a finding is reportable")
    def assess_reportability(finding_id: str) -> dict[str, Any]:
        return _service().assess_reportability(finding_id)

    @router.post("/findings/{finding_id}/remediation", summary="Build a remediation plan")
    def remediate(finding_id: str) -> dict[str, Any]:
        return _service().remediate(finding_id)

    @router.post("/findings/{finding_id}/retest", summary="Build a retest plan")
    def retest(finding_id: str) -> dict[str, Any]:
        return _service().retest(finding_id)

    @router.get("/findings/{finding_id}/evidence", summary="Get the evidence bundle")
    def evidence_bundle(finding_id: str) -> dict[str, Any]:
        return _service().evidence_bundle(finding_id)

    @router.get("/findings/{finding_id}/timeline", summary="Get the finding timeline")
    def finding_timeline(finding_id: str) -> dict[str, Any]:
        return _service().finding_timeline(finding_id)

    @router.get("/findings/{finding_id}", summary="List reports for a finding")
    def list_reports(finding_id: str) -> list[dict[str, Any]]:
        return _service().list_reports(finding_id)

    @router.post("/findings/{finding_id}/generate", summary="Generate a professional report package")
    def generate_report(finding_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().generate_report(
            finding_id,
            template=str(body.get("template") or "pentest"),
            report_id=str(body.get("report_id") or ""),
            force=bool(body.get("force", False)),
        )

    @router.post("/findings/{finding_id}/report", summary="Create a report draft")
    def create_report(finding_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().create_report(finding_id, template=str(body.get("template") or "pentest"))

    @router.get("/{report_id}", summary="Get a report and its latest package")
    def get_report(report_id: str) -> dict[str, Any]:
        return _service().get_report(report_id)

    @router.get("/{report_id}/versions", summary="Get the immutable report versions")
    def report_versions(report_id: str) -> list[dict[str, Any]]:
        return _service().report_versions(report_id)

    @router.post("/{report_id}/qa", summary="Run report QA validation")
    def qa_report(report_id: str) -> dict[str, Any]:
        return _service().qa_report(report_id)

    @router.post("/{report_id}/finalize", summary="Finalize the report as READY_FOR_SUBMISSION")
    def finalize(report_id: str) -> dict[str, Any]:
        return _service().finalize_submission_ready(report_id)

    @router.post("/{report_id}/transition", summary="Transition the report lifecycle state")
    def transition(report_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().transition_report(report_id, to_state=str(body.get("to_state") or ""))

    @router.get("/{report_id}/export", summary="Export a report into a format")
    def export(report_id: str, fmt: str = "markdown") -> dict[str, Any]:
        return _service().export_report(report_id, fmt=fmt)

    @router.get("/{report_id}/export/sarif", summary="Export a report as SARIF")
    def export_sarif(report_id: str) -> dict[str, Any]:
        return _service().export_sarif(report_id)

    @router.get("/{report_id}/executive-summary", summary="Get the executive summary")
    def executive_summary(report_id: str) -> dict[str, Any]:
        return _service().executive_summary(report_id)

    @router.get("/{report_id}/correlation", summary="Get the cross-finding correlation report")
    def finding_correlation(report_id: str) -> dict[str, Any]:
        return _service().finding_correlation(report_id)

    @router.get("/templates/{template}", summary="Get a report template")
    def report_template(template: str) -> dict[str, Any]:
        return _service().report_template(template)

    return router
