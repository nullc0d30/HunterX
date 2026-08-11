# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability finding orchestration API routes.

Exposes the Sprint 028 application services: create finding, get finding,
list findings, assess evidence, get evidence gaps, get the validation plan,
execute validation, generate a PoC, replay a PoC, assess impact, calculate
confidence, get the confidence explanation, resolve conflicts, deduplicate,
correlate root causes, classify unknown behavior, evaluate report readiness,
finalize report-ready, reject findings and get the complete finding package.
Handlers resolve services from the shared dependency container.
"""

from __future__ import annotations

from typing import Any

from hunterx.api.router import ApiRouter
from hunterx.application.vulnerability_finding import VulnerabilityFindingService


def build_finding_router() -> ApiRouter:
    """Build the ``/findings`` route group."""
    router = ApiRouter(prefix="/findings")

    from hunterx.api.deps import get_container

    def _service() -> VulnerabilityFindingService:
        return get_container().resolve(VulnerabilityFindingService)

    @router.post("", summary="Create an orchestrated finding")
    def create_finding(body: dict[str, Any]) -> dict[str, Any]:
        service = _service()
        return service.create_finding(
            mission_id=str(body.get("mission_id") or ""),
            target_id=str(body.get("target_id") or ""),
            vulnerability_class=str(body.get("vulnerability_class") or "unknown_behavior"),
            title=str(body.get("title") or ""),
            description=str(body.get("description") or ""),
            severity=str(body.get("severity") or "info"),
            tool=str(body.get("tool") or ""),
            asset_id=str(body.get("asset_id") or ""),
            asset=str(body.get("asset") or ""),
            endpoints=tuple(body.get("endpoints") or []),
            parameters=tuple(body.get("parameters") or []),
            observations=body.get("observations"),
            scope=body.get("scope"),
            provenance=str(body.get("provenance") or ""),
        )

    @router.get("", summary="List findings for a mission")
    def list_findings(mission_id: str) -> list[dict[str, Any]]:
        return _service().list_findings(mission_id)

    @router.get("/{finding_id}", summary="Get an orchestrated finding")
    def get_finding(finding_id: str) -> dict[str, Any]:
        return _service().get_finding(finding_id)

    @router.post("/{finding_id}/evidence/assess", summary="Assess evidence requirements and gaps")
    def assess_evidence(finding_id: str) -> dict[str, Any]:
        return _service().assess_evidence(finding_id)

    @router.get("/{finding_id}/evidence/gaps", summary="Get evidence gaps")
    def evidence_gaps(finding_id: str) -> list[dict[str, Any]]:
        return _service().get_evidence_gaps(finding_id)

    @router.get("/{finding_id}/validation-plan", summary="Get the ranked validation strategy plan")
    def validation_plan(finding_id: str) -> dict[str, Any]:
        return _service().get_validation_plan(finding_id)

    @router.post("/{finding_id}/validate", summary="Execute validation")
    def validate_finding(finding_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().validate_finding(finding_id, strategy_id=body.get("strategy_id"))

    @router.post("/{finding_id}/poc", summary="Generate a minimal, sanitized PoC")
    def generate_poc(finding_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().generate_poc(
            finding_id,
            poc_format=str(body.get("poc_format") or "http_request"),
            reproduction=body.get("reproduction"),
        )

    @router.post("/{finding_id}/poc/{poc_id}/replay", summary="Replay a PoC under controlled conditions")
    def replay_poc(finding_id: str, poc_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().replay_poc(finding_id, poc_id, outcome=body.get("outcome"))

    @router.post("/{finding_id}/impact", summary="Assess evidence-backed impact")
    def assess_impact(finding_id: str) -> dict[str, Any]:
        return _service().assess_impact(finding_id)

    @router.post("/{finding_id}/confidence", summary="Calculate the evidence-driven confidence")
    def calculate_confidence(finding_id: str) -> dict[str, Any]:
        return _service().calculate_confidence(finding_id)

    @router.get("/{finding_id}/confidence/explain", summary="Get the confidence explanation")
    def confidence_explanation(finding_id: str) -> dict[str, Any]:
        return _service().get_confidence_explanation(finding_id)

    @router.post("/{finding_id}/conflicts/{conflict_id}/resolve", summary="Resolve an evidence conflict")
    def resolve_conflict(finding_id: str, conflict_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().resolve_conflict(
            finding_id,
            conflict_id,
            resolution=str(body.get("resolution") or "resolved"),
            reason=str(body.get("reason") or ""),
        )

    @router.post("/{finding_id}/deduplicate", summary="Correlate the finding against existing findings")
    def deduplicate_finding(finding_id: str) -> dict[str, Any]:
        return _service().deduplicate_finding(finding_id)

    @router.post("/{finding_id}/root-cause", summary="Correlate a shared root cause")
    def correlate_root_cause(finding_id: str) -> dict[str, Any]:
        return _service().correlate_root_cause(finding_id)

    @router.post("/{finding_id}/unknown", summary="Classify an unknown-behavior finding")
    def classify_unknown(finding_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().classify_unknown(
            finding_id,
            known_signatures=body.get("known_signatures"),
            security_relevant=body.get("security_relevant"),
            reproducible=bool(body.get("reproducible", False)),
        )

    @router.get("/{finding_id}/report-readiness", summary="Evaluate the report-readiness checklist")
    def report_readiness(finding_id: str) -> dict[str, Any]:
        return _service().get_report_readiness(finding_id)

    @router.post("/{finding_id}/report-ready", summary="Finalize the finding as REPORT_READY")
    def finalize_report_ready(finding_id: str) -> dict[str, Any]:
        return _service().finalize_report_ready(finding_id)

    @router.post("/{finding_id}/reject", summary="Reject, disprove or mark a finding out of scope")
    def reject_finding(finding_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().reject_finding(
            finding_id,
            reason=str(body.get("reason") or ""),
            state=str(body.get("state") or "rejected"),
        )

    @router.get("/{finding_id}/package", summary="Get the complete finding package")
    def finding_package(finding_id: str) -> dict[str, Any]:
        return _service().get_finding_package(finding_id)

    return router
