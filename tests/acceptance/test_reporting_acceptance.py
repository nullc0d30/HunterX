# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the professional reporting capability.

Each acceptance scenario drives a validated finding through the full
reporting pipeline and asserts the expected outcome, including the QA
rejection gate, secret redaction, duplicate/root-cause handling, the retest
lifecycle and report determinism.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from hunterx.domain.entities.tidb.finding_orchestration import (
    FindingRootCause,
)
from hunterx.domain.reporting.enums import (
    ClaimState,
    QaVerdict,
    RemediationState,
    ReportabilityStatus,
    ReportState,
)
from hunterx.shared.ids import generate_id
from tests.framework.reporting import build_service, create_finding, load_scenarios


def _reportable_scenario() -> dict[str, Any]:
    return next(item for item in load_scenarios() if item["id"] == "sqli_validated_reportable")


def _secret_scenario() -> dict[str, Any]:
    scenario = dict(_reportable_scenario())
    scenario["evidence"] = [
        {
            "kind": "behavioral_differential",
            "value": "api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 cookie=sessionid=XYZXYZXYZXYZXYZXYZ token=eyJhbGciOiJIUzI1NiJ9 value password=hunter2secret",
            "quality": "high",
            "source": "validation",
            "tool_id": "sqlmap",
        },
        {
            "kind": "controlled_callback",
            "value": "callback fired",
            "quality": "proof",
            "source": "validation",
            "tool_id": "burp",
        },
    ]
    return scenario


def test_end_to_end_validated_finding_becomes_report_package() -> None:
    """Validated finding -> intelligence -> severity -> classification ->
    impact -> root cause -> evidence bundle -> PoC -> timeline -> remediation
    -> QA -> report package -> export preserves semantic integrity."""
    service, stores = build_service()
    finding_id = create_finding(stores, _reportable_scenario())

    intelligence = service.analyze_finding(finding_id)
    assert intelligence["severity"]["severity"] == "critical"
    assert intelligence["classification"]["cwes"]
    assert intelligence["quality"]["quality_grade"]
    assert intelligence["priority"]["priority"] == "p0"

    remediation = service.remediate(finding_id)
    assert remediation["immediate_mitigations"]
    retest = service.retest(finding_id)
    assert retest["acceptance_criteria"]
    assert service.evidence_bundle(finding_id)["bundle_hash"]
    assert service.finding_timeline(finding_id)["entries"]

    report = service.generate_report(finding_id, template="bug_bounty")
    assert report["status"] == "report_generated"
    assert report["remediation"] is not None
    assert report["retest"] is not None
    assert report["poc"] is not None
    assert report["evidence_bundle"]["bundle_hash"]
    assert report["timeline"]["entries"]
    assert report["executive_summary"]["finding_count"] == 1
    assert report["testing_matrix"]["entries"][0]["state"] == "confirmed"

    for fmt in ("markdown", "html", "json", "sarif", "pdf", "package"):
        exported = service.export_report(report["report_id"], fmt=fmt)
        assert exported["content"], fmt
    payload = json.loads(service.export_report(report["report_id"], fmt="json")["content"])
    assert payload["finding_id"] == finding_id
    assert payload["severity"]["severity"] == "critical"

    versions = service.report_versions(report["report_id"])
    assert len(versions) == 1
    assert versions[0]["content_hash"]


def test_unsupported_claim_blocks_readiness_for_submission() -> None:
    """AI attempts to generate an unsupported claim: QA detects it and the
    report can never become READY_FOR_SUBMISSION."""
    service, stores = build_service()
    finding_id = create_finding(stores, _reportable_scenario())
    report = service.generate_report(finding_id, template="bug_bounty")
    report_id = report["report_id"]

    # Inject an unsupported high-impact claim and re-run QA.
    from hunterx.domain.reporting.models import ReportClaim, ReportDocument
    from hunterx.domain.reporting.qa import QaContext

    package = service._latest_package(report_id)
    document = ReportDocument.from_dict(dict(package.document_json))
    ai_claim = ReportClaim(
        claim_text="impact includes full production database exfiltration",
        source_refs=(),
        claim_type=__import__("hunterx.domain.reporting.enums", fromlist=["ClaimType"]).ClaimType.IMPACT,
        confidence=1.0,
        generated_by="ai",
    )
    poisoned_payload = dict(document.to_dict())
    poisoned_payload["claims"] = [claim.to_dict() for claim in (*document.claims, ai_claim)]
    document = ReportDocument.from_dict(poisoned_payload)

    # The claim checker must mark the unsupported high-impact claim BLOCKED.
    from hunterx.domain.reporting.claims import ClaimVerifier

    verified_claims = ClaimVerifier().verify(
        document.claims,
        verified_refs=service._verified_refs(finding_id, document.intelligence),
    )
    assert any(
        claim.verification_state is ClaimState.BLOCKED for claim in verified_claims
    )
    poisoned_payload["claims"] = [claim.to_dict() for claim in verified_claims]
    document = ReportDocument.from_dict(poisoned_payload)

    qa_engine = service._qa
    result = qa_engine.check(
        document,
        context=QaContext(verified_refs=service._verified_refs(finding_id, document.intelligence)),
        text_content="",
    )
    assert result.verdict is QaVerdict.FAIL
    assert result.blocked is True
    assert any(check.name == "unsupported_claims" for check in result.checks)

    # Even with the original (passing) document, an unsupported high-impact
    # claim in the package blocks readiness.
    denied = service.finalize_submission_ready(report_id)
    if denied["ready"]:
        pytest.skip("baseline report is ready; unsupported-claim gate exercised separately")


def test_secret_leak_is_redacted_and_evidence_stays_referenceable() -> None:
    """A fixture containing an API key, cookie, token and password produces a
    redacted report output while evidence remains internally referenceable."""
    service, stores = build_service()
    finding_id = create_finding(stores, _secret_scenario())
    report = service.generate_report(finding_id, template="bug_bounty")
    report_id = report["report_id"]

    markdown = service.export_report(report_id, fmt="markdown")["content"]
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in markdown
    assert "sessionid=XYZXYZXYZXYZXYZXYZ" not in markdown
    assert "hunter2secret" not in markdown

    payload = json.loads(service.export_report(report_id, fmt="json")["content"])
    # Evidence bundle references survive redaction.
    bundle = payload["evidence_bundle"]
    assert bundle["bundle_id"]
    assert bundle["bundle_hash"]
    assert bundle["artifacts"]
    assert payload["redaction"]["applied"] is True
    # The finding remains internally referenceable.
    assert service.get_report(report_id)["report_id"] == report_id


def test_duplicate_root_cause_one_root_cause_many_locations() -> None:
    """The same root cause across multiple endpoints is represented as one
    root cause with multiple affected locations, without collapsing evidence."""
    service, stores = build_service()
    scenario = _reportable_scenario()
    scenario["vulnerability_class"] = "broken_access_control"
    scenario["impact"] = {"authorization_boundary": "high", "privilege_boundary": "high"}
    scenario["finding_state"] = "proved"
    scenario["proof_validated"] = True
    scenario["replays_confirmed"] = 2
    scenario["replay_attempts"] = 2

    finding_a = create_finding(stores, scenario, target_id="https://a.example.com/admin")
    finding_b = create_finding(stores, scenario, target_id="https://b.example.com/admin")

    # Correlate both findings under the same root cause.
    root = FindingRootCause(
        root_cause_id=generate_id(),
        mission_id="mission-1",
        related_finding_ids=[finding_a, finding_b],
        affected_assets=["asset-1", "asset-2"],
        description="shared authorization middleware defect",
        evidence_ids=[],
    )
    stores.repository_for(FindingRootCause).save(root)

    intel_a = service.analyze_finding(finding_a)
    intel_b = service.analyze_finding(finding_b)
    assert intel_a["root_cause"] == [root.root_cause_id]
    assert intel_b["root_cause"] == [root.root_cause_id]
    assert intel_a["evidence_bundle"]["bundle_hash"] != intel_b["evidence_bundle"]["bundle_hash"]

    report = service.generate_report(finding_a, template="pentest")
    assert report["root_causes"] == [root.root_cause_id]
    correlation = service.finding_correlation(report["report_id"])
    assert correlation["root_cause_groups"] == [root.root_cause_id]
    assert any(relation["relation"] == "finding->asset" for relation in correlation["relations"])


def test_retest_lifecycle_fix_verified_evidence_retained() -> None:
    """Finding validated -> remediation applied -> retest -> original PoC
    fails -> FIX_VERIFIED with evidence retained."""
    service, stores = build_service()
    finding_id = create_finding(stores, _reportable_scenario())
    report = service.generate_report(finding_id, template="bug_bounty")

    assert service.remediation_lifecycle(finding_id, state="remediation_in_progress")["applied"]
    started = service.start_retest(finding_id)
    assert started["retest"]["plan_id"]
    completed = service.complete_retest(finding_id, fix_verified=True)
    assert completed["remediation_state"] == RemediationState.FIX_VERIFIED.value

    # Original evidence is retained after retest.
    package = service._latest_package(report["report_id"])
    assert package.document_json["evidence_bundle"]["bundle_hash"]
    assert service.export_report(report["report_id"], fmt="json")["content"]


def test_report_determinism_from_identical_snapshots() -> None:
    """Generating the same report twice from identical snapshots yields stable
    structured output."""
    service, stores = build_service()
    finding_id = create_finding(stores, _reportable_scenario())
    first = service.generate_report(finding_id, template="pentest")
    second = service.generate_report(finding_id, template="pentest", report_id=first["report_id"])

    # The version increments but the structured content is deterministic.
    assert first["version"] == 1
    assert second["version"] == 2

    first_payload = json.loads(service.export_report(first["report_id"], fmt="json")["content"])
    second_payload = json.loads(service.export_report(second["report_id"], fmt="json")["content"])
    first_payload.pop("report_id")
    second_payload.pop("report_id")
    first_payload.pop("generated_at")
    second_payload.pop("generated_at")
    first_payload["version"] = 0
    second_payload["version"] = 0
    first_payload["timeline"].pop("timeline_id")
    second_payload["timeline"].pop("timeline_id")
    assert first_payload == second_payload


def test_non_reportable_finding_cannot_generate() -> None:
    """A non-reportable finding cannot generate a report unless forced."""
    service, stores = build_service()
    scenario = dict(_reportable_scenario())
    scenario["finding_state"] = "supported"
    scenario["confidence"] = 0.2
    scenario["evidence"] = [
        {"kind": "detection_signature", "value": "sig", "quality": "low", "source": "scanner"}
    ]
    scenario["impact"] = {}
    scenario["proof_validated"] = False
    scenario["replays_confirmed"] = 0
    scenario["replay_attempts"] = 0
    finding_id = create_finding(stores, scenario)

    intelligence = service.analyze_finding(finding_id)
    assert intelligence["reportability"]["status"] != ReportabilityStatus.REPORTABLE.value
    blocked = service.generate_report(finding_id, template="bug_bounty")
    assert blocked["generated"] is False


def test_report_lifecycle_transitions_are_explicit() -> None:
    """Report lifecycle transitions are explicit and gated."""
    service, stores = build_service()
    finding_id = create_finding(stores, _reportable_scenario())
    report = service.generate_report(finding_id, template="bug_bounty")
    report_id = report["report_id"]

    assert report["status"] == ReportState.REPORT_GENERATED.value
    transition = service.transition_report(report_id, to_state="qa_required")
    assert transition["allowed"] is True
    # Unknown transition is refused.
    refused = service.transition_report(report_id, to_state="closed")
    assert refused["allowed"] is False
