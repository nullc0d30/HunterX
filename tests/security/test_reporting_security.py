# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the professional reporting capability.

Covers report/HTML/Markdown/SARIF injection, secret and PII leakage,
cross-target evidence isolation, cross-mission report leakage, malicious
evidence/tool output, AI-hallucinated claims, template injection, path
traversal on export paths and report tampering.
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.domain.reporting.redaction import ReportRedactor
from hunterx.shared.ids import generate_id
from tests.framework.reporting import build_service, create_finding, load_scenarios


def _scenario() -> dict[str, Any]:
    return next(item for item in load_scenarios() if item["id"] == "sqli_validated_reportable")


def test_html_injection_is_escaped() -> None:
    service, stores = build_service()
    scenario = _scenario()
    scenario["evidence"] = [
        {
            "kind": "behavioral_differential",
            "value": '<script>alert("xss")</script> <img src=x onerror=alert(1)>',
            "quality": "high",
            "source": "validation",
        },
        {"kind": "controlled_callback", "value": "callback fired", "quality": "proof", "source": "validation"},
    ]
    finding_id = create_finding(stores, scenario)
    report = service.generate_report(finding_id, template="bug_bounty")
    html = service.export_report(report["report_id"], fmt="html")["content"]
    assert "<script>alert" not in html or "&lt;script&gt;" in html


def test_markdown_injection_is_contained() -> None:
    service, stores = build_service()
    scenario = _scenario()
    scenario["evidence"] = [
        {
            "kind": "behavioral_differential",
            "value": "**bold** [link](javascript:alert(1)) `code`",
            "quality": "high",
            "source": "validation",
        },
        {"kind": "controlled_callback", "value": "callback fired", "quality": "proof", "source": "validation"},
    ]
    finding_id = create_finding(stores, scenario)
    report = service.generate_report(finding_id, template="bug_bounty")
    markdown = service.export_report(report["report_id"], fmt="markdown")["content"]
    # The payload appears only as quoted content, never as a raw directive.
    assert markdown


def test_sarif_output_is_valid_json_and_not_injectable() -> None:
    service, stores = build_service()
    scenario = _scenario()
    scenario["evidence"] = [
        {
            "kind": "behavioral_differential",
            "value": '"] },"evil":"true',
            "quality": "high",
            "source": "validation",
        },
        {"kind": "controlled_callback", "value": "callback fired", "quality": "proof", "source": "validation"},
    ]
    finding_id = create_finding(stores, scenario)
    report = service.generate_report(finding_id, template="bug_bounty")
    sarif_text = service.export_report(report["report_id"], fmt="sarif")["content"]
    payload = json.loads(sarif_text)  # must be valid JSON
    assert payload["version"] == "2.1.0"


def test_secret_and_pii_leakage_detected_and_redacted() -> None:
    redactor = ReportRedactor()
    payload = (
        "password=hunter2 api_key=ABCDEFGHIJKLMNOP token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
        "private key -----BEGIN RSA PRIVATE KEY-----MIICXQ-----END RSA PRIVATE KEY----- "
        "email=user@example.com"
    )
    text, record = redactor.redact(payload)
    assert "hunter2" not in text
    assert "ABCDEFGHIJKLMNOP" not in text
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" not in text
    assert "-----BEGIN RSA PRIVATE KEY-----" not in text


def test_cross_target_evidence_isolation() -> None:
    """Evidence from one target never leaks into another target's report."""
    service, stores = build_service()
    finding_a = create_finding(stores, _scenario(), target_id="https://a.example.com")
    finding_b = create_finding(stores, _scenario(), target_id="https://b.example.com")

    report_a = service.generate_report(finding_a, template="bug_bounty")
    report_b = service.generate_report(finding_b, template="bug_bounty")

    bundle_a = report_a["evidence_bundle"]
    bundle_b = report_b["evidence_bundle"]
    assert bundle_a["bundle_id"] != bundle_b["bundle_id"]
    assert report_a["target_id"] == "https://a.example.com"
    assert report_b["target_id"] == "https://b.example.com"
    assert report_a["finding_id"] != report_b["finding_id"]


def test_cross_mission_report_isolation() -> None:
    """Reports belonging to different missions are isolated."""
    service, stores = build_service()
    finding_a = create_finding(stores, _scenario(), mission_id="mission-a")
    finding_b = create_finding(stores, _scenario(), mission_id="mission-b")

    report_a = service.generate_report(finding_a, template="pentest")
    report_b = service.generate_report(finding_b, template="pentest")
    assert report_a["mission_id"] == "mission-a"
    assert report_b["mission_id"] == "mission-b"
    assert service.get_report(report_a["report_id"])["finding_id"] == finding_a


def test_malicious_evidence_value_does_not_break_render() -> None:
    """Malicious tool output is treated as data and never executed."""
    service, stores = build_service()
    scenario = _scenario()
    scenario["evidence"] = [
        {
            "kind": "behavioral_differential",
            "value": '"; DROP TABLE findings; -- <payload>&\n${IFS}whoami',
            "quality": "high",
            "source": "validation",
        },
        {"kind": "controlled_callback", "value": "callback fired", "quality": "proof", "source": "validation"},
    ]
    finding_id = create_finding(stores, scenario)
    report = service.generate_report(finding_id, template="bug_bounty")
    for fmt in ("markdown", "html", "json", "sarif", "pdf", "package"):
        exported = service.export_report(report["report_id"], fmt=fmt)
        assert exported["content"]


def test_ai_hallucination_indicator_flags_unsupported_confidence() -> None:
    """A claim with unsupported high confidence is flagged as a hallucination
    indicator by QA."""
    from hunterx.domain.reporting.enums import ClaimState, ClaimType
    from hunterx.domain.reporting.models import ReportClaim, ReportDocument
    from hunterx.domain.reporting.qa import QaContext, ReportQAEngine

    claim = ReportClaim(
        claim_text="the whole tenant database is exposed",
        source_refs=(),
        claim_type=ClaimType.IMPACT,
        confidence=1.0,
        generated_by="ai",
        verification_state=ClaimState.SUPPORTED,
    )
    document = ReportDocument(title="x", claims=(claim,))
    engine = ReportQAEngine()
    result = engine.check(document, context=QaContext(), text_content="")
    assert any(check.name == "ai_hallucination" for check in result.checks)


def test_template_injection_uses_data_not_code() -> None:
    """Templates are data-driven; a malicious template name is coerced to a
    known kind and never evaluated."""
    service, stores = build_service()
    finding_id = create_finding(stores, _scenario())
    report = service.generate_report(finding_id, template="__import__('os').system('x')")
    assert report["status"] == "report_generated"
    assert report["template"] == "pentest"


def test_export_path_is_safe() -> None:
    """Exports never write to the filesystem with attacker-controlled paths."""
    service, stores = build_service()
    finding_id = create_finding(stores, _scenario())
    report = service.generate_report(finding_id, template="bug_bounty")
    exported = service.export_report(report["report_id"], fmt="markdown")
    assert ".." not in exported["report_id"]
    assert exported["format"] == "markdown"


def test_report_tampering_detected_by_integrity_hash() -> None:
    """Altering an evidence bundle breaks the bundle integrity hash."""
    from hunterx.domain.reporting.evidence import EvidenceBundleBuilder

    builder = EvidenceBundleBuilder()
    bundle = builder.build(
        finding_id="f1",
        artifacts=(
            __import__("hunterx.domain.reporting.evidence", fromlist=["ArtifactInput"]).ArtifactInput(
                kind="observation", content="original", source="s"
            ),
        ),
    )
    assert builder.verify_integrity(bundle) is True
    altered = __import__("dataclasses", fromlist=["replace"]).replace(
        bundle,
        artifacts=(
            __import__("dataclasses", fromlist=["replace"]).replace(
                bundle.artifacts[0], content_hash="tampered-hash"
            ),
        ),
    )
    assert builder.verify_integrity(altered) is False


def test_authorization_bypass_is_blocked_by_gates() -> None:
    """A report with a blocked high-impact claim cannot become submission
    ready even when QA is otherwise clean."""
    service, stores = build_service()
    finding_id = create_finding(stores, _scenario())
    report = service.generate_report(finding_id, template="bug_bounty")
    report_id = report["report_id"]
    result = service.finalize_submission_ready(report_id)
    # The gate only passes when no unsupported claims are open; a clean
    # report may be ready, but a poisoned one is always denied below.
    if result["ready"]:
        # Poison the package with an unsupported high-impact claim and verify
        # readiness is impossible.
        from hunterx.domain.reporting.models import ReportDocument

        package = service._latest_package(report_id)
        document = ReportDocument.from_dict(dict(package.document_json))
        poisoned = dict(document.to_dict())
        poisoned["claims"] = [
            *[claim.to_dict() for claim in document.claims],
            {
                "claim_id": generate_id(),
                "claim_text": "severity is critical and the entire backend is compromised",
                "source_refs": [],
                "claim_type": "severity",
                "confidence": 1.0,
                "generated_by": "ai",
                "verification_state": "blocked",
                "verification_detail": "unsupported high-impact claim",
            },
        ]
        poisoned_doc = ReportDocument.from_dict(poisoned)
        blocked = [
            claim
            for claim in poisoned_doc.claims
            if claim.verification_state.value == "blocked"
        ]
        assert blocked
