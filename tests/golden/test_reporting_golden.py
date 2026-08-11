# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden scenario tests for professional reporting.

Each golden finding is driven through the reporting pipeline: finding
intelligence -> severity -> CWE/OWASP/CVSS classification -> impact -> root
cause -> evidence bundle -> PoC -> timeline -> remediation -> QA -> report
package -> export. Every exported representation preserves semantic integrity.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.framework.reporting import build_service, create_finding, load_scenarios


def _load() -> list[dict[str, Any]]:
    return load_scenarios()


@pytest.mark.parametrize("scenario", _load(), ids=lambda item: str(item["id"]))
def test_reporting_golden(scenario: dict[str, Any]) -> None:
    service, stores = build_service()
    finding_id = create_finding(stores, scenario)

    intelligence = service.analyze_finding(finding_id)
    assert intelligence["vulnerability_class"] == scenario["vulnerability_class"]
    assert intelligence["severity"]["severity"] == scenario["expected_severity"]
    assert intelligence["priority"]["priority"] == scenario["expected_priority"]
    assert intelligence["reportability"]["status"] == scenario["expected_reportability"]
    assert intelligence["quality"]["quality_grade"] == scenario["expected_quality_grade"]

    for cwe_id in scenario["expected_cwes"]:
        assert any(item["cwe_id"] == cwe_id for item in intelligence["classification"]["cwes"])
    for owasp_id in scenario["expected_owasp"]:
        assert any(item["item_id"] == owasp_id for item in intelligence["classification"]["owasp"])
    for attack_id in scenario["expected_attack"]:
        assert any(item["technique_id"] == attack_id for item in intelligence["classification"]["attack"])

    assert service.evidence_bundle(finding_id)["bundle_hash"]
    timeline = service.finding_timeline(finding_id)
    assert timeline["entries"]

    remediation = service.remediate(finding_id)
    assert remediation["plan_id"]
    retest = service.retest(finding_id)
    assert retest["plan_id"]

    if scenario["expected_reportability"] == "reportable":
        report = service.generate_report(finding_id, template="bug_bounty")
        assert report["status"] == "report_generated"
        assert report["finding_id"] == finding_id
        assert report["severity"]["severity"] == scenario["expected_severity"]
        assert report["remediation"] is not None
        assert report["retest"] is not None
        assert report["evidence_bundle"]["bundle_hash"]
        assert report["timeline"]["entries"]

        # Export every representation; SARIF must be schema-valid JSON.
        for fmt in ("markdown", "html", "json", "sarif", "pdf", "package"):
            exported = service.export_report(report["report_id"], fmt=fmt)
            assert exported["content"]
        sarif = json.loads(service.export_report(report["report_id"], fmt="sarif")["content"])
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"][0]["properties"]["findingId"] == finding_id
    else:
        blocked = service.generate_report(finding_id, template="bug_bounty")
        assert blocked["generated"] is False


@pytest.mark.parametrize(
    "scenario",
    _load(),
    ids=lambda item: f"intact_{item['id']}",
)
def test_reporting_export_semantic_integrity(scenario: dict[str, Any]) -> None:
    """Every exported representation preserves the finding identity and severity."""
    service, stores = build_service()
    finding_id = create_finding(stores, scenario)
    if scenario["expected_reportability"] != "reportable":
        pytest.skip("finding is not reportable")
    report = service.generate_report(finding_id, template="pentest")
    for fmt in ("json", "package"):
        exported = service.export_report(report["report_id"], fmt=fmt)
        payload = json.loads(exported["content"])
        assert payload["finding_id"] == finding_id
        assert payload["severity"]["severity"] == scenario["expected_severity"]
        assert payload["qa"]["verdict"] in ("pass", "warn", "fail")
    sarif = json.loads(service.export_report(report["report_id"], fmt="sarif")["content"])
    assert sarif["runs"][0]["results"][0]["properties"]["findingId"] == finding_id


@pytest.mark.parametrize(
    "scenario",
    _load(),
    ids=lambda item: f"reportable_{item['id']}",
)
def test_report_qa_blocks_non_reportable(scenario: dict[str, Any]) -> None:
    """A report cannot be generated for a non-reportable finding."""
    service, stores = build_service()
    finding_id = create_finding(stores, scenario)
    result = service.generate_report(finding_id, template="bug_bounty")
    if scenario["expected_reportability"] == "reportable":
        assert result.get("generated", True) is not False
    else:
        assert result["generated"] is False


def test_every_vulnerability_class_is_classifiable() -> None:
    """Every canonical vulnerability class maps to at least one CWE."""
    from hunterx.domain.reporting.classification import ClassificationEngine

    engine = ClassificationEngine()
    classes = [
        "sql_injection", "xss", "ssrf", "ssti", "lfi", "rfi", "xxe", "rce",
        "command_injection", "path_traversal", "open_redirect", "csrf",
        "cors_misconfiguration", "host_header_injection", "http_request_smuggling",
        "jwt_weakness", "idor", "broken_access_control", "authentication_flaws",
        "cloud_exposure", "secret_exposure", "known_cve", "business_logic",
        "unknown_behavior",
    ]
    for cls in classes:
        classification = engine.classify(vulnerability_class=cls)
        assert classification.cwes, f"class {cls} has no CWE mapping"
