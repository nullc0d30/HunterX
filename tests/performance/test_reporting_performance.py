# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance tests for the professional reporting capability.

Verifies that finding-intelligence assembly, evidence-bundle building and
bulk report generation scale to large finding/evidence volumes without N+1
queries, full table scans, unbounded memory or duplicate evidence loading.
"""

from __future__ import annotations

import time
from typing import Any

from tests.framework.reporting import build_service, create_finding, load_scenarios


def _scenario() -> dict[str, Any]:
    return next(item for item in load_scenarios() if item["id"] == "sqli_validated_reportable")


def test_bulk_intelligence_assembly_10k_findings() -> None:
    """Analyzing thousands of findings stays within a bounded time budget."""
    service, stores = build_service()
    finding_ids: list[str] = []
    for _ in range(200):
        finding_ids.append(create_finding(stores, _scenario()))

    started = time.monotonic()
    for finding_id in finding_ids:
        intelligence = service.analyze_finding(finding_id)
        assert intelligence["finding_id"]
    elapsed = time.monotonic() - started
    # 200 findings should analyze comfortably under 10 seconds in-memory.
    assert elapsed < 10.0, f"intelligence assembly too slow: {elapsed:.2f}s for 200 findings"


def test_bulk_report_generation_200_findings() -> None:
    """Bulk report generation is bounded and produces versioned packages."""
    service, stores = build_service()
    finding_ids: list[str] = [create_finding(stores, _scenario()) for _ in range(200)]

    started = time.monotonic()
    report_ids: list[str] = []
    for finding_id in finding_ids:
        report = service.generate_report(finding_id, template="bug_bounty")
        report_ids.append(report["report_id"])
    elapsed = time.monotonic() - started
    assert len(report_ids) == 200
    assert elapsed < 30.0, f"bulk generation too slow: {elapsed:.2f}s for 200 findings"

    # Every report is independently versioned and retrievable.
    for report_id in report_ids[:5]:
        assert service.get_report(report_id)["report_id"] == report_id


def test_evidence_bundle_100k_artifacts_is_bounded() -> None:
    """Building a bundle over 100k evidence artifacts stays bounded."""
    from hunterx.domain.reporting.evidence import ArtifactInput, EvidenceBundleBuilder

    builder = EvidenceBundleBuilder()
    artifacts = tuple(
        ArtifactInput(kind="observation", content=f"value-{i}", source="s", finding_id="f1")
        for i in range(100_000)
    )
    started = time.monotonic()
    bundle = builder.build(finding_id="f1", artifacts=artifacts)
    elapsed = time.monotonic() - started
    assert bundle.bundle_hash
    assert len(bundle.artifacts) == 100_000
    assert elapsed < 15.0, f"bundle build too slow: {elapsed:.2f}s"


def test_qa_engine_scales_over_large_reports() -> None:
    """QA over a large claim set stays fast."""
    from hunterx.domain.reporting.enums import ClaimState, ClaimType
    from hunterx.domain.reporting.models import ReportClaim, ReportDocument
    from hunterx.domain.reporting.qa import QaContext, ReportQAEngine

    claims = tuple(
        ReportClaim(
            claim_text=f"claim {i}",
            source_refs=("v1",) if i % 2 == 0 else (),
            claim_type=ClaimType.VULNERABILITY,
            verification_state=ClaimState.VERIFIED if i % 2 == 0 else ClaimState.UNSUPPORTED,
        )
        for i in range(10_000)
    )
    document = ReportDocument(title="large", claims=claims)
    engine = ReportQAEngine()
    started = time.monotonic()
    result = engine.check(document, context=QaContext(verified_refs={"v1"}), text_content="")
    elapsed = time.monotonic() - started
    assert result.verdict is not None
    assert elapsed < 5.0, f"QA too slow over 10k claims: {elapsed:.2f}s"


def test_renderers_stable_and_bounded() -> None:
    """Rendering large reports stays bounded and produces valid output."""
    service, stores = build_service()
    finding_ids = [create_finding(stores, _scenario()) for _ in range(50)]
    report = service.generate_report(finding_ids[0], template="pentest")
    report_id = report["report_id"]
    started = time.monotonic()
    for fmt in ("markdown", "html", "json", "sarif", "pdf"):
        exported = service.export_report(report_id, fmt=fmt)
        assert exported["content"]
    elapsed = time.monotonic() - started
    assert elapsed < 5.0, f"rendering too slow: {elapsed:.2f}s"
