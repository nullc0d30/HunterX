# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden finding scenarios (Sprint 034.5).

Certifies the finding flow gate: a detection without reproducible evidence must
NOT become a fully validated finding. Each scenario asserts the evidence
sufficiency level and that only evidence-backed hypotheses advance toward
validation; known vulnerabilities, variants and novel behaviors are exercised.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunterx.platform import build_platform

_SCENARIOS_PATH = Path(__file__).parent / "scenarios.json"


def _load_scenarios() -> list[dict[str, object]]:
    payload = json.loads(_SCENARIOS_PATH.read_text(encoding="utf-8"))
    return list(payload["scenarios"])  # type: ignore[arg-type]


def _observations(kinds: list[object]) -> list[dict[str, object]]:
    return [{"kind": kind, "value": f"{kind}-value", "quality": "high", "source": "tool"} for kind in kinds]


@pytest.fixture
def service():
    platform = build_platform()
    return platform.vulnerability_finding_service  # type: ignore[attr-defined]


@pytest.mark.parametrize("scenario", _load_scenarios(), ids=lambda item: str(item["id"]))
def test_golden_finding_scenario(service, scenario: dict[str, object]) -> None:
    finding = service.create_finding(  # type: ignore[attr-defined]
        mission_id="m1",
        target_id="https://example.com",
        asset_id="asset-1",
        vulnerability_class=str(scenario["vulnerability_class"]),
        title=f"finding-{scenario['id']}",
        description="scenario",
        severity="medium",
        tool="nuclei",
        endpoints=tuple(str(item) for item in scenario.get("endpoints") or []),
        parameters=tuple(str(item) for item in scenario.get("parameters") or []),
        observations=_observations(list(scenario.get("observations") or [])),
    )
    assert finding["status"] in ("supported", "validation_required")

    assessment = service.assess_evidence(finding["finding_id"])  # type: ignore[attr-defined]
    sufficiency = {item["purpose"]: item["level"] for item in assessment["sufficiency"]}
    expected = str(scenario["expected_validation_sufficiency"])
    assert sufficiency["validation"] == expected

    # Gate: detection without reproducible evidence never validates.
    if not scenario.get("validated"):
        assert sufficiency["validation"] == "insufficient"
        assert finding["status"] != "validated"


def test_evidence_survives_finding_package(service) -> None:
    finding = service.create_finding(  # type: ignore[attr-defined]
        mission_id="m1",
        target_id="https://example.com",
        asset_id="asset-1",
        vulnerability_class="sql_injection",
        title="SQLi with evidence",
        description="evidence flow",
        severity="high",
        tool="nuclei",
        endpoints=("/search",),
        parameters=("q",),
        observations=_observations(["detection_signature", "differential_database_behavior"]),
    )
    package = service.get_finding_package(finding["finding_id"])  # type: ignore[attr-defined]
    producers = [item for item in package["provenance"] if item.get("tool") == "nuclei"]
    assert producers
    assert package["evidence"]
    assert package["scope"]["target"] == "https://example.com"
