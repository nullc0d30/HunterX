# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden PoC scenarios (Sprint 034.5).

Certifies the PoC lifecycle: generation is never validation; a PoC must be
statically validated, then replayed against the exact target with matching
behavior, and only a confirmed replay proves the finding. Refutation
(non-reproducible, different target) is preserved and regresses the finding.
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


def _observations(*kinds: str) -> list[dict[str, object]]:
    return [{"kind": kind, "value": f"{kind}-value", "quality": "high", "source": "tool"} for kind in kinds]


@pytest.fixture
def service():
    platform = build_platform()
    return platform.vulnerability_finding_service  # type: ignore[attr-defined]


def _validated_finding(service) -> dict[str, object]:
    """Create an evidence-backed SQL injection finding awaiting proof."""
    finding = service.create_finding(  # type: ignore[attr-defined]
        mission_id="m1",
        target_id="https://example.com",
        asset_id="asset-1",
        vulnerability_class="sql_injection",
        title="SQLi",
        description="SQLi at /search?q=",
        severity="high",
        tool="nuclei",
        endpoints=("/search",),
        parameters=("q",),
        observations=_observations("detection_signature", "differential_database_behavior"),
    )
    return finding


@pytest.mark.parametrize("scenario", _load_scenarios(), ids=lambda item: str(item["id"]))
def test_golden_poc_scenario(service, scenario: dict[str, object]) -> None:
    finding = _validated_finding(service)
    poc = service.generate_poc(  # type: ignore[attr-defined]
        finding["finding_id"],
        reproduction={"request": "/search?q=test", "method": "GET"},
    )
    # Generation is never validation.
    assert poc["lifecycle_state"] == "static_validated"
    assert poc["poc_id"]
    assert poc["finding_id"] == finding["finding_id"]

    outcome = scenario["outcome"]
    replay = service.replay_poc(  # type: ignore[attr-defined]
        finding["finding_id"],
        poc["poc_id"],
        outcome=dict(outcome) if isinstance(outcome, dict) else outcome,
    )
    assert replay["verdict"] == scenario["expected_verdict"]

    # A confirmed replay advances the finding to PROVED; any refutation never does.
    status = service.get_finding(finding["finding_id"])["status"]  # type: ignore[attr-defined]
    if scenario["expected_verdict"] == "confirmed":
        assert status == "proved"
    else:
        assert status != "proved"


def test_poc_is_traceable_to_execution(service) -> None:
    finding = _validated_finding(service)
    poc = service.generate_poc(finding["finding_id"], reproduction={"request": "/search?q=1"})  # type: ignore[attr-defined]
    replay = service.replay_poc(  # type: ignore[attr-defined]
        finding["finding_id"], poc["poc_id"], outcome={"confirmed": True, "target": "https://example.com"}
    )
    assert replay["verdict"] == "confirmed"
    # Replay record links the PoC back to the finding and preserves provenance.
    assert replay["poc_id"] == poc["poc_id"]
    assert replay["finding_id"] == finding["finding_id"]
