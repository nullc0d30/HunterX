# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Codebase conformance tests.

These integration tests run the real linter against the actual HunterX source
tree and assert the architecture is clean. They are the CI validation tests:
if the source tree ever violates the dependency matrix, these tests fail.

The check intentionally disables nothing except the API stability comparison
(which uses the committed baseline and is validated separately) — the layer
rules, cycle detection, plugin/tool boundaries and documentation gates all run.
"""

from __future__ import annotations

import pathlib

from hunterx.architecture.lint import ArchitectureLinter, LintOptions
from hunterx.architecture.policy import load_policy

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "config" / "architecture.yaml"


def test_architecture_policy_file_exists() -> None:
    assert POLICY_PATH.is_file(), "config/architecture.yaml must exist"


def test_codebase_has_no_architecture_errors() -> None:
    policy = load_policy(POLICY_PATH)
    linter = ArchitectureLinter(
        policy=policy,
        options=LintOptions(repo_root=REPO_ROOT),
    )
    report = linter.run()
    assert report.error_count() == 0, _format_errors(report)


def test_api_baseline_is_in_sync() -> None:
    from hunterx.architecture.stability import compare_api, load_baseline, snapshot_tree

    policy = load_policy(POLICY_PATH)
    baseline = load_baseline(REPO_ROOT / policy.api_baseline)
    current = snapshot_tree(REPO_ROOT / policy.package_root)
    breaking = [change for change in compare_api(baseline, current) if change.breaking]
    assert breaking == [], "Public API drifted from config/api_baseline.json; run `hunterx-arch stability --generate`"


def test_known_waivers_and_cycles_are_documented() -> None:
    policy = load_policy(POLICY_PATH)
    assert policy.waivers, "The dependency matrix must document known waivers"
    assert policy.known_cycles, "The dependency matrix must document known cycles"


def _format_errors(report: object) -> str:
    lines = ["Architecture violations found in the codebase:"]
    for violation in getattr(report, "violations", []):
        lines.append(f"  [{violation.code}] {violation.module}: {violation.message}")
    return "\n".join(lines)
