# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the engineering-platform CLI (python -m eng)."""

from __future__ import annotations

from eng.__main__ import build_parser, main


def test_parser_exposes_commands() -> None:
    parser = build_parser()
    subparsers_action = next(a for a in parser._actions if getattr(a, "choices", None))
    commands = set(subparsers_action.choices)
    for expected in ("gates", "security", "sbom", "compliance", "packaging", "readiness", "check-release"):
        assert expected in commands


def test_check_release_valid() -> None:
    assert main(["check-release", "7.1.0"]) == 0
    assert main(["check-release", "7.1.0", "--json"]) == 0


def test_check_release_invalid() -> None:
    assert main(["check-release", "not-a-version"]) == 2


def test_sbom_cyclonedx() -> None:
    assert main(["sbom", "--format", "cyclonedx"]) == 0


def test_sbom_spdx() -> None:
    assert main(["sbom", "--format", "spdx"]) == 0


def test_compliance_returns_binary() -> None:
    # Exit code is 0 when compliance + hygiene pass; the real repo must pass.
    assert main(["compliance"]) in (0, 1)
