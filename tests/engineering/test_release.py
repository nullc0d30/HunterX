# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for release engineering (eng.release)."""

from __future__ import annotations

import pathlib

import pytest
from eng.release import (
    build_rollback_plan,
    generate_checksums,
    is_valid_version,
    parse_changelog,
    parse_version,
    render_release_notes,
    sha256_file,
    suggest_bump,
    verify_checksums,
)


def test_parse_valid_semver() -> None:
    version = parse_version("7.1.0")
    assert (version.major, version.minor, version.patch) == (7, 1, 0)
    assert version.is_prerelease is False
    assert str(version) == "7.1.0"


def test_parse_prerelease() -> None:
    version = parse_version("7.2.0-rc.1+build5")
    assert version.is_prerelease is True
    assert str(version) == "7.2.0-rc.1+build5"


def test_invalid_versions_rejected() -> None:
    for bad in ("7", "7.1", "v7.1.0", "7.1.0.0", "7..1.0", "abc", ""):
        assert is_valid_version(bad) is False, bad
    assert is_valid_version("1.2.3") is True


def test_version_ordering() -> None:
    assert parse_version("1.0.0") < parse_version("1.0.1")
    assert parse_version("1.0.0-rc.1") < parse_version("1.0.0")
    assert parse_version("1.0.0-rc.1") < parse_version("1.0.0-rc.2")
    assert parse_version("2.0.0") > parse_version("1.9.9")


def test_version_bump() -> None:
    assert str(parse_version("1.2.3").bump("patch")) == "1.2.4"
    assert str(parse_version("1.2.3").bump("minor")) == "1.3.0"
    assert str(parse_version("1.2.3").bump("major")) == "2.0.0"


def test_suggest_bump() -> None:
    assert suggest_bump(["feat: add x"]) == "minor"
    assert suggest_bump(["fix: repair y"]) == "patch"
    assert suggest_bump(["feat!: breaking"]) == "major"
    assert suggest_bump(["fix: x", "BREAKING CHANGE: drop api"]) == "major"
    assert suggest_bump([]) == "none"


def test_parse_and_render_changelog() -> None:
    text = "# Changelog\n\n## [7.1.0] - 2026-08-01\n\n### Added\n- Feature one\n\n## [7.0.0] - 2026-07-01\n\n### Fixed\n- Bug\n"
    entries = parse_changelog(text)
    assert entries[0].version == "7.1.0"
    assert "Feature one" in entries[0].body
    notes = render_release_notes(entries, "7.1.0")
    assert "## 7.1.0" in notes
    assert "Feature one" in notes


def test_render_missing_version() -> None:
    assert "pending" in render_release_notes([], "9.9.9")


def test_sha256_and_checksums(tmp_path: pathlib.Path) -> None:
    file = tmp_path / "artifact.whl"
    file.write_bytes(b"hello world")
    digest = sha256_file(file)
    assert len(digest) == 64
    sums = generate_checksums([file])
    assert sums[0].sha256 == digest
    assert sums[0].name == "artifact.whl"


def test_verify_checksums(tmp_path: pathlib.Path) -> None:
    file = tmp_path / "artifact.whl"
    file.write_bytes(b"hello world")
    digest = sha256_file(file)
    (tmp_path / "SHA256SUMS.txt").write_text(f"{digest}  artifact.whl\n", encoding="utf-8")
    verified = verify_checksums(tmp_path)
    assert verified[0].name == "artifact.whl"


def test_verify_checksums_detects_mismatch(tmp_path: pathlib.Path) -> None:
    file = tmp_path / "artifact.whl"
    file.write_bytes(b"hello world")
    (tmp_path / "SHA256SUMS.txt").write_text(f"{'0' * 64}  artifact.whl\n", encoding="utf-8")
    with pytest.raises(ValueError):
        verify_checksums(tmp_path)


def test_rollback_plan() -> None:
    plan = build_rollback_plan(parse_version("7.2.0"))
    assert plan.previous_version == "7.2.1"  # patch-bump fallback
    assert "hunterx==" in plan.package_version
    assert "nullc0d30/hunterx:" in plan.image_tag
