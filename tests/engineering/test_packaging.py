# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for packaging validation (eng.packaging)."""

from __future__ import annotations

import pathlib

from eng.packaging import _is_dist, validate_packaging
from eng.tooling import ToolResult


class _FakeRunner:
    """Returns canned build/twine results."""

    def __init__(self, outcomes: dict[str, ToolResult]) -> None:
        self.outcomes = outcomes

    def available(self, executable: str) -> bool:
        return True

    def run(
        self, args: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int = 600
    ) -> ToolResult:
        return self.outcomes.get(args[0], ToolResult(returncode=0, stdout=""))


def test_is_dist() -> None:
    assert _is_dist("hunterxsec-7.0.0-py3-none-any.whl") is True
    assert _is_dist("hunterxsec-7.0.0.tar.gz") is True
    assert _is_dist("hunterxsec-7.0.0.zip") is False
    assert _is_dist("README.md") is False


def test_validate_packaging_passes(tmp_path: pathlib.Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "hunterxsec-7.0.0-py3-none-any.whl").write_bytes(b"w")
    (dist / "hunterxsec-7.0.0.tar.gz").write_bytes(b"s")
    runner = _FakeRunner(
        {
            "python": ToolResult(returncode=0, stdout="built"),
            "twine": ToolResult(returncode=0, stdout="clean"),
        }
    )
    report = validate_packaging(tmp_path, runner=runner)
    assert report.ok is True
    assert report.artifacts == ["hunterxsec-7.0.0-py3-none-any.whl", "hunterxsec-7.0.0.tar.gz"]


def test_validate_packaging_fails_without_sdist(tmp_path: pathlib.Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "hunterxsec-7.0.0-py3-none-any.whl").write_bytes(b"w")
    runner = _FakeRunner(
        {
            "python": ToolResult(returncode=0, stdout="built"),
            "twine": ToolResult(returncode=0, stdout="clean"),
        }
    )
    report = validate_packaging(tmp_path, runner=runner)
    assert report.ok is False
    assert any(c.name == "sdist" and c.status.value == "fail" for c in report.checks)


def test_validate_packaging_build_failure(tmp_path: pathlib.Path) -> None:
    runner = _FakeRunner({"python": ToolResult(returncode=1, stderr="build failed")})
    report = validate_packaging(tmp_path, runner=runner)
    assert report.ok is False
    assert report.summary.startswith("packaging failed")
