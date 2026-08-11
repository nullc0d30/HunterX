# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the hunterx-arch CLI."""

from __future__ import annotations

import pathlib

import pytest

from hunterx.architecture import cli


def _write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _repo(tmp_path: pathlib.Path) -> pathlib.Path:
    _write(tmp_path / "pyproject.toml", "[project]\nname = 'x'\n")
    _write(
        tmp_path / "src/hunterx/__init__.py",
        '"""HunterX."""\n',
    )
    _write(
        tmp_path / "src/hunterx/domain/entities/target.py",
        '"""Target."""\nclass Target:\n    pass\n',
    )
    _write(
        tmp_path / "src/hunterx/domain/entities/evil.py",
        '"""Evil."""\nfrom hunterx.infrastructure.cache import Cache\nclass Evil:\n    pass\n',
    )
    return tmp_path


def test_lint_exit_code_one_on_violations(tmp_path: pathlib.Path) -> None:
    _repo(tmp_path)
    exit_code = cli.main(["lint", "--root", str(tmp_path), "--format", "text"])
    assert exit_code == 1


def test_lint_json_contains_violation(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    _repo(tmp_path)
    exit_code = cli.main(["lint", "--root", str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "ARCH-001" in out


def test_matrix_command(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    _repo(tmp_path)
    assert cli.main(["matrix", "--root", str(tmp_path)]) == 0
    assert "domain" in capsys.readouterr().out


def test_graph_command(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    _repo(tmp_path)
    assert cli.main(["graph", "--root", str(tmp_path)]) == 0
    assert "flowchart LR" in capsys.readouterr().out


def test_report_writes_file(tmp_path: pathlib.Path) -> None:
    root = _repo(tmp_path)
    output = tmp_path / "out" / "report.md"
    assert cli.main(["report", "--root", str(root), "--output", str(output), "--format", "markdown"]) == 1
    assert output.is_file()
    assert "Architecture Enforcement Report" in output.read_text(encoding="utf-8")


def test_stability_generate_and_check(tmp_path: pathlib.Path) -> None:
    root = _repo(tmp_path)
    baseline = tmp_path / "config" / "api_baseline.json"
    assert cli.main(["stability", "--root", str(root), "--generate", "--output", str(baseline)]) == 0
    assert baseline.is_file()
    assert cli.main(["stability", "--root", str(root), "--output", str(baseline)]) == 0


def test_stability_no_baseline_errors(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repo(tmp_path)
    assert cli.main(["stability", "--root", str(root)]) == 2
    assert "No API baseline" in capsys.readouterr().err


def test_version(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
