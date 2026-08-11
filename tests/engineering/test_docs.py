# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for documentation validation (eng.docs)."""

from __future__ import annotations

import pathlib

from eng.docs import _iter_markdown_links, _resolve_link, validate_docs


def _write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _minimal_repo(root: pathlib.Path) -> None:
    for name in (
        "README.md",
        "LICENSE",
        "NOTICE",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "pyproject.toml",
    ):
        _write(root / name, f"# {name}\n")
    _write(
        root / "README.md",
        "# HunterX\n\n## Installation\n\n## Usage\n\n## License\n\nSee [CONTRIBUTING](CONTRIBUTING.md)\n",
    )
    _write(
        root / "CONTRIBUTING.md",
        "# Contributing\n\n## Development\n\n## Testing\n",
    )
    for doc, sections in {
        "docs/v7-devsecops.md": ("quality gate", "security pipeline"),
        "docs/v7-cicd-architecture.md": ("workflow", "quality gate"),
        "docs/v7-quality-gates.md": ("ruff", "mypy", "coverage"),
        "docs/v7-security-pipeline.md": ("bandit", "semgrep", "gitleaks"),
        "docs/v7-release-guide.md": ("semantic version", "changelog"),
    }.items():
        body = "\n".join(f"## {s}" for s in sections)
        _write(root / doc, f"# doc\n\n{body}\n")
    _write(root / "docs" / "index.md", "# Docs\n\nSee [quality gates](v7-quality-gates.md)\n")


def test_docs_report_all_pass_on_healthy_repo(tmp_path: pathlib.Path) -> None:
    _minimal_repo(tmp_path)
    report = validate_docs(tmp_path)
    assert report.failed == 0, report.summary
    assert (tmp_path / "artifacts" / "docs-report.json").is_file()


def test_docs_report_missing_required_file(tmp_path: pathlib.Path) -> None:
    _minimal_repo(tmp_path)
    (tmp_path / "NOTICE").unlink()
    report = validate_docs(tmp_path)
    assert report.failed >= 1
    assert any(c.name == "required-files" and not c.ok for c in report.checks)


def test_docs_report_missing_engineering_doc(tmp_path: pathlib.Path) -> None:
    _minimal_repo(tmp_path)
    (tmp_path / "docs" / "v7-release-guide.md").unlink()
    report = validate_docs(tmp_path)
    assert any(c.name == "engineering-docs" and not c.ok for c in report.checks)


def test_iter_markdown_links_skips_fences() -> None:
    text = "[a](a.md)\n```\n[b](fake.md)\n```\n[c](c.md)\n"
    assert _iter_markdown_links(text) == ["a.md", "c.md"]


def test_resolve_link_relative(tmp_path: pathlib.Path) -> None:
    (tmp_path / "target.md").write_text("t", encoding="utf-8")
    assert _resolve_link(tmp_path, "target.md") is not None
    assert _resolve_link(tmp_path, "missing.md") is None


def test_resolve_link_site_absolute(tmp_path: pathlib.Path) -> None:
    docs = tmp_path / "docs"
    _write(docs / "cli" / "examples.md", "# e\n")
    resolved = _resolve_link(docs, "/cli/examples/")
    assert resolved is not None
    assert resolved.name == "examples.md"
