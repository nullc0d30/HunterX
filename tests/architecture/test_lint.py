# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the architecture linter (synthetic repositories)."""

from __future__ import annotations

import pathlib
from collections.abc import Callable

from hunterx.architecture.lint import ArchitectureLinter, LintOptions
from hunterx.architecture.policy import default_policy
from hunterx.architecture.violations import ViolationCodes

Builder = Callable[[pathlib.Path], None]


def _write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _build_clean_repo(root: pathlib.Path) -> None:
    """Build a conforming mini repository."""
    _write(
        root / "src/hunterx/shared/ids.py",
        '"""Shared ids."""\ndef generate_id() -> str:\n    return "x"\n',
    )
    _write(
        root / "src/hunterx/domain/entities/target.py",
        '"""Target entity."""\nfrom hunterx.shared.ids import generate_id\nclass Target:\n    pass\n',
    )
    _write(
        root / "src/hunterx/domain/ports/stores.py",
        '"""Store ports."""\nclass StorePort:\n    pass\n',
    )
    _write(
        root / "src/hunterx/infrastructure/cache.py",
        '"""Cache adapter."""\nfrom hunterx.domain.ports.stores import StorePort\nclass MemoryCache:\n    pass\n',
    )
    _write(
        root / "src/hunterx/application/missions.py",
        '"""Mission use-case."""\nfrom hunterx.domain.entities.target import Target\nclass MissionService:\n    pass\n',
    )
    _write(
        root / "src/hunterx/__init__.py",
        '"""HunterX package."""\n',
    )


def _lint(root: pathlib.Path, **overrides: bool) -> object:
    options = LintOptions(repo_root=root)
    for key, value in overrides.items():
        setattr(options, key, value)
    return ArchitectureLinter(policy=default_policy(), options=options).run()


def test_clean_repo_has_no_errors(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    report = _lint(tmp_path)
    assert report.error_count() == 0
    assert report.is_clean()


def test_domain_importing_infrastructure_is_violation(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "src/hunterx/domain/entities/evil.py",
        '"""Evil entity."""\nfrom hunterx.infrastructure.cache import MemoryCache\nclass Evil:\n    pass\n',
    )
    report = _lint(tmp_path)
    assert report.error_count() == 1
    violation = report.violations[0]
    assert violation.code == ViolationCodes.IMPORT_LAYER
    assert "domain" in violation.message
    assert violation.remediation  # remediation guidance present


def test_application_importing_infrastructure_is_violation(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "src/hunterx/application/evil.py",
        '"""Evil app."""\nfrom hunterx.infrastructure.cache import MemoryCache\nclass Evil:\n    pass\n',
    )
    report = _lint(tmp_path)
    assert report.error_count() == 1
    assert report.violations[0].code == ViolationCodes.IMPORT_LAYER


def test_forbidden_legacy_import_is_violation(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "src/hunterx/domain/entities/legacy_import.py",
        '"""Legacy import."""\nimport core.agents\n',
    )
    report = _lint(tmp_path)
    assert report.error_count() == 1
    assert report.violations[0].code == ViolationCodes.IMPORT_FORBIDDEN


def test_circular_dependency_is_violation(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "src/hunterx/a.py",
        '"""Module a."""\nfrom hunterx.b import B\nclass A:\n    pass\n',
    )
    _write(
        tmp_path / "src/hunterx/b.py",
        '"""Module b."""\nfrom hunterx.a import A\nclass B:\n    pass\n',
    )
    report = _lint(tmp_path)
    assert report.error_count() == 1
    assert report.violations[0].code == ViolationCodes.CIRCULAR_DEPENDENCY
    assert len(report.cycles) == 1


def test_missing_docstring_is_error(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "src/hunterx/domain/entities/nodoc.py",
        "class NoDoc:\n    pass\n",
    )
    report = _lint(tmp_path)
    docs = [v for v in report.violations if v.code == ViolationCodes.DOCSTRING_MISSING]
    assert any("nodoc" in violation.module for violation in docs)


def test_plugin_boundary_violation(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "plugins/my_plugin.py",
        '"""A plugin."""\nfrom hunterx.infrastructure.cache import MemoryCache\n',
    )
    report = _lint(tmp_path)
    assert report.error_count() == 1
    assert report.violations[0].code == ViolationCodes.PLUGIN_BOUNDARY


def test_tool_boundary_violation(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "tools/nmap/adapter.py",
        '"""An adapter."""\nfrom hunterx.application.missions import MissionService\n',
    )
    report = _lint(tmp_path)
    assert report.error_count() == 1
    assert report.violations[0].code == ViolationCodes.TOOL_BOUNDARY


def test_waived_violation_becomes_known_issue(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "src/hunterx/plugins/sdk/results.py",
        '"""SDK results."""\nclass FindingResult:\n    pass\n',
    )
    _write(
        tmp_path / "src/hunterx/domain/execution.py",
        '"""Domain execution."""\nfrom hunterx.plugins.sdk.results import FindingResult\n',
    )
    report = _lint(tmp_path)
    assert report.error_count() == 0
    assert any(issue.module == "hunterx.domain.execution" for issue in report.known_issues)


def test_disabling_checks_skips_them(tmp_path: pathlib.Path) -> None:
    _build_clean_repo(tmp_path)
    _write(
        tmp_path / "src/hunterx/domain/entities/nodoc.py",
        "class NoDoc:\n    pass\n",
    )
    report = _lint(tmp_path, check_docs=False)
    assert report.error_count() == 0
